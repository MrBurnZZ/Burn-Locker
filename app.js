// webapp/app.js
//
// This is the Android/mobile-web counterpart to extension/popup.js. Same
// vault logic (core/vault.js, unmodified — that's the point of keeping
// crypto/vault code separate from the UI), different platform glue:
//   - storage: IndexedDB instead of chrome.storage.local
//   - "stay unlocked this session": sessionStorage instead of
//     chrome.storage.session (same idea — cleared when the tab/browser
//     closes — just the web-standard equivalent, since there's no
//     chrome.* API outside an extension)
//   - idle auto-lock: a plain setTimeout instead of chrome.alarms,
//     because this page — unlike the extension's popup — stays alive in
//     its tab the whole time, so a normal in-page timer works fine
//   - no autofill/Fill button: a web page has no way to reach into
//     other apps on the phone, so this is a look-up-and-copy tool;
//     Android's own copy/paste is what gets a value into another app

import { Vault, WrongPasswordError } from './core/vault.js';
import { generatePassword, exportKeyRaw, importKeyRaw } from './core/crypto.js';

// --- storage adapter: IndexedDB, wrapped to match the same get/set shape core/vault.js expects ---
const DB_NAME = 'simple-vault';
const DB_VERSION = 1;
const STORE_NAME = 'kv';

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

const storage = {
  async get(key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const req = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  },
  async set(key, value) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
  async remove(key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
};

// --- "stay unlocked for this browser session" via sessionStorage ---
const SESSION_KEY_STORAGE = 'simpleVaultSessionKey';

function cacheSessionKeyBytes(rawKeyB64) {
  try {
    sessionStorage.setItem(SESSION_KEY_STORAGE, rawKeyB64);
  } catch (err) {
    console.error('Could not cache session key', err);
  }
}
function readCachedSessionKeyBytes() {
  try {
    return sessionStorage.getItem(SESSION_KEY_STORAGE);
  } catch {
    return null;
  }
}
function clearCachedSessionKeyBytes() {
  try {
    sessionStorage.removeItem(SESSION_KEY_STORAGE);
  } catch {
    /* ignore */
  }
}

// --- idle auto-lock: this page stays open in its tab, so a plain timer works (no background worker needed) ---
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
let idleTimerId = null;

function resetIdleTimer() {
  if (idleTimerId) clearTimeout(idleTimerId);
  idleTimerId = setTimeout(() => {
    vault.lock();
    clearCachedSessionKeyBytes();
    showView('view-unlock');
    showToast('Locked after 15 minutes of inactivity');
  }, IDLE_TIMEOUT_MS);
}
function clearIdleTimer() {
  if (idleTimerId) clearTimeout(idleTimerId);
  idleTimerId = null;
}

const vault = new Vault(storage);
let editingEntryId = null;

// --- theme (dark mode) ---
// Stored under its own localStorage key, separate from the vault
// (IndexedDB), on purpose: the burn/duress wipe is deliberately scoped to
// vault data only (see Vault.wipe() in core/vault.js), and forgetting
// your saved logins should never also reset how the app looks.
// localStorage is synchronous, so this can run immediately, before
// anything else — there's no flash of the wrong theme while it loads.
//
// Three-way preference — 'system' | 'light' | 'dark' — matching the Windows
// app's ThemePreference enum and SettingsView exactly: 'system' means "read
// whatever the OS/browser prefers right now and use that," checked once
// whenever the theme is applied (on load, or when this setting changes),
// not something that keeps following the OS live after that. Storing
// 'system' as an explicit value (rather than just "nothing saved yet")
// means it's a real choice you can come back to — pick Light, then later
// decide you want to just match the OS again — not only a first-run
// default that gets permanently overwritten the first time you touch the
// setting.
const THEME_STORAGE_KEY = 'simpleVaultTheme'; // 'system' | 'light' | 'dark'

function systemPrefersDark() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

/** Resolves a stored preference ('system' | 'light' | 'dark') to the actual 'light' | 'dark' to render. */
function resolveTheme(preference) {
  if (preference === 'dark') return 'dark';
  if (preference === 'light') return 'light';
  return systemPrefersDark() ? 'dark' : 'light'; // 'system', or no preference saved yet
}

function applyTheme(preference) {
  document.documentElement.setAttribute('data-theme', resolveTheme(preference));
  const select = document.getElementById('theme-select');
  if (select) select.value = preference;
}

function loadTheme() {
  let stored = null;
  try {
    stored = localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    // Falls through to the system-preference default below.
  }
  applyTheme(stored || 'system'); // no explicit choice saved yet defaults to following the OS
}
loadTheme(); // run immediately — before init() — so there's no flash of the wrong theme

document.getElementById('theme-select').addEventListener('change', (e) => {
  const preference = e.target.value;
  applyTheme(preference);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, preference);
  } catch (err) {
    console.error('Could not save theme preference', err);
  }
});

// --- view switching ---
const views = [
  'view-create',
  'view-unlock',
  'view-vault',
  'view-entry-form',
  'view-export',
  'view-import',
  'view-security',
  'view-burn-confirm',
  'view-duress-setup',
  'view-duress-remove',
];
function showView(id) {
  for (const v of views) {
    document.getElementById(v).classList.toggle('active', v === id);
  }
}

function showToast(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 1800);
}

/**
 * Reflects whether `input` is currently showing plaintext onto its toggle
 * button's visual state, title, and aria-label.
 */
function setToggleState(button, input) {
  const visible = input.type === 'text';
  button.classList.toggle('showing', visible);
  const label = visible ? 'Hide password' : 'Show password';
  button.title = label;
  button.setAttribute('aria-label', label);
}

/**
 * Clears a password field back to empty AND masked, and keeps its
 * show/hide toggle in sync with that. Used everywhere a form is reset
 * before being shown (so a wipe or a fresh open never leaves last time's
 * password sitting there) and right after a value has been used (so it
 * isn't left in the DOM, visible or not, any longer than necessary).
 */
function resetPasswordField(id) {
  const input = document.getElementById(id);
  if (!input) return;
  input.value = '';
  input.type = 'password';
  const btn = document.querySelector(`.toggle-visibility-btn[data-target="${id}"]`);
  if (btn) setToggleState(btn, input);
}

// Every password field's show/hide toggle works the same way — this wires
// all of them up in one place instead of repeating a click handler per
// field. Covers both entry-password's toggle (inside .password-row) and
// every master/export/import/duress password field (inside
// .password-field); both use the same data-target attribute.
document.querySelectorAll('.toggle-visibility-btn[data-target]').forEach((btn) => {
  const input = document.getElementById(btn.dataset.target);
  if (!input) return;
  setToggleState(btn, input);
  btn.addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
    setToggleState(btn, input);
  });
});

/**
 * Clears the "create your vault" form. Needed before showing that screen
 * after a wipe (burn button or duress password) — this page's DOM stays
 * alive the whole time the tab is open, so without this, whatever was
 * last typed into these fields (e.g. when the vault was originally
 * created) would still be sitting there, visible, on the screen a wipe
 * lands on.
 */
function resetCreateForm() {
  resetPasswordField('create-password');
  resetPasswordField('create-password-confirm');
  document.getElementById('create-error').textContent = '';
}

// --- startup ---
async function init() {
  if (await tryRestoreSession()) {
    renderEntryList();
    showView('view-vault');
    return;
  }
  if (await vault.exists()) {
    showView('view-unlock');
  } else {
    showView('view-create');
  }
}

async function tryRestoreSession() {
  try {
    const rawKeyB64 = readCachedSessionKeyBytes();
    if (!rawKeyB64) return false;
    const workingKey = await importKeyRaw(rawKeyB64); // non-extractable, same as a fresh unlock
    await vault.unlockWithKey(workingKey);
    resetIdleTimer();
    return true;
  } catch (err) {
    console.error('Could not restore cached session, falling back to password prompt', err);
    clearCachedSessionKeyBytes();
    return false;
  }
}

/**
 * Derives a second, extractable copy of the key purely to cache it — the
 * key vault.create()/unlock() actually uses for encrypt/decrypt stays
 * non-extractable throughout. Never allowed to block access to an
 * already-correctly-unlocked vault if it fails for any reason.
 */
async function cacheSession(masterPassword) {
  try {
    const extractableKey = await vault.deriveExtractableKey(masterPassword);
    const rawKeyB64 = await exportKeyRaw(extractableKey);
    cacheSessionKeyBytes(rawKeyB64);
    resetIdleTimer();
  } catch (err) {
    console.error('Could not cache this session — you will be asked for your master password next time too', err);
  }
}

// --- create vault ---
document.getElementById('form-create').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = document.getElementById('create-password').value;
  const confirm = document.getElementById('create-password-confirm').value;
  const errorEl = document.getElementById('create-error');

  if (pw !== confirm) {
    errorEl.textContent = "Passwords don't match.";
    return;
  }
  if (pw.length < 8) {
    errorEl.textContent = 'Use at least 8 characters — longer is better.';
    return;
  }
  errorEl.textContent = '';
  await vault.create(pw);
  await cacheSession(pw);
  renderEntryList();
  showView('view-vault');
});

// --- unlock vault ---
document.getElementById('form-unlock').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = document.getElementById('unlock-password').value;
  const errorEl = document.getElementById('unlock-error');

  // Check the duress password BEFORE attempting a normal unlock. This has
  // to run first and separately — the duress password was never used to
  // encrypt the vault, so vault.unlock(pw) would just fail on it like any
  // other wrong password, and by design there's no error message or other
  // visible difference here: a match wipes the vault and quietly falls
  // through to "no vault exists yet," the same screen a brand new install
  // would show.
  try {
    if (await vault.isDuressPassword(pw)) {
      await vault.wipe();
      clearSessionArtifacts();
      resetPasswordField('unlock-password');
      errorEl.textContent = '';
      resetCreateForm();
      showView('view-create');
      return;
    }
  } catch (err) {
    console.error('Duress-password check failed', err);
    // Fall through to a normal unlock attempt — never let a broken check
    // here be the reason a legitimate unlock doesn't happen.
  }

  try {
    await vault.unlock(pw);
    await cacheSession(pw);
    errorEl.textContent = '';
    resetPasswordField('unlock-password');
    renderEntryList();
    showView('view-vault');
  } catch (err) {
    if (err instanceof WrongPasswordError) {
      errorEl.textContent = 'Incorrect master password.';
    } else {
      errorEl.textContent = 'Something went wrong. Please try again.';
      console.error(err);
    }
  }
});

/**
 * Clears everything OUTSIDE the vault's own persisted blob that
 * represents "this browser session is unlocked" — the cached session key
 * and the idle-lock timer. Shared by an explicit Lock, deleting the
 * vault, and a duress-password wipe, since all three need the same
 * cleanup: the vault itself (vault.lock() / vault.wipe()) only owns its
 * own in-memory state and its one storage entry, never these
 * session-cache artifacts.
 */
function clearSessionArtifacts() {
  clearCachedSessionKeyBytes();
  clearIdleTimer();
}

// --- lock ---
document.getElementById('btn-lock').addEventListener('click', () => {
  vault.lock();
  clearSessionArtifacts();
  showView('view-unlock');
});

// --- entry list rendering + search ---
function renderEntryList() {
  const listEl = document.getElementById('entry-list');
  const emptyEl = document.getElementById('empty-state');
  const query = document.getElementById('search-box').value.trim().toLowerCase();

  const entries = vault
    .getEntries()
    .filter((e) => !query || e.title.toLowerCase().includes(query) || e.username.toLowerCase().includes(query))
    .sort((a, b) => a.title.localeCompare(b.title));

  listEl.innerHTML = '';
  emptyEl.style.display = entries.length ? 'none' : 'block';

  for (const entry of entries) {
    const li = document.createElement('li');
    li.className = 'entry-row';
    li.innerHTML = `
      <div class="entry-info">
        <span class="title"></span>
        <span class="username"></span>
      </div>
      <div class="entry-actions">
        <button data-action="copy-username" title="Copy username">User</button>
        <button data-action="copy-password" title="Copy password">Pass</button>
        <button data-action="edit" title="Edit">Edit</button>
      </div>
    `;
    li.querySelector('.title').textContent = entry.title;
    li.querySelector('.username').textContent = entry.username || '(no username)';

    li.querySelector('[data-action="copy-username"]').addEventListener('click', () => copyToClipboard(entry.username, 'Username copied'));
    li.querySelector('[data-action="copy-password"]').addEventListener('click', () => copyToClipboard(entry.password, 'Password copied'));
    li.querySelector('[data-action="edit"]').addEventListener('click', () => openEntryForm(entry));

    listEl.appendChild(li);
  }
}

document.getElementById('search-box').addEventListener('input', renderEntryList);

async function copyToClipboard(text, message) {
  try {
    await navigator.clipboard.writeText(text || '');
    showToast(message);
    resetIdleTimer();
  } catch (err) {
    console.error('Clipboard write failed', err);
    showToast('Could not copy — clipboard access blocked');
  }
}

// --- add / edit entry form ---
document.getElementById('btn-add').addEventListener('click', () => openEntryForm(null));

function openEntryForm(entry) {
  editingEntryId = entry ? entry.id : null;
  document.getElementById('entry-form-title').textContent = entry ? 'Edit login' : 'Add login';
  document.getElementById('entry-id').value = entry ? entry.id : '';
  document.getElementById('entry-title').value = entry ? entry.title : '';
  document.getElementById('entry-username').value = entry ? entry.username : '';
  document.getElementById('entry-password').value = entry ? entry.password : '';
  document.getElementById('entry-url').value = entry ? entry.url : '';
  document.getElementById('entry-notes').value = entry ? entry.notes : '';
  document.getElementById('entry-password').type = 'password';
  const entryToggleBtn = document.querySelector('.toggle-visibility-btn[data-target="entry-password"]');
  if (entryToggleBtn) setToggleState(entryToggleBtn, document.getElementById('entry-password'));
  document.getElementById('btn-delete-entry').style.display = entry ? 'inline-block' : 'none';
  showView('view-entry-form');
}

document.getElementById('btn-cancel-entry').addEventListener('click', () => {
  renderEntryList();
  showView('view-vault');
});

// entry-password's own toggle button is wired up generically, alongside
// every other password field's, by the .toggle-visibility-btn[data-target]
// loop near the top of this file.

document.getElementById('btn-generate').addEventListener('click', () => {
  const pw = generatePassword({ length: 20 });
  const input = document.getElementById('entry-password');
  input.value = pw;
  input.type = 'text';
  const toggleBtn = document.querySelector('.toggle-visibility-btn[data-target="entry-password"]');
  if (toggleBtn) setToggleState(toggleBtn, input);
});

document.getElementById('form-entry').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = {
    title: document.getElementById('entry-title').value.trim(),
    username: document.getElementById('entry-username').value.trim(),
    password: document.getElementById('entry-password').value,
    url: document.getElementById('entry-url').value.trim(),
    notes: document.getElementById('entry-notes').value.trim(),
  };
  if (editingEntryId) {
    await vault.updateEntry(editingEntryId, payload);
  } else {
    await vault.addEntry(payload);
  }
  resetIdleTimer();
  renderEntryList();
  showView('view-vault');
});

document.getElementById('btn-delete-entry').addEventListener('click', async () => {
  if (!editingEntryId) return;
  await vault.deleteEntry(editingEntryId);
  resetIdleTimer();
  renderEntryList();
  showView('view-vault');
});

// --- export ---
document.getElementById('btn-open-export').addEventListener('click', () => {
  resetPasswordField('export-password');
  document.getElementById('export-error').textContent = '';
  showView('view-export');
});

document.getElementById('btn-cancel-export').addEventListener('click', () => showView('view-vault'));

document.getElementById('form-export').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = document.getElementById('export-password').value;
  const errorEl = document.getElementById('export-error');
  try {
    const exported = await vault.exportEntries(pw);
    downloadJSON(`burn-locker-export-${todayStamp()}.json`, exported);
    resetIdleTimer();
    showToast('Export downloaded');
    showView('view-vault');
  } catch (err) {
    if (err instanceof WrongPasswordError) {
      errorEl.textContent = 'Incorrect master password.';
    } else {
      errorEl.textContent = 'Something went wrong. Please try again.';
      console.error(err);
    }
  }
});

// --- import ---
document.getElementById('btn-open-import').addEventListener('click', () => {
  document.getElementById('import-file').value = '';
  resetPasswordField('import-password');
  document.getElementById('import-error').textContent = '';
  showView('view-import');
});

document.getElementById('btn-cancel-import').addEventListener('click', () => {
  renderEntryList();
  showView('view-vault');
});

document.getElementById('form-import').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById('import-file');
  const pw = document.getElementById('import-password').value;
  const errorEl = document.getElementById('import-error');
  const file = fileInput.files[0];

  if (!file) {
    errorEl.textContent = 'Choose an export file first.';
    return;
  }

  try {
    const exported = JSON.parse(await file.text());
    const result = await vault.importEntries(exported, pw);
    resetIdleTimer();
    renderEntryList();
    showToast(summarizeImport(result));
    showView('view-vault');
  } catch (err) {
    if (err instanceof WrongPasswordError) {
      errorEl.textContent = 'Incorrect password for that export file.';
    } else if (err instanceof SyntaxError) {
      errorEl.textContent = "That file doesn't look like a valid export.";
    } else {
      errorEl.textContent = err.message || 'Something went wrong. Please try again.';
      console.error(err);
    }
  }
});

function downloadJSON(filename, dataObj) {
  const blob = new Blob([JSON.stringify(dataObj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function todayStamp() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

/** Turns { added, updated, skipped } from importEntries() into one readable line. */
function summarizeImport({ added, updated, skipped }) {
  const parts = [];
  if (added) parts.push(`${added} added`);
  if (updated) parts.push(`${updated} updated`);
  if (skipped) parts.push(`${skipped} already up to date`);
  return parts.length ? parts.join(', ') : 'Nothing new to import';
}

// --- security hub ---
document.getElementById('btn-open-security').addEventListener('click', async () => {
  const hasDuress = await vault.hasDuressPassword();
  document.getElementById('duress-status').textContent = hasDuress
    ? 'A duress password is currently set.'
    : 'No duress password is set.';
  document.getElementById('btn-setup-duress').style.display = hasDuress ? 'none' : 'inline-block';
  document.getElementById('btn-remove-duress').style.display = hasDuress ? 'inline-block' : 'none';
  showView('view-security');
});

document.getElementById('btn-cancel-security').addEventListener('click', () => showView('view-vault'));

// --- delete vault ("burn") ---
document.getElementById('btn-open-burn').addEventListener('click', () => {
  resetPasswordField('burn-password');
  document.getElementById('burn-error').textContent = '';
  showView('view-burn-confirm');
});

document.getElementById('btn-cancel-burn').addEventListener('click', () => showView('view-security'));

document.getElementById('form-burn-confirm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = document.getElementById('burn-password').value;
  const errorEl = document.getElementById('burn-error');
  try {
    const correct = await vault.verifyMasterPassword(pw);
    if (!correct) {
      errorEl.textContent = 'Incorrect master password.';
      return;
    }
    await vault.wipe();
    clearSessionArtifacts();
    resetPasswordField('burn-password');
    resetCreateForm();
    showView('view-create'); // same screen a brand new install shows
  } catch (err) {
    errorEl.textContent = 'Something went wrong. Please try again.';
    console.error(err);
  }
});

// --- set up duress password ---
document.getElementById('btn-setup-duress').addEventListener('click', () => {
  resetPasswordField('duress-setup-master');
  resetPasswordField('duress-setup-password');
  resetPasswordField('duress-setup-confirm');
  document.getElementById('duress-setup-error').textContent = '';
  showView('view-duress-setup');
});

document.getElementById('btn-cancel-duress-setup').addEventListener('click', () => showView('view-security'));

document.getElementById('form-duress-setup').addEventListener('submit', async (e) => {
  e.preventDefault();
  const masterPw = document.getElementById('duress-setup-master').value;
  const duressPw = document.getElementById('duress-setup-password').value;
  const confirmPw = document.getElementById('duress-setup-confirm').value;
  const errorEl = document.getElementById('duress-setup-error');

  if (duressPw !== confirmPw) {
    errorEl.textContent = "Duress passwords don't match.";
    return;
  }
  try {
    await vault.setDuressPassword(masterPw, duressPw);
    errorEl.textContent = '';
    showToast('Duress password set');
    showView('view-vault');
    renderEntryList();
  } catch (err) {
    if (err instanceof WrongPasswordError) {
      errorEl.textContent = 'Incorrect master password.';
    } else {
      errorEl.textContent = err.message || 'Something went wrong. Please try again.';
    }
  }
});

// --- remove duress password ---
document.getElementById('btn-remove-duress').addEventListener('click', () => {
  resetPasswordField('duress-remove-master');
  document.getElementById('duress-remove-error').textContent = '';
  showView('view-duress-remove');
});

document.getElementById('btn-cancel-duress-remove').addEventListener('click', () => showView('view-security'));

document.getElementById('form-duress-remove').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = document.getElementById('duress-remove-master').value;
  const errorEl = document.getElementById('duress-remove-error');
  try {
    await vault.removeDuressPassword(pw);
    errorEl.textContent = '';
    showToast('Duress password removed');
    showView('view-vault');
    renderEntryList();
  } catch (err) {
    if (err instanceof WrongPasswordError) {
      errorEl.textContent = 'Incorrect master password.';
    } else {
      errorEl.textContent = 'Something went wrong. Please try again.';
      console.error(err);
    }
  }
});

// --- service worker registration (offline support + installability) ---
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch((err) => console.error('Service worker registration failed', err));
  });
}

init();
