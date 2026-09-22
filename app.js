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

// --- view switching ---
const views = ['view-create', 'view-unlock', 'view-vault', 'view-entry-form'];
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
  try {
    await vault.unlock(pw);
    await cacheSession(pw);
    errorEl.textContent = '';
    document.getElementById('unlock-password').value = '';
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

// --- lock ---
document.getElementById('btn-lock').addEventListener('click', () => {
  vault.lock();
  clearCachedSessionKeyBytes();
  clearIdleTimer();
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
  document.getElementById('btn-delete-entry').style.display = entry ? 'inline-block' : 'none';
  showView('view-entry-form');
}

document.getElementById('btn-cancel-entry').addEventListener('click', () => {
  renderEntryList();
  showView('view-vault');
});

document.getElementById('btn-toggle-password').addEventListener('click', () => {
  const input = document.getElementById('entry-password');
  input.type = input.type === 'password' ? 'text' : 'password';
});

document.getElementById('btn-generate').addEventListener('click', () => {
  const pw = generatePassword({ length: 20 });
  const input = document.getElementById('entry-password');
  input.value = pw;
  input.type = 'text';
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

// --- service worker registration (offline support + installability) ---
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch((err) => console.error('Service worker registration failed', err));
  });
}

init();
