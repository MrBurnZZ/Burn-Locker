// core/vault.js
//
// Sits one layer above crypto.js: this is where "the vault" as a concept
// lives — creating one, unlocking it, and adding/editing/removing entries.
// It doesn't care whether it's running in the browser extension or the
// mobile web app; each of those just hands it a small `storage` object
// (get/set) for wherever that platform keeps data, and everything else
// is identical. That's what lets both share this one file unmodified.

import { generateSalt, deriveKey, encryptJSON, decryptJSON, exportKeyRaw, hashRawKey, DEFAULT_PBKDF2_ITERATIONS } from './crypto.js';

const STORAGE_KEY = 'vaultBlob';

// What a vault created before iteration counts were stored alongside it
// (i.e. before this migration existed) must have used — PBKDF2's original
// hardcoded value. Only used as a fallback when a stored blob has no
// `iterations` field of its own.
const LEGACY_PBKDF2_ITERATIONS = 310000;

export class WrongPasswordError extends Error {
  constructor() {
    super('Incorrect master password');
    this.name = 'WrongPasswordError';
  }
}

export class Vault {
  /**
   * @param {{get: (key:string)=>Promise<any>, set: (key:string, val:any)=>Promise<void>}} storage
   */
  constructor(storage) {
    this.storage = storage;
    this.key = null; // the in-memory AES key, only set while unlocked
    this.data = null; // { entries: [...] }, only set while unlocked
  }

  /** Has a vault already been created on this device? */
  async exists() {
    const blob = await this.storage.get(STORAGE_KEY);
    return !!blob;
  }

  /** First-time setup: pick a master password and create an empty vault. */
  async create(masterPassword) {
    const salt = generateSalt();
    this.key = await deriveKey(masterPassword, salt, { iterations: DEFAULT_PBKDF2_ITERATIONS });
    this.data = { entries: [] };
    await this._persist(salt, DEFAULT_PBKDF2_ITERATIONS);
  }

  /**
   * Attempt to unlock an existing vault. Throws WrongPasswordError if the
   * master password is incorrect (decryption failing IS the password
   * check — see core/crypto.js for why).
   *
   * Also carries a one-time, backward-compatible security upgrade: a vault
   * created back when PBKDF2_ITERATIONS was lower gets quietly re-derived
   * with today's DEFAULT_PBKDF2_ITERATIONS and a fresh salt, right after
   * its password is confirmed correct — the same "upgrade on next login"
   * pattern a lot of password-hashing systems use. This only happens once
   * per vault (after which its stored iteration count matches the
   * default, so this check is a no-op on every later unlock). Doing it
   * this way — rather than just raising the constant — is deliberate:
   * silently changing what a stored value means broke real unlocks once
   * already in this project (see the "master password no longer works"
   * incident in README/ROADMAP), so this stores what was actually used.
   */
  async unlock(masterPassword) {
    const blob = await this.storage.get(STORAGE_KEY);
    if (!blob) throw new Error('No vault exists on this device yet');
    const storedIterations = blob.iterations || LEGACY_PBKDF2_ITERATIONS;
    const key = await deriveKey(masterPassword, base64ToBytes(blob.salt), { iterations: storedIterations });
    await this.unlockWithKey(key);

    if (storedIterations < DEFAULT_PBKDF2_ITERATIONS) {
      const newSalt = generateSalt();
      this.key = await deriveKey(masterPassword, newSalt, { iterations: DEFAULT_PBKDF2_ITERATIONS });
      await this._persist(newSalt, DEFAULT_PBKDF2_ITERATIONS);
    }
  }

  /**
   * Unlock using an already-derived key instead of a password — used to
   * restore a "stay unlocked for this browser session" cache without
   * asking for the master password again. Throws WrongPasswordError if
   * the key doesn't decrypt the stored vault (e.g. a stale/corrupt cache).
   */
  async unlockWithKey(key) {
    const blob = await this.storage.get(STORAGE_KEY);
    if (!blob) throw new Error('No vault exists on this device yet');
    let data;
    try {
      data = await decryptJSON(key, blob.iv, blob.ciphertext);
    } catch {
      throw new WrongPasswordError();
    }
    this.key = key;
    this.data = data;
  }

  /**
   * Derive an EXTRACTABLE copy of the vault key from the master password.
   * Only used for one purpose: producing raw bytes that can be cached in
   * session storage. The key actually used for day-to-day encrypt/decrypt
   * (from create()/unlock()) is always non-extractable — this is a
   * separate, one-off derivation so that stronger guarantee never has to
   * be relaxed just to support session caching.
   */
  async deriveExtractableKey(masterPassword) {
    return this._deriveKeyFromStoredSalt(masterPassword, { extractable: true });
  }

  async _deriveKeyFromStoredSalt(masterPassword, options = {}) {
    const blob = await this.storage.get(STORAGE_KEY);
    if (!blob) throw new Error('No vault exists on this device yet');
    const salt = base64ToBytes(blob.salt);
    const iterations = blob.iterations || LEGACY_PBKDF2_ITERATIONS;
    return deriveKey(masterPassword, salt, { ...options, iterations });
  }

  /** Wipe the in-memory key and decrypted data. Call this on lock/close. */
  lock() {
    this.key = null;
    this.data = null;
  }

  get unlocked() {
    return this.key !== null;
  }

  getEntries() {
    this._assertUnlocked();
    return this.data.entries;
  }

  async addEntry({ title, username, password, url = '', notes = '' }) {
    this._assertUnlocked();
    const entry = {
      id: crypto.randomUUID(),
      title,
      username,
      password,
      url,
      notes,
      updatedAt: Date.now(),
    };
    this.data.entries.push(entry);
    await this._persist();
    return entry;
  }

  async updateEntry(id, changes) {
    this._assertUnlocked();
    const entry = this.data.entries.find((e) => e.id === id);
    if (!entry) throw new Error('Entry not found');
    Object.assign(entry, changes, { updatedAt: Date.now() });
    await this._persist();
    return entry;
  }

  async deleteEntry(id) {
    this._assertUnlocked();
    this.data.entries = this.data.entries.filter((e) => e.id !== id);
    await this._persist();
  }

  _assertUnlocked() {
    if (!this.unlocked) throw new Error('Vault is locked');
  }

  /**
   * Checks whether `password` is this vault's real master password,
   * without changing anything and without requiring the vault to already
   * be unlocked. Used to gate sensitive actions (deleting the vault,
   * setting/removing the duress password) behind proof of the master
   * password, the same re-verify-don't-trust-the-session approach
   * exportEntries has always used.
   */
  async verifyMasterPassword(password) {
    const blob = await this.storage.get(STORAGE_KEY);
    if (!blob) throw new Error('No vault exists on this device yet');
    const verifyKey = await this._deriveKeyFromStoredSalt(password);
    try {
      await decryptJSON(verifyKey, blob.iv, blob.ciphertext);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Package the current entries into an encrypted, portable file — this is
   * how entries move between the extension and the mobile web app, since
   * v1 has no live sync between them. Re-verifies the master password
   * against the actual stored vault first (rather than trusting whatever
   * was typed), so a typo here fails loudly now instead of producing a
   * file that silently can't be decrypted later. The export is protected
   * with its own fresh salt — never the live vault's — so it's a
   * self-contained encrypted artifact in its own right, not merely a copy
   * of vault internals.
   */
  async exportEntries(masterPassword) {
    if (!(await this.verifyMasterPassword(masterPassword))) {
      throw new WrongPasswordError();
    }

    const exportSalt = generateSalt();
    const exportIterations = DEFAULT_PBKDF2_ITERATIONS;
    const exportKey = await deriveKey(masterPassword, exportSalt, { iterations: exportIterations });
    const { iv, ciphertext } = await encryptJSON(exportKey, { entries: this.data.entries });
    return {
      // This literal tag is a cross-platform compatibility token shared
      // with the Windows app's export format, not user-facing text, so it
      // deliberately keeps its pre-rebrand value rather than following the
      // Simple Vault → Burn Locker rename.
      format: 'simple-vault-export',
      version: 1,
      salt: bytesToBase64(exportSalt),
      iterations: exportIterations,
      iv,
      ciphertext,
      exportedAt: Date.now(),
    };
  }

  /**
   * Decrypt a file produced by exportEntries() and merge its entries into
   * the currently unlocked vault. "Same entry" is decided by matching
   * title + username (case-insensitive, trimmed) against what's already
   * here — there's no shared id between separate vaults to match on, so
   * this is a heuristic, not a guarantee. For each incoming entry:
   *   - no match found              → added as a new entry
   *   - match found, incoming newer → the existing entry is updated in
   *                                    place (its id is kept)
   *   - match found, not newer      → skipped, nothing changes
   * "Newer" compares each entry's updatedAt timestamp, so importing the
   * same file twice is a no-op the second time rather than creating
   * duplicates. Returns { added, updated, skipped } counts.
   */
  async importEntries(exportedFile, password) {
    this._assertUnlocked();
    if (!exportedFile || exportedFile.format !== 'simple-vault-export') {
      throw new Error('This file is not a Burn Locker export.');
    }

    const salt = base64ToBytes(exportedFile.salt);
    const iterations = exportedFile.iterations || LEGACY_PBKDF2_ITERATIONS; // older export files predate this field
    const key = await deriveKey(password, salt, { iterations });
    let decrypted;
    try {
      decrypted = await decryptJSON(key, exportedFile.iv, exportedFile.ciphertext);
    } catch {
      throw new WrongPasswordError();
    }

    const incoming = Array.isArray(decrypted.entries) ? decrypted.entries : [];
    const matchKey = (e) => `${(e.title || '').trim().toLowerCase()}\u0000${(e.username || '').trim().toLowerCase()}`;
    const existingByKey = new Map(this.data.entries.map((e) => [matchKey(e), e]));

    let added = 0;
    let updated = 0;
    let skipped = 0;

    for (const incomingEntry of incoming) {
      const normalized = {
        title: incomingEntry.title || '(untitled)',
        username: incomingEntry.username || '',
        password: incomingEntry.password || '',
        url: incomingEntry.url || '',
        notes: incomingEntry.notes || '',
      };
      const existing = existingByKey.get(matchKey(normalized));

      if (!existing) {
        const fresh = { id: crypto.randomUUID(), ...normalized, updatedAt: Date.now() };
        this.data.entries.push(fresh);
        existingByKey.set(matchKey(fresh), fresh); // so a later dup within the same file matches this, not re-adds
        added++;
        continue;
      }

      const incomingUpdatedAt = incomingEntry.updatedAt || 0;
      if (incomingUpdatedAt > existing.updatedAt) {
        Object.assign(existing, normalized, { updatedAt: Date.now() });
        updated++;
      } else {
        skipped++;
      }
    }

    await this._persist();
    return { added, updated, skipped };
  }

  /**
   * Re-encrypt the current in-memory data and write it to storage.
   * `newSalt`/`newIterations` only need to be passed when they're
   * changing (first creation, or the iteration-count upgrade in unlock());
   * otherwise whatever's already on disk is carried forward unchanged —
   * ordinary saves (adding/editing/deleting an entry) never touch either.
   * `newDuress` follows the same "omit to keep, pass null to clear"
   * pattern, distinct from "not provided" — see setDuressPassword/
   * removeDuressPassword.
   */
  async _persist(newSalt, newIterations, newDuress) {
    const existing = await this.storage.get(STORAGE_KEY);
    const saltB64 = newSalt ? bytesToBase64(newSalt) : existing.salt;
    const iterations = newIterations || existing?.iterations || LEGACY_PBKDF2_ITERATIONS;
    const duress = newDuress !== undefined ? newDuress : existing?.duress;
    const { iv, ciphertext } = await encryptJSON(this.key, this.data);
    const blob = { salt: saltB64, iterations, iv, ciphertext, updatedAt: Date.now() };
    if (duress) blob.duress = duress;
    await this.storage.set(STORAGE_KEY, blob);
  }

  /**
   * Permanently deletes this vault's own data — the encrypted entries and
   * whatever salt/iteration/duress config goes with them — and nothing
   * else. It's all one storage entry (STORAGE_KEY / 'vaultBlob'), so
   * removing it can't accidentally touch any other key this app or the
   * browser stores, let alone anything outside this app. Callers (the
   * "delete vault" button and the duress-password trigger in popup.js/
   * app.js) are responsible for also clearing their own session-cache key
   * and idle-lock timer afterward — the same cleanup already done on an
   * ordinary Lock — since this method only owns the persisted vault blob.
   */
  async wipe() {
    this.lock();
    await this.storage.remove(STORAGE_KEY);
  }

  /**
   * True if `candidatePassword` is this vault's duress password — the one
   * that, typed at the unlock screen instead of the real master password,
   * should trigger a silent wipe rather than an unlock attempt. Safe (and
   * meant) to call while the vault is still locked, since that's exactly
   * when it needs to run: before a normal unlock() is even attempted.
   * Returns false if no duress password has been set up for this vault.
   */
  async isDuressPassword(candidatePassword) {
    const blob = await this.storage.get(STORAGE_KEY);
    if (!blob || !blob.duress) return false;
    const { salt, iterations, verifier } = blob.duress;
    const key = await deriveKey(candidatePassword, base64ToBytes(salt), { iterations, extractable: true });
    const candidateVerifier = await hashRawKey(await exportKeyRaw(key));
    return candidateVerifier === verifier;
  }

  /** Has a duress password been set up for this vault? */
  async hasDuressPassword() {
    const blob = await this.storage.get(STORAGE_KEY);
    return !!blob?.duress;
  }

  /**
   * Sets (or replaces) this vault's duress password. Requires the REAL
   * master password to be re-entered first — this changes a security
   * setting, so it shouldn't be settable by anyone who merely finds the
   * vault open and unlocked, the same reasoning as export re-verifying the
   * password rather than trusting an already-unlocked session.
   *
   * Only a comparison "verifier" is stored for the duress password — a
   * salted, PBKDF2-hardened hash of it (see crypto.js's hashRawKey) — not
   * the password itself, and the duress password is never used to encrypt
   * anything. There's no decoy vault in this version (a real one would let
   * an attacker see cover data on a duress unlock, at real added
   * complexity); entering it here always means "wipe," not "show something
   * else instead."
   */
  async setDuressPassword(masterPassword, duressPassword) {
    this._assertUnlocked();
    if (!duressPassword || duressPassword.length < 8) {
      throw new Error('Use a duress password of at least 8 characters.');
    }

    if (!(await this.verifyMasterPassword(masterPassword))) {
      throw new WrongPasswordError();
    }
    if (duressPassword === masterPassword) {
      throw new Error('The duress password must be different from your master password.');
    }

    const duressSalt = generateSalt();
    const duressKey = await deriveKey(duressPassword, duressSalt, {
      iterations: DEFAULT_PBKDF2_ITERATIONS,
      extractable: true,
    });
    const verifier = await hashRawKey(await exportKeyRaw(duressKey));
    await this._persist(undefined, undefined, {
      salt: bytesToBase64(duressSalt),
      iterations: DEFAULT_PBKDF2_ITERATIONS,
      verifier,
    });
  }

  /** Turns off the duress password. Also requires the real master password. */
  async removeDuressPassword(masterPassword) {
    this._assertUnlocked();
    if (!(await this.verifyMasterPassword(masterPassword))) {
      throw new WrongPasswordError();
    }
    await this._persist(undefined, undefined, null);
  }
}

function bytesToBase64(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
