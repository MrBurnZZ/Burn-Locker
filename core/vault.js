// core/vault.js
//
// Sits one layer above crypto.js: this is where "the vault" as a concept
// lives — creating one, unlocking it, and adding/editing/removing entries.
// It doesn't care whether it's running in the browser extension or the
// mobile web app; each of those just hands it a small `storage` object
// (get/set) for wherever that platform keeps data, and everything else
// is identical. That's what lets both share this one file unmodified.

import { generateSalt, deriveKey, encryptJSON, decryptJSON } from './crypto.js';

const STORAGE_KEY = 'vaultBlob';

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
    this.key = await deriveKey(masterPassword, salt);
    this.data = { entries: [] };
    await this._persist(salt);
  }

  /**
   * Attempt to unlock an existing vault. Throws WrongPasswordError if the
   * master password is incorrect (decryption failing IS the password
   * check — see core/crypto.js for why).
   */
  async unlock(masterPassword) {
    const key = await this._deriveKeyFromStoredSalt(masterPassword);
    await this.unlockWithKey(key);
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

  async _deriveKeyFromStoredSalt(masterPassword, options) {
    const blob = await this.storage.get(STORAGE_KEY);
    if (!blob) throw new Error('No vault exists on this device yet');
    const salt = base64ToBytes(blob.salt);
    return deriveKey(masterPassword, salt, options);
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
    const verifyKey = await this._deriveKeyFromStoredSalt(masterPassword);
    const blob = await this.storage.get(STORAGE_KEY);
    try {
      await decryptJSON(verifyKey, blob.iv, blob.ciphertext);
    } catch {
      throw new WrongPasswordError();
    }

    const exportSalt = generateSalt();
    const exportKey = await deriveKey(masterPassword, exportSalt);
    const { iv, ciphertext } = await encryptJSON(exportKey, { entries: this.data.entries });
    return {
      format: 'simple-vault-export',
      version: 1,
      salt: bytesToBase64(exportSalt),
      iv,
      ciphertext,
      exportedAt: Date.now(),
    };
  }

  /**
   * Decrypt a file produced by exportEntries() and add its entries to the
   * currently unlocked vault. Deliberately simple for v1: every incoming
   * entry is added as new (with a fresh id), never matched up against or
   * merged with existing entries — importing the same file twice will
   * create duplicates rather than silently guessing which entries are
   * "the same." Returns how many entries were added.
   */
  async importEntries(exportedFile, password) {
    this._assertUnlocked();
    if (!exportedFile || exportedFile.format !== 'simple-vault-export') {
      throw new Error('This file is not a Simple Vault export.');
    }

    const salt = base64ToBytes(exportedFile.salt);
    const key = await deriveKey(password, salt);
    let decrypted;
    try {
      decrypted = await decryptJSON(key, exportedFile.iv, exportedFile.ciphertext);
    } catch {
      throw new WrongPasswordError();
    }

    const incoming = Array.isArray(decrypted.entries) ? decrypted.entries : [];
    for (const entry of incoming) {
      this.data.entries.push({
        id: crypto.randomUUID(),
        title: entry.title || '(untitled)',
        username: entry.username || '',
        password: entry.password || '',
        url: entry.url || '',
        notes: entry.notes || '',
        updatedAt: Date.now(),
      });
    }
    await this._persist();
    return incoming.length;
  }

  /**
   * Re-encrypt the current in-memory data and write it to storage.
   * `salt` only needs to be passed on first creation; after that we reuse
   * the salt already on disk (it isn't secret, it just needs to stay
   * consistent so the same password always derives the same key).
   */
  async _persist(newSalt) {
    let saltB64;
    if (newSalt) {
      saltB64 = bytesToBase64(newSalt);
    } else {
      const existing = await this.storage.get(STORAGE_KEY);
      saltB64 = existing.salt;
    }
    const { iv, ciphertext } = await encryptJSON(this.key, this.data);
    await this.storage.set(STORAGE_KEY, { salt: saltB64, iv, ciphertext, updatedAt: Date.now() });
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
