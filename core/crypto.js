// core/crypto.js
//
// This is the only file in the whole project that touches actual cryptography.
// Everything else (extension UI, web app UI) just calls these functions.
// Keeping crypto in one small, well-tested file is deliberate: it's the
// single place a mistake would matter most, so it's the single place to
// review carefully.
//
// Design in plain terms:
//   - Nothing here ever sends anything anywhere. It only runs on the device.
//   - The master password itself is NEVER stored, anywhere, in any form.
//   - Instead, we derive an encryption key FROM the master password
//     (PBKDF2), and use that key to encrypt/decrypt the vault (AES-GCM).
//   - "Is the password correct?" is answered by "did decryption succeed?" —
//     there's no separate password hash stored to check against, which
//     means there's one less thing that could leak.
//   - Uses only the browser/Node built-in Web Crypto API (`crypto.subtle`).
//     No hand-rolled crypto, no third-party crypto library to trust.

const PBKDF2_ITERATIONS = 310000; // OWASP-recommended floor for PBKDF2-SHA256 as of 2023+
const KEY_LENGTH_BITS = 256; // AES-256
const SALT_LENGTH_BYTES = 16;
const IV_LENGTH_BYTES = 12; // recommended IV size for AES-GCM

const subtle = globalThis.crypto.subtle;

function toBase64(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromBase64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Random salt, generated fresh once per vault (stored alongside the vault, not secret). */
export function generateSalt() {
  return globalThis.crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
}

/**
 * Derive an AES-GCM encryption key from a master password + salt.
 * PBKDF2 with a high iteration count makes brute-forcing the master
 * password computationally expensive even if someone steals the
 * encrypted vault file.
 *
 * By default the resulting key is non-extractable — the raw key bytes can
 * never be read back out, only used to encrypt/decrypt. Pass
 * `{ extractable: true }` only when the raw bytes genuinely need to be
 * exported (see exportKeyRaw below) — right now that's just the "stay
 * unlocked for this browser session" feature, which needs to stash the
 * key somewhere it can be picked back up from.
 */
export async function deriveKey(masterPassword, salt, { extractable = false } = {}) {
  const passwordBytes = new TextEncoder().encode(masterPassword);
  const baseKey = await subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: KEY_LENGTH_BITS },
    extractable,
    ['encrypt', 'decrypt']
  );
}

/**
 * Export a key's raw bytes so they can be cached somewhere (e.g. the
 * browser's in-memory session storage) and re-imported later without
 * asking for the master password again. Only works on a key that was
 * derived with { extractable: true } — see deriveKey.
 */
export async function exportKeyRaw(key) {
  const raw = await subtle.exportKey('raw', key);
  return toBase64(new Uint8Array(raw));
}

/**
 * Rebuild a usable key from bytes previously produced by exportKeyRaw.
 * The rebuilt key is non-extractable by default — even though it started
 * life as an exportable key, once it's re-imported this way there's no
 * way to export it again, which keeps the key actually used for ongoing
 * encrypt/decrypt work held to the same "can't be read back out" standard
 * as a normal freshly-derived key.
 */
export async function importKeyRaw(rawBase64, { extractable = false } = {}) {
  const raw = fromBase64(rawBase64);
  return subtle.importKey('raw', raw, 'AES-GCM', extractable, ['encrypt', 'decrypt']);
}

/**
 * Encrypt a JS object under the given key. Returns base64 strings safe to
 * store in extension storage / IndexedDB / a backup file.
 * A fresh random IV is used every time — reusing an IV with AES-GCM is the
 * one mistake that breaks its guarantees, so we generate one per call.
 */
export async function encryptJSON(key, data) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return {
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext)),
  };
}

/**
 * Decrypt back to a JS object. AES-GCM is "authenticated" encryption: if
 * the key is wrong (wrong master password) or the data was tampered with,
 * this throws instead of silently returning garbage. That's what lets us
 * use "did decrypt() succeed?" as the password check.
 */
export async function decryptJSON(key, iv, ciphertext) {
  const plaintextBytes = await subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(iv) },
    key,
    fromBase64(ciphertext)
  );
  return JSON.parse(new TextDecoder().decode(plaintextBytes));
}

/**
 * Cryptographically secure password generator. Uses rejection sampling
 * (not modulo on getRandomValues) so every allowed character stays equally
 * likely — a `% charset.length` shortcut subtly biases toward the low end
 * of the charset, which is a real weakness in a "random" password.
 */
export function generatePassword({
  length = 20,
  uppercase = true,
  lowercase = true,
  numbers = true,
  symbols = true,
} = {}) {
  let charset = '';
  if (uppercase) charset += 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // no I/O — easy to misread
  if (lowercase) charset += 'abcdefghijkmnopqrstuvwxyz'; // no l
  if (numbers) charset += '23456789'; // no 0/1
  if (symbols) charset += '!@#$%^&*()-_=+[]{}';

  if (!charset) throw new Error('At least one character set must be enabled');

  const maxValid = 256 - (256 % charset.length);
  const result = [];
  const buf = new Uint8Array(1);
  while (result.length < length) {
    globalThis.crypto.getRandomValues(buf);
    if (buf[0] >= maxValid) continue; // reject biased range, try again
    result.push(charset[buf[0] % charset.length]);
  }
  return result.join('');
}
