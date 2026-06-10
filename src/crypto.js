// crypto.js — Valv cryptography module
//
// Written to run unchanged in both the browser and Node (>= 19):
// globalThis.crypto (WebCrypto) and btoa/atob exist globally in both.
// In the browser build, build.mjs strips the export line at the bottom so
// the functions become plain global declarations; the Node test suite
// imports this file as an ES module.
//
// Design (see CLAUDE.md):
//   password --PBKDF2-SHA256, 600k iterations, 16 B salt--> AES-256-GCM key
//   key + 12 B random nonce (FRESH on every encryption) --> ciphertext
//   A wrong password or tampered data means the GCM tag does not validate
//   and decrypt throws. Corrupt plaintext is therefore never produced.
'use strict';

// Default PBKDF2 iteration count for NEW vaults. Deliberately high — key
// derivation happens once per unlock/save, so ~0.5 s of work is a fair
// price for making offline guessing expensive. Stored in the file format's
// `iterations` field, so it can be raised in future versions without
// breaking existing vaults (decryption always reads it from the file).
const KDF_ITERATIONS_DEFAULT = 600000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;

/**
 * Cryptographically secure random bytes (never Math.random).
 * @param {number} length
 * @returns {Uint8Array}
 */
function randomBytes(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Encode bytes as base64 (the on-disk representation of all binary fields).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function toBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Decode a base64 string back into bytes.
 * @param {string} base64
 * @returns {Uint8Array}
 */
function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Derive an AES-256-GCM key from a master password with PBKDF2-SHA256.
 *
 * The iteration count is a parameter — not a constant — because decryption
 * must use whatever count the vault file declares (format versioning).
 * The resulting key is non-extractable: the raw key material can never be
 * read back out of the CryptoKey object, even by app code.
 *
 * @param {string} password master password (never stored or logged)
 * @param {Uint8Array} salt 16 random bytes, stored alongside the ciphertext
 * @param {number} iterations PBKDF2 iteration count from the file format
 * @returns {Promise<CryptoKey>} non-extractable AES-GCM key
 */
async function deriveKey(password, salt, iterations) {
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return globalThis.crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']);
}

/**
 * Encrypt plaintext with a derived key.
 *
 * Generates a FRESH random 12-byte nonce on every call. Reusing a nonce
 * under the same key would be catastrophic for GCM (it leaks the XOR of
 * plaintexts and breaks authentication), which is why callers cannot pass
 * a nonce in.
 *
 * @param {CryptoKey} key from deriveKey()
 * @param {string} plaintext UTF-8 string (the serialized vault payload)
 * @returns {Promise<{nonce: string, ciphertext: string}>} both base64
 */
async function encryptWithKey(key, plaintext) {
  const nonce = randomBytes(NONCE_BYTES);
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(plaintext));
  return { nonce: toBase64(nonce), ciphertext: toBase64(new Uint8Array(ciphertext)) };
}

/**
 * Decrypt ciphertext with a derived key.
 *
 * @param {CryptoKey} key from deriveKey()
 * @param {string} nonceB64 base64 nonce stored with the ciphertext
 * @param {string} ciphertextB64 base64 ciphertext (includes the GCM tag)
 * @returns {Promise<string>} the plaintext
 * @throws if the key is wrong or the data was tampered with — the GCM tag
 *   validates both, so corrupt plaintext is never returned
 */
async function decryptWithKey(key, nonceB64, ciphertextB64) {
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(nonceB64) }, key, fromBase64(ciphertextB64));
  return new TextDecoder().decode(plaintext);
}

/**
 * Full flow password -> complete vault block in the file format.
 * Used at vault creation and password change (fresh salt each time) and in
 * the test suite.
 *
 * @param {string} password
 * @param {string} plaintext
 * @param {number} [iterations] defaults to KDF_ITERATIONS_DEFAULT; the
 *   chosen value is recorded in the block's `iterations` field
 * @returns {Promise<object>} `{version, kdf, iterations, salt, nonce, ciphertext}`
 */
async function encryptVault(password, plaintext, iterations = KDF_ITERATIONS_DEFAULT) {
  const salt = randomBytes(SALT_BYTES);
  const key = await deriveKey(password, salt, iterations);
  const { nonce, ciphertext } = await encryptWithKey(key, plaintext);
  return {
    version: 1,
    kdf: 'PBKDF2-SHA256',
    iterations,
    salt: toBase64(salt),
    nonce,
    ciphertext,
  };
}

/**
 * Decrypt a vault block produced by encryptVault (or by the app).
 * Reads the iteration count from the block itself so that vaults written
 * by older or newer app versions keep working.
 *
 * @param {string} password
 * @param {object} blob a parsed vault block
 * @returns {Promise<string>} the plaintext payload
 * @throws on wrong password or tampered data
 */
async function decryptVault(password, blob) {
  const key = await deriveKey(password, fromBase64(blob.salt), blob.iterations);
  return decryptWithKey(key, blob.nonce, blob.ciphertext);
}

export {
  KDF_ITERATIONS_DEFAULT, SALT_BYTES, NONCE_BYTES,
  randomBytes, toBase64, fromBase64,
  deriveKey, encryptWithKey, decryptWithKey, encryptVault, decryptVault,
};
