// crypto.js — Valv kryptomodul
//
// Skriven för att fungera oförändrad i både webbläsare och Node (>= 19):
// globalThis.crypto (WebCrypto) samt btoa/atob finns globalt i båda.
// I webbläsarbygget tar build.mjs bort export-raden längst ned, så att
// funktionerna blir vanliga globala deklarationer; i Node-testerna
// importeras filen som en ES-modul.
//
// Design (se CLAUDE.md):
//   lösenord --PBKDF2-SHA256, 600 000 iter, 16 B salt--> AES-256-GCM-nyckel
//   nyckel + 12 B slumpad nonce (NY vid varje kryptering) --> ciphertext
//   Fel lösenord eller manipulerad data => GCM-taggen validerar inte och
//   decrypt kastar. Vi får alltså aldrig korrupt klartext.
'use strict';

const KDF_ITERATIONS_DEFAULT = 600000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function toBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveKey(password, salt, iterations) {
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return globalThis.crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, // ej extraherbar — nyckelmaterialet kan inte läsas ut ur CryptoKey-objektet
    ['encrypt', 'decrypt']);
}

async function encryptWithKey(key, plaintext) {
  const nonce = randomBytes(NONCE_BYTES); // ny nonce VARJE gång
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(plaintext));
  return { nonce: toBase64(nonce), ciphertext: toBase64(new Uint8Array(ciphertext)) };
}

async function decryptWithKey(key, nonceB64, ciphertextB64) {
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(nonceB64) }, key, fromBase64(ciphertextB64));
  return new TextDecoder().decode(plaintext);
}

// Hela flödet lösenord -> komplett valvblock enligt filformatet.
// Används vid skapande och lösenordsbyte (nytt salt varje gång) samt i tester.
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

// Kastar vid fel lösenord eller manipulerad data.
// Iterationsantalet läses ur blocket så att äldre/framtida valv fungerar.
async function decryptVault(password, blob) {
  const key = await deriveKey(password, fromBase64(blob.salt), blob.iterations);
  return decryptWithKey(key, blob.nonce, blob.ciphertext);
}

export {
  KDF_ITERATIONS_DEFAULT, SALT_BYTES, NONCE_BYTES,
  randomBytes, toBase64, fromBase64,
  deriveKey, encryptWithKey, decryptWithKey, encryptVault, decryptVault,
};
