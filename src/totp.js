// totp.js — TOTP generator (RFC 6238) for Valv
//
// Pure WebCrypto, no third-party libraries: HMAC via crypto.subtle and a
// ~20-line base32 decoder of our own. Like the other modules this file is
// environment-neutral (browser + Node >= 19) so the RFC test vectors can run
// in the Node suite; build.mjs strips the export line for the browser.
'use strict';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decode a base32 string (RFC 4648). Case-insensitive; whitespace and `=`
 * padding are ignored, since authenticator secrets are often displayed in
 * spaced lowercase groups.
 * @param {string} str
 * @returns {Uint8Array}
 * @throws on characters outside the base32 alphabet
 */
function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s=]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const index = BASE32_ALPHABET.indexOf(ch);
    if (index === -1) throw new Error('invalid base32 character: ' + ch);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

const TOTP_HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
const TOTP_DEFAULTS = { period: 30, digits: 6, algorithm: 'SHA1' };

/**
 * Parse user TOTP input: either a plain base32 secret (spaces and case are
 * tolerated) or a full otpauth:// URI, from which secret, period, digits
 * and algorithm are extracted. Defaults follow RFC 6238 usage in the wild:
 * 30 s period, 6 digits, SHA-1.
 * @param {string} input
 * @returns {{secret: string, period: number, digits: number, algorithm: string} | null}
 *   null when the input is not a usable TOTP configuration
 */
function parseTotpInput(input) {
  const text = String(input).trim();
  if (!text) return null;
  let secret;
  let period = TOTP_DEFAULTS.period;
  let digits = TOTP_DEFAULTS.digits;
  let algorithm = TOTP_DEFAULTS.algorithm;
  if (/^otpauth:\/\//i.test(text)) {
    let url;
    try { url = new URL(text); } catch { return null; }
    const params = url.searchParams;
    secret = (params.get('secret') || '').replace(/\s+/g, '').toUpperCase();
    period = parseInt(params.get('period'), 10) || period;
    digits = parseInt(params.get('digits'), 10) || digits;
    algorithm = (params.get('algorithm') || algorithm).toUpperCase();
  } else {
    secret = text.replace(/\s+/g, '').toUpperCase();
  }
  if (!secret || !(algorithm in TOTP_HASHES)
      || period < 5 || period > 300 || digits < 4 || digits > 10) {
    return null;
  }
  try {
    if (base32Decode(secret).length === 0) return null;
  } catch {
    return null;
  }
  return { secret, period, digits, algorithm };
}

/**
 * Generate the TOTP code for a moment in time (RFC 6238).
 * @param {{secret: string, period?: number, digits?: number, algorithm?: string}} config
 * @param {number} nowMs Unix time in milliseconds (pass Date.now())
 * @returns {Promise<string>} zero-padded code
 */
async function generateTotp(config, nowMs) {
  const period = config.period || TOTP_DEFAULTS.period;
  const digits = config.digits || TOTP_DEFAULTS.digits;
  const hash = TOTP_HASHES[config.algorithm || TOTP_DEFAULTS.algorithm] || 'SHA-1';
  // 64-bit big-endian counter; JS numbers are exact far beyond any real time
  let counter = Math.floor(nowMs / 1000 / period);
  const message = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    message[i] = counter & 0xff;
    counter = Math.floor(counter / 256);
  }
  const key = await globalThis.crypto.subtle.importKey(
    'raw', base32Decode(config.secret), { name: 'HMAC', hash }, false, ['sign']);
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, message));
  // dynamic truncation (RFC 4226 §5.3)
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24)
    | (mac[offset + 1] << 16)
    | (mac[offset + 2] << 8)
    | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/**
 * Seconds left until the current TOTP code rolls over.
 * @param {number} period
 * @param {number} nowMs
 * @returns {number} 1..period
 */
function totpRemainingSeconds(period, nowMs) {
  return period - (Math.floor(nowMs / 1000) % period);
}

export { base32Decode, parseTotpInput, generateTotp, totpRemainingSeconds, TOTP_DEFAULTS };
