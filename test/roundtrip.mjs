// test/roundtrip.mjs — tests for the crypto module, the file format and i18n.
// Run: node test/roundtrip.mjs   (run node build.mjs first for the dist test)
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  KDF_ITERATIONS_DEFAULT, SALT_BYTES, NONCE_BYTES,
  randomBytes, toBase64, fromBase64,
  deriveKey, encryptWithKey, decryptWithKey, encryptVault, decryptVault,
} from '../src/crypto.js';
import {
  BIP39_WORDS, BIP39_SET, SEED_WORD_COUNTS,
  isValidSeedWordCount, parseSeedPhrase, unknownSeedWords, normalizeEntry,
} from '../src/seed.js';
import { STRINGS } from '../src/i18n.js';

// A low iteration count keeps the tests that are not about key derivation
// itself fast. One test runs the full default count (600 000).
const FAST_ITER = 1000;

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

test('base64 round-trip', () => {
  const bytes = randomBytes(64);
  assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
  assert.equal(toBase64(new Uint8Array(0)), '');
});

test('encrypt/decrypt round-trip at the full iteration count (600 000)', async () => {
  const plaintext = '{"entries":[{"title":"Bank","password":"secret åäö 🔐"}]}';
  const blob = await encryptVault('correct horse battery staple', plaintext);
  assert.equal(blob.version, 1);
  assert.equal(blob.kdf, 'PBKDF2-SHA256');
  assert.equal(blob.iterations, KDF_ITERATIONS_DEFAULT);
  assert.equal(fromBase64(blob.salt).length, SALT_BYTES);
  assert.equal(fromBase64(blob.nonce).length, NONCE_BYTES);
  assert.equal(await decryptVault('correct horse battery staple', blob), plaintext);
});

test('wrong password throws', async () => {
  const blob = await encryptVault('right password', 'data', FAST_ITER);
  await assert.rejects(decryptVault('wrong password', blob));
});

test('tampered ciphertext throws (the GCM tag validates)', async () => {
  const blob = await encryptVault('password', 'data', FAST_ITER);
  const bytes = fromBase64(blob.ciphertext);
  bytes[0] ^= 0xff;
  const tampered = { ...blob, ciphertext: toBase64(bytes) };
  await assert.rejects(decryptVault('password', tampered));
});

test('tampered nonce throws', async () => {
  const blob = await encryptVault('password', 'data', FAST_ITER);
  const bytes = fromBase64(blob.nonce);
  bytes[0] ^= 0xff;
  await assert.rejects(decryptVault('password', { ...blob, nonce: toBase64(bytes) }));
});

test('fresh nonce and fresh ciphertext on every encryption', async () => {
  const key = await deriveKey('password', randomBytes(SALT_BYTES), FAST_ITER);
  const a = await encryptWithKey(key, 'same plaintext');
  const b = await encryptWithKey(key, 'same plaintext');
  assert.notEqual(a.nonce, b.nonce);
  assert.notEqual(a.ciphertext, b.ciphertext);
  assert.equal(await decryptWithKey(key, a.nonce, a.ciphertext), 'same plaintext');
  assert.equal(await decryptWithKey(key, b.nonce, b.ciphertext), 'same plaintext');
});

test('the iterations field in the block drives the derivation', async () => {
  const blob = await encryptVault('password', 'data', 2500);
  assert.equal(blob.iterations, 2500);
  assert.equal(await decryptVault('password', blob), 'data');
  // wrong iteration count => wrong key => throws
  await assert.rejects(decryptVault('password', { ...blob, iterations: 2501 }));
});

test('round-trip with a seed entry', async () => {
  const seedEntry = {
    id: '11111111-1111-4111-8111-111111111111',
    type: 'seed',
    title: 'Ledger',
    wallet: 'Ledger Nano X',
    words: parseSeedPhrase('abandon ability able about above absent absorb abstract absurd abuse access accident'),
    passphrase: 'extra-25th-word',
    derivation: "m/44'/60'/0'/0/0",
    notes: 'main wallet',
    created: '2026-06-10T00:00:00Z',
    modified: '2026-06-10T00:00:00Z',
  };
  const loginEntry = {
    id: '22222222-2222-4222-8222-222222222222',
    type: 'login',
    title: 'Bank', username: 'alice', password: 'pw', url: '', notes: '',
    created: '2026-06-10T00:00:00Z', modified: '2026-06-10T00:00:00Z',
  };
  const payload = JSON.stringify({ entries: [seedEntry, loginEntry], meta: {} });
  const blob = await encryptVault('password', payload, FAST_ITER);
  const decrypted = JSON.parse(await decryptVault('password', blob));
  assert.deepEqual(decrypted.entries[0], seedEntry);
  assert.equal(decrypted.entries[0].words.length, 12);
  assert.deepEqual(decrypted.entries[1], loginEntry);
});

test('backward compatibility: vault from an old version (no type field)', async () => {
  // exactly the payload shape the app wrote before seed support existed
  const oldEntry = {
    id: '33333333-3333-4333-8333-333333333333',
    title: 'Old entry', username: 'user', password: 'secret', url: 'https://example.com',
    notes: 'note', created: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z',
  };
  const blob = await encryptVault('password', JSON.stringify({ entries: [oldEntry], meta: {} }), FAST_ITER);

  // open: normalization assigns type "login" without losing any field
  const opened = JSON.parse(await decryptVault('password', blob)).entries.map(normalizeEntry);
  assert.equal(opened[0].type, 'login');
  assert.deepEqual(opened[0], { ...oldEntry, type: 'login' });

  // re-save and open again — still no data loss
  const blob2 = await encryptVault('password', JSON.stringify({ entries: opened, meta: {} }), FAST_ITER);
  const reopened = JSON.parse(await decryptVault('password', blob2)).entries.map(normalizeEntry);
  assert.deepEqual(reopened, opened);
});

test('parseSeedPhrase: split on whitespace, trim + lowercase', () => {
  assert.deepEqual(
    parseSeedPhrase('  Abandon\tABILITY \n able  about '),
    ['abandon', 'ability', 'able', 'about']);
  assert.deepEqual(parseSeedPhrase(''), []);
  assert.deepEqual(parseSeedPhrase('   '), []);
});

test('BIP39 validation: word list and unknown words', () => {
  assert.equal(BIP39_WORDS.split(' ').length, 2048);
  assert.equal(BIP39_SET.size, 2048);
  assert.ok(BIP39_SET.has('abandon') && BIP39_SET.has('zoo'));
  assert.deepEqual(unknownSeedWords(['abandon', 'zoo']), []);
  assert.deepEqual(unknownSeedWords(['abandon', 'xyzzy', '', 'blåbär']), ['xyzzy', 'blåbär']);
  assert.deepEqual(SEED_WORD_COUNTS, [12, 15, 18, 21, 24]);
  for (const n of [12, 15, 18, 21, 24]) assert.ok(isValidSeedWordCount(n));
  for (const n of [0, 11, 13, 23, 25]) assert.ok(!isValidSeedWordCount(n));
});

test('i18n: en and sv define exactly the same keys with the same types', () => {
  const langs = Object.keys(STRINGS);
  assert.deepEqual(langs.sort(), ['en', 'sv']);
  const enKeys = Object.keys(STRINGS.en).sort();
  const svKeys = Object.keys(STRINGS.sv).sort();
  assert.deepEqual(svKeys, enKeys);
  for (const key of enKeys) {
    assert.equal(typeof STRINGS.sv[key], typeof STRINGS.en[key], `type of ${key}`);
    if (typeof STRINGS.en[key] === 'string') {
      assert.ok(STRINGS.en[key].length > 0, `en.${key} is empty`);
      assert.ok(STRINGS.sv[key].length > 0, `sv.${key} is empty`);
    }
  }
});

test('round-trip in dist/valv.html (save simulation)', async () => {
  let html;
  try {
    html = await readFile(new URL('../dist/valv.html', import.meta.url), 'utf8');
  } catch {
    console.log('    (skipped — run "node build.mjs" first)');
    return;
  }
  // The same regex the app's save mechanism uses.
  const VAULT_BLOCK_RE =
    /(<script id="vault-data" type="application\/json">)([\s\S]*?)(<\/script>)/;
  assert.ok(VAULT_BLOCK_RE.test(html), 'the vault-data block exists in the build');

  const payload = JSON.stringify({ entries: [], meta: { modified: '2026-01-01T00:00:00Z' } });
  const blob = await encryptVault('password', payload, FAST_ITER);
  const vaultJson = JSON.stringify(blob);
  const saved = html.replace(VAULT_BLOCK_RE, (_m, open, _old, close) => open + vaultJson + close);

  // The block is replaced; the rest of the file is byte-identical.
  assert.equal(saved.match(VAULT_BLOCK_RE)[2], vaultJson);
  assert.equal(saved.replace(VAULT_BLOCK_RE, '$1$3'), html.replace(VAULT_BLOCK_RE, '$1$3'));

  // ...and the data in the "saved" file can be unlocked.
  const parsed = JSON.parse(saved.match(VAULT_BLOCK_RE)[2]);
  assert.equal(await decryptVault('password', parsed), payload);
});

let failed = 0;
for (const [name, fn] of tests) {
  try {
    await fn();
    console.log('  ✔', name);
  } catch (err) {
    failed++;
    console.error('  ✘', name);
    console.error('   ', err.message.split('\n')[0]);
  }
}
console.log(failed ? `\n${failed} test(s) failed` : `\nAll ${tests.length} tests passed`);
process.exit(failed ? 1 : 0);
