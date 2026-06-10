// test/roundtrip.mjs — tester för kryptomodulen och spara-simulering.
// Kör: node test/roundtrip.mjs   (kör node build.mjs först för dist-testet)
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

// Lågt iterationsantal i de tester som inte handlar om deriveringen i sig,
// så att sviten är snabb. Ett test kör fullt antal (600 000).
const FAST_ITER = 1000;

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

test('base64 round-trip', () => {
  const bytes = randomBytes(64);
  assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
  assert.equal(toBase64(new Uint8Array(0)), '');
});

test('encrypt/decrypt round-trip med fullt iterationsantal (600 000)', async () => {
  const plaintext = '{"entries":[{"title":"Bank","password":"hemligt åäö 🔐"}]}';
  const blob = await encryptVault('korrekt häst batteri häftstift', plaintext);
  assert.equal(blob.version, 1);
  assert.equal(blob.kdf, 'PBKDF2-SHA256');
  assert.equal(blob.iterations, KDF_ITERATIONS_DEFAULT);
  assert.equal(fromBase64(blob.salt).length, SALT_BYTES);
  assert.equal(fromBase64(blob.nonce).length, NONCE_BYTES);
  assert.equal(await decryptVault('korrekt häst batteri häftstift', blob), plaintext);
});

test('fel lösenord kastar', async () => {
  const blob = await encryptVault('rätt lösenord', 'data', FAST_ITER);
  await assert.rejects(decryptVault('fel lösenord', blob));
});

test('manipulerad ciphertext kastar (GCM-taggen validerar)', async () => {
  const blob = await encryptVault('lösenord', 'data', FAST_ITER);
  const bytes = fromBase64(blob.ciphertext);
  bytes[0] ^= 0xff;
  const tampered = { ...blob, ciphertext: toBase64(bytes) };
  await assert.rejects(decryptVault('lösenord', tampered));
});

test('manipulerad nonce kastar', async () => {
  const blob = await encryptVault('lösenord', 'data', FAST_ITER);
  const bytes = fromBase64(blob.nonce);
  bytes[0] ^= 0xff;
  await assert.rejects(decryptVault('lösenord', { ...blob, nonce: toBase64(bytes) }));
});

test('ny nonce och ny ciphertext vid varje kryptering', async () => {
  const key = await deriveKey('lösenord', randomBytes(SALT_BYTES), FAST_ITER);
  const a = await encryptWithKey(key, 'samma klartext');
  const b = await encryptWithKey(key, 'samma klartext');
  assert.notEqual(a.nonce, b.nonce);
  assert.notEqual(a.ciphertext, b.ciphertext);
  assert.equal(await decryptWithKey(key, a.nonce, a.ciphertext), 'samma klartext');
  assert.equal(await decryptWithKey(key, b.nonce, b.ciphertext), 'samma klartext');
});

test('iterations-fältet i blocket styr deriveringen', async () => {
  const blob = await encryptVault('lösenord', 'data', 2500);
  assert.equal(blob.iterations, 2500);
  assert.equal(await decryptVault('lösenord', blob), 'data');
  // fel iterationsantal => fel nyckel => kastar
  await assert.rejects(decryptVault('lösenord', { ...blob, iterations: 2501 }));
});

test('round-trip med seed-post', async () => {
  const seedEntry = {
    id: '11111111-1111-4111-8111-111111111111',
    type: 'seed',
    title: 'Ledger',
    wallet: 'Ledger Nano X',
    words: parseSeedPhrase('abandon ability able about above absent absorb abstract absurd abuse access accident'),
    passphrase: 'extra-ord-25',
    derivation: "m/44'/60'/0'/0/0",
    notes: 'huvudplånboken',
    created: '2026-06-10T00:00:00Z',
    modified: '2026-06-10T00:00:00Z',
  };
  const loginEntry = {
    id: '22222222-2222-4222-8222-222222222222',
    type: 'login',
    title: 'Banken', username: 'daniel', password: 'pw', url: '', notes: '',
    created: '2026-06-10T00:00:00Z', modified: '2026-06-10T00:00:00Z',
  };
  const payload = JSON.stringify({ entries: [seedEntry, loginEntry], meta: {} });
  const blob = await encryptVault('lösenord', payload, FAST_ITER);
  const decrypted = JSON.parse(await decryptVault('lösenord', blob));
  assert.deepEqual(decrypted.entries[0], seedEntry);
  assert.equal(decrypted.entries[0].words.length, 12);
  assert.deepEqual(decrypted.entries[1], loginEntry);
});

test('bakåtkompatibilitet: valv från gammal version (utan type-fält)', async () => {
  // exakt det payload-format som appen skrev innan seed-stödet fanns
  const oldEntry = {
    id: '33333333-3333-4333-8333-333333333333',
    title: 'Gammal post', username: 'anv', password: 'hemligt', url: 'https://ex.se',
    notes: 'anteckning', created: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z',
  };
  const blob = await encryptVault('lösenord', JSON.stringify({ entries: [oldEntry], meta: {} }), FAST_ITER);

  // öppna: normalisering ger type "login" utan att något fält tappas
  const opened = JSON.parse(await decryptVault('lösenord', blob)).entries.map(normalizeEntry);
  assert.equal(opened[0].type, 'login');
  assert.deepEqual(opened[0], { ...oldEntry, type: 'login' });

  // spara om och öppna igen — fortfarande ingen dataförlust
  const blob2 = await encryptVault('lösenord', JSON.stringify({ entries: opened, meta: {} }), FAST_ITER);
  const reopened = JSON.parse(await decryptVault('lösenord', blob2)).entries.map(normalizeEntry);
  assert.deepEqual(reopened, opened);
});

test('parseSeedPhrase: splitta på whitespace, trim + lowercase', () => {
  assert.deepEqual(
    parseSeedPhrase('  Abandon\tABILITY \n able  about '),
    ['abandon', 'ability', 'able', 'about']);
  assert.deepEqual(parseSeedPhrase(''), []);
  assert.deepEqual(parseSeedPhrase('   '), []);
});

test('BIP39-validering: ordlista och okända ord', () => {
  assert.equal(BIP39_WORDS.split(' ').length, 2048);
  assert.equal(BIP39_SET.size, 2048);
  assert.ok(BIP39_SET.has('abandon') && BIP39_SET.has('zoo'));
  assert.deepEqual(unknownSeedWords(['abandon', 'zoo']), []);
  assert.deepEqual(unknownSeedWords(['abandon', 'xyzzy', '', 'blåbär']), ['xyzzy', 'blåbär']);
  assert.deepEqual(SEED_WORD_COUNTS, [12, 15, 18, 21, 24]);
  for (const n of [12, 15, 18, 21, 24]) assert.ok(isValidSeedWordCount(n));
  for (const n of [0, 11, 13, 23, 25]) assert.ok(!isValidSeedWordCount(n));
});

test('round-trip i dist/valv.html (spara-simulering)', async () => {
  let html;
  try {
    html = await readFile(new URL('../dist/valv.html', import.meta.url), 'utf8');
  } catch {
    console.log('    (hoppas över — kör "node build.mjs" först)');
    return;
  }
  // Samma regex som appens spara-mekanism använder.
  const VAULT_BLOCK_RE =
    /(<script id="vault-data" type="application\/json">)([\s\S]*?)(<\/script>)/;
  assert.ok(VAULT_BLOCK_RE.test(html), 'vault-data-blocket finns i bygget');

  const payload = JSON.stringify({ entries: [], meta: { modified: '2026-01-01T00:00:00Z' } });
  const blob = await encryptVault('lösenord', payload, FAST_ITER);
  const vaultJson = JSON.stringify(blob);
  const saved = html.replace(VAULT_BLOCK_RE, (_m, open, _old, close) => open + vaultJson + close);

  // Blocket är utbytt, resten av filen är byte-identisk.
  assert.equal(saved.match(VAULT_BLOCK_RE)[2], vaultJson);
  assert.equal(saved.replace(VAULT_BLOCK_RE, '$1$3'), html.replace(VAULT_BLOCK_RE, '$1$3'));

  // ...och datan i den "sparade" filen går att låsa upp.
  const parsed = JSON.parse(saved.match(VAULT_BLOCK_RE)[2]);
  assert.equal(await decryptVault('lösenord', parsed), payload);
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
console.log(failed ? `\n${failed} test misslyckades` : `\nAlla ${tests.length} test gick igenom`);
process.exit(failed ? 1 : 0);
