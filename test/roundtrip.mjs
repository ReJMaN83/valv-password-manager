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
  TRASH_RETENTION_DAYS, purgeExpiredTrash, splitRecoveryCodes,
} from '../src/seed.js';
import { STRINGS } from '../src/i18n.js';
import { base32Decode, parseTotpInput, generateTotp, totpRemainingSeconds } from '../src/totp.js';

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

test('round-trip with an API key entry', async () => {
  const apikeyEntry = {
    id: '44444444-4444-4444-8444-444444444444',
    type: 'apikey',
    title: 'Stripe',
    service: 'Stripe Payments',
    // Deliberately NOT shaped like a real provider key (no sk_test_/AKIA…
    // prefix): GitHub push protection pattern-matches those even in fixtures.
    key: 'valv-example-key-4eC39HqLyjWDarjt',
    secret: 'valv-example-webhook-secret-123',
    environment: 'test',
    scopes: 'read:charges write:charges',
    expires: '2027-01-01',
    url: 'https://dashboard.stripe.com',
    notes: 'CI account',
    created: '2026-06-10T00:00:00Z',
    modified: '2026-06-10T00:00:00Z',
  };
  const payload = JSON.stringify({ entries: [apikeyEntry], meta: {} });
  const blob = await encryptVault('password', payload, FAST_ITER);
  const decrypted = JSON.parse(await decryptVault('password', blob));
  assert.deepEqual(decrypted.entries[0], apikeyEntry);
  // normalizeEntry must leave explicitly typed entries untouched
  // (apart from defaulting the v1.2 deleted flag)
  assert.deepEqual(decrypted.entries.map(normalizeEntry)[0], { ...apikeyEntry, deleted: false });
});

test('mixed vault with all three entry types survives open/save/reopen', async () => {
  const entries = [
    { id: 'a0000000-0000-4000-8000-000000000001', title: 'Old login (no type)',
      username: 'alice', password: 'pw1', url: '', notes: '',
      created: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z' },
    { id: 'a0000000-0000-4000-8000-000000000002', type: 'seed', title: 'Wallet',
      wallet: 'Ledger', words: parseSeedPhrase('legal winner thank year wave sausage worth useful legal winner thank yellow'),
      passphrase: '', derivation: '', notes: '',
      created: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z' },
    { id: 'a0000000-0000-4000-8000-000000000003', type: 'apikey', title: 'AWS',
      service: 'AWS', key: 'EXAMPLE-ACCESS-KEY-ID-1234', secret: 'example/secret/access/key',
      environment: 'production', scopes: '', expires: '', url: '', notes: '',
      created: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z' },
  ];
  const blob = await encryptVault('password', JSON.stringify({ entries, meta: {} }), FAST_ITER);
  const opened = JSON.parse(await decryptVault('password', blob)).entries.map(normalizeEntry);
  assert.equal(opened[0].type, 'login');   // untyped entry normalized
  assert.equal(opened[1].type, 'seed');    // explicit types untouched
  assert.equal(opened[2].type, 'apikey');
  assert.deepEqual(opened[1], { ...entries[1], deleted: false });
  assert.deepEqual(opened[2], { ...entries[2], deleted: false });

  // re-save and reopen — no changes, no data loss
  const blob2 = await encryptVault('password', JSON.stringify({ entries: opened, meta: {} }), FAST_ITER);
  const reopened = JSON.parse(await decryptVault('password', blob2)).entries.map(normalizeEntry);
  assert.deepEqual(reopened, opened);
});

test('backward compatibility: vault from an old version (no type field)', async () => {
  // exactly the payload shape the app wrote before seed support existed
  const oldEntry = {
    id: '33333333-3333-4333-8333-333333333333',
    title: 'Old entry', username: 'user', password: 'secret', url: 'https://example.com',
    notes: 'note', created: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z',
  };
  const blob = await encryptVault('password', JSON.stringify({ entries: [oldEntry], meta: {} }), FAST_ITER);

  // open: normalization assigns type "login" and deleted=false without
  // losing any field
  const opened = JSON.parse(await decryptVault('password', blob)).entries.map(normalizeEntry);
  assert.equal(opened[0].type, 'login');
  assert.deepEqual(opened[0], { ...oldEntry, type: 'login', deleted: false });

  // re-save and open again — still no data loss
  const blob2 = await encryptVault('password', JSON.stringify({ entries: opened, meta: {} }), FAST_ITER);
  const reopened = JSON.parse(await decryptVault('password', blob2)).entries.map(normalizeEntry);
  assert.deepEqual(reopened, opened);
});

test('mixed vault with all FIVE entry types survives open/save/reopen', async () => {
  const stamp = { created: '2026-06-10T00:00:00Z', modified: '2026-06-10T00:00:00Z' };
  const entries = [
    { id: 'b0000000-0000-4000-8000-000000000001', type: 'login', title: 'Mail',
      username: 'alice', password: 'pw', url: '', notes: '',
      totpSecret: 'JBSWY3DPEHPK3PXP', totpPeriod: 30, totpDigits: 6, totpAlgorithm: 'SHA1', ...stamp },
    { id: 'b0000000-0000-4000-8000-000000000002', type: 'seed', title: 'Wallet',
      wallet: 'Trezor', words: parseSeedPhrase('legal winner thank year wave sausage worth useful legal winner thank yellow'),
      passphrase: '', derivation: '', notes: '', ...stamp },
    { id: 'b0000000-0000-4000-8000-000000000003', type: 'apikey', title: 'CI',
      service: 'Example CI', key: 'valv-example-key-123', secret: '',
      environment: 'test', scopes: '', expires: '', url: '', notes: '', ...stamp },
    { id: 'b0000000-0000-4000-8000-000000000004', type: 'note', title: 'Server notes',
      body: 'first line\nsecond line åäö', ...stamp },
    { id: 'b0000000-0000-4000-8000-000000000005', type: 'recovery', title: 'GitHub 2FA',
      service: 'GitHub', codes: [{ code: 'aaaa-1111', used: true }, { code: 'bbbb-2222', used: false }],
      notes: '', deleted: true, deletedAt: '2026-06-09T00:00:00Z', ...stamp },
  ];
  const blob = await encryptVault('password', JSON.stringify({ entries, meta: {} }), FAST_ITER);
  const opened = JSON.parse(await decryptVault('password', blob)).entries.map(normalizeEntry);
  assert.deepEqual(opened.map((e) => e.type), ['login', 'seed', 'apikey', 'note', 'recovery']);
  assert.deepEqual(opened[3], { ...entries[3], deleted: false });
  assert.deepEqual(opened[4], entries[4]); // explicit deleted flag untouched

  const blob2 = await encryptVault('password', JSON.stringify({ entries: opened, meta: {} }), FAST_ITER);
  const reopened = JSON.parse(await decryptVault('password', blob2)).entries.map(normalizeEntry);
  assert.deepEqual(reopened, opened);
});

test('normalizeEntry on v1.1-era data: deleted defaults to false', () => {
  const v11Entry = { id: 'x', type: 'apikey', title: 'A', key: 'k' };
  assert.equal(normalizeEntry(v11Entry).deleted, false);
  assert.equal(normalizeEntry({ id: 'y', title: 'old login' }).type, 'login');
  assert.equal(normalizeEntry({ id: 'y', title: 'old login' }).deleted, false);
  // an explicit flag — true or false — is never overwritten
  assert.equal(normalizeEntry({ id: 'z', type: 'note', title: 'N', deleted: true }).deleted, true);
});

test('trash: entries deleted more than 30 days ago are purged (mocked clock)', () => {
  const now = new Date('2026-06-10T12:00:00Z').getTime();
  const day = 86400000;
  const entries = [
    { id: '1', title: 'kept, not deleted', deleted: false },
    { id: '2', title: 'kept, deleted 29 days ago', deleted: true,
      deletedAt: new Date(now - 29 * day).toISOString() },
    { id: '3', title: 'purged, deleted 31 days ago', deleted: true,
      deletedAt: new Date(now - 31 * day).toISOString() },
    { id: '4', title: 'kept, deleted with unknown age', deleted: true },
    { id: '5', title: 'kept, exactly at the limit', deleted: true,
      deletedAt: new Date(now - TRASH_RETENTION_DAYS * day).toISOString() },
  ];
  const purged = purgeExpiredTrash(entries, now);
  assert.deepEqual(purged.map((e) => e.id), ['1', '2', '4', '5']);
});

test('splitRecoveryCodes: lines and whitespace', () => {
  assert.deepEqual(
    splitRecoveryCodes('  aaaa-1111\nbbbb-2222 cccc-3333\n\n dddd-4444\t'),
    ['aaaa-1111', 'bbbb-2222', 'cccc-3333', 'dddd-4444']);
  assert.deepEqual(splitRecoveryCodes(''), []);
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

test('base32 decoder: RFC 4648, whitespace, case, padding, invalid input', () => {
  // "12345678901234567890" (the RFC 6238 test secret) in base32
  const expected = new Uint8Array([...'12345678901234567890'].map((c) => c.charCodeAt(0)));
  assert.deepEqual(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), expected);
  // spaced lowercase groups, as authenticator apps display them
  assert.deepEqual(base32Decode('gezd gnbv gy3t qojq gezd gnbv gy3t qojq'), expected);
  // padding is ignored
  assert.deepEqual(base32Decode('MZXW6==='), new Uint8Array([0x66, 0x6f, 0x6f]));
  assert.throws(() => base32Decode('ABC1DEF')); // '1' is not in the alphabet
});

test('TOTP matches the RFC 6238 Appendix B vectors (SHA-1)', async () => {
  // Appendix B uses the 20-byte ASCII secret "12345678901234567890" and
  // 8-digit codes; the 6-digit code is the same value mod 10^6.
  const config = { secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', period: 30, digits: 8, algorithm: 'SHA1' };
  const vectors = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];
  for (const [seconds, expected] of vectors) {
    assert.equal(await generateTotp(config, seconds * 1000), expected, `T=${seconds}`);
    // adjusted to 6 digits: the same dynamic-truncation value mod 10^6
    assert.equal(
      await generateTotp({ ...config, digits: 6 }, seconds * 1000),
      String(Number(expected) % 10 ** 6).padStart(6, '0'),
      `T=${seconds} (6 digits)`);
  }
});

test('totpRemainingSeconds counts down to the period boundary', () => {
  assert.equal(totpRemainingSeconds(30, 0), 30);
  assert.equal(totpRemainingSeconds(30, 29_000), 1);
  assert.equal(totpRemainingSeconds(30, 30_000), 30);
  assert.equal(totpRemainingSeconds(30, 59_999), 1);
});

test('parseTotpInput: plain base32 and otpauth:// URIs', () => {
  // plain base32 with spaces and lowercase, defaults applied
  assert.deepEqual(parseTotpInput(' gezd gnbv gy3t qojq gezd gnbv gy3t qojq '),
    { secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', period: 30, digits: 6, algorithm: 'SHA1' });
  // full otpauth URI with overrides
  assert.deepEqual(parseTotpInput(
    'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=60&digits=8&algorithm=SHA256'),
    { secret: 'JBSWY3DPEHPK3PXP', period: 60, digits: 8, algorithm: 'SHA256' });
  // URI defaults
  assert.deepEqual(parseTotpInput('otpauth://totp/X?secret=JBSWY3DPEHPK3PXP'),
    { secret: 'JBSWY3DPEHPK3PXP', period: 30, digits: 6, algorithm: 'SHA1' });
  // invalid inputs
  assert.equal(parseTotpInput(''), null);
  assert.equal(parseTotpInput('not base32 at all!1'), null);
  assert.equal(parseTotpInput('otpauth://totp/X'), null); // no secret
  assert.equal(parseTotpInput('otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=MD5'), null);
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
