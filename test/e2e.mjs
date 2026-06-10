// test/e2e.mjs — end-to-end verification of the round-trip invariant in a
// real Chromium. Requires playwright-core (devDependency) plus a downloaded
// Playwright Chromium:
//
//   npm ci && npx playwright-core install chromium
//   node build.mjs && node test/e2e.mjs
//
// Flow: generation 1 = dist/valv.html (first run) -> create vault, add an
// entry, save -> generation 2. Open gen 2, unlock, verify, change, save ->
// generation 3. Open gen 3 and verify everything again. Then: export ->
// import into a fresh shell, upgrade-from-file into a fresh shell, and the
// i18n language round-trip.
//
// NOTE: in headless mode showSaveFilePicker rejects with AbortError (which
// the app correctly treats as "user cancelled"), so the test removes the
// API to exercise the download fallback instead.
import { homedir } from 'node:os';
import { copyFileSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

// In CI, REQUIRE_E2E=1 turns a missing browser into a failure instead of a skip.
const skip = (reason) => {
  if (process.env.REQUIRE_E2E) {
    console.error('e2e: REQUIRED but cannot run —', reason);
    process.exit(1);
  }
  console.log('e2e: skipped —', reason);
  process.exit(0);
};

let chromium;
try {
  ({ chromium } = await import('playwright-core'));
} catch {
  skip('playwright-core is not installed');
}

function findChromium() {
  if (process.env.CHROMIUM_PATH) return process.env.CHROMIUM_PATH;
  // Preferred: the browser revision registered for this playwright-core
  // version (what `npx playwright-core install chromium` provides).
  try {
    const exe = chromium.executablePath();
    readFileSync(exe, { length: 1 });
    return exe;
  } catch { /* fall through to a cache scan */ }
  const cache = path.join(homedir(), '.cache/ms-playwright');
  for (const dir of readdirSync(cache).filter((d) => /^chromium-\d+$/.test(d)).sort().reverse()) {
    for (const sub of ['chrome-linux64/chrome', 'chrome-linux/chrome']) {
      const exe = path.join(cache, dir, sub);
      try { readFileSync(exe, { length: 1 }); return exe; } catch { /* try the next one */ }
    }
  }
  return null;
}

const EXE = findChromium();
if (!EXE) {
  skip('no Playwright Chromium found (set CHROMIUM_PATH or run: npx playwright-core install chromium)');
}

const DIST = new URL('../dist/valv.html', import.meta.url).pathname;
// Deliberately non-ASCII: passwords must survive åäö and similar.
const PW = 'testlösenord-åäö-123!';
const tmp = mkdtempSync('/tmp/valv-rt-');

const browser = await chromium.launch({ executablePath: EXE });
const ctx = await browser.newContext({ acceptDownloads: true });
await ctx.addInitScript(() => { delete window.showSaveFilePicker; });

let failed = 0;
const check = (name, cond) => {
  console.log((cond ? '  ✔ ' : '  ✘ ') + name);
  if (!cond) failed++;
};

async function saveAndCapture(page, file) {
  const dl = page.waitForEvent('download');
  await page.click('#save-btn');
  await (await dl).saveAs(file);
}

// ---- Generation 1: first run, create vault, add an entry, save
const gen1 = path.join(tmp, 'gen1.html');
copyFileSync(DIST, gen1);
let page = await ctx.newPage();
await page.goto('file://' + gen1);
check('gen1: first-run mode is shown', await page.isVisible('#create-form'));
await page.fill('#create-password', PW);
await page.fill('#create-password2', PW);
await page.click('#create-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('gen1: main view appears after creation', true);
check('gen1: unsaved indicator is shown', await page.isVisible('#dirty-indicator'));

await page.click('#new-login-btn');
await page.fill('#entry-title', 'Bank <script>alert(1)</script>');
await page.fill('#entry-username', 'alice');
await page.fill('#entry-password', 'secret-1!');
await page.fill('#entry-url', 'https://bank.example');
await page.click('#entry-form button[type=submit]');
check('gen1: entry renders in the list (XSS-safe via textContent)',
  (await page.textContent('.entry-title')) === 'Bank <script>alert(1)</script>');

const gen2 = path.join(tmp, 'gen2.html');
await saveAndCapture(page, gen2);
check('gen1: saving produced a downloaded file', true);
await page.close();

// ---- Generation 2: open the SAVED file — the core invariant
page = await ctx.newPage();
await page.goto('file://' + gen2);
check('gen2: unlock mode is shown (not first run)', await page.isVisible('#unlock-form'));

await page.fill('#unlock-password', 'wrong-password');
await page.click('#unlock-btn');
await page.waitForSelector('#unlock-error', { state: 'visible' });
check('gen2: wrong password shows an error', true);

await page.fill('#unlock-password', PW);
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('gen2: the right password unlocks', true);
check('gen2: the entry survived the round-trip',
  (await page.textContent('.entry-title')) === 'Bank <script>alert(1)</script>');
check('gen2: no unsaved indicator after a clean unlock', !(await page.isVisible('#dirty-indicator')));

const gen2src = readFileSync(gen2, 'utf8');
check('gen2: no plaintext passwords in the file',
  !gen2src.includes('secret-1!') && !gen2src.includes('Bank <script>'));
check('gen2: no external references in the file', !/(?:src|href)\s*=\s*["']https?:/i.test(gen2src));

await page.click('#new-login-btn');
await page.fill('#entry-title', 'Email');
await page.fill('#entry-username', 'alice.smith');
await page.fill('#entry-password', 'other-password');
await page.click('#entry-form button[type=submit]');
check('gen2: unsaved indicator appears after a change', await page.isVisible('#dirty-indicator'));

await page.fill('#search', 'bank');
check('gen2: search filters the list', (await page.locator('#entry-list li').count()) === 1);
await page.fill('#search', '');

// ---- Seed entry: create by pasting a whole phrase
// NOTE: the phrase is deliberately NOT in alphabetical order — the BIP39
// list is inlined (alphabetically) in the app code, so an alphabetical
// phrase would be a substring of the file and the plaintext checks below
// would be meaningless.
const PHRASE = 'zoo wine vivid urge tape sugar response oxygen muscle legend item glove';
const SEED_WORDS = PHRASE.split(' ');
await page.click('#new-seed-btn');
await page.fill('#seed-title', 'Ledger');
await page.fill('#seed-wallet', 'Ledger Nano X');
await page.evaluate((phrase) => {
  const input = document.querySelector('#seed-grid input');
  const dt = new DataTransfer();
  dt.setData('text/plain', phrase);
  input.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
}, PHRASE.toUpperCase()); // uppercase: exercises trim + lowercase
const pasted = await page.evaluate(() =>
  Array.from(document.querySelectorAll('#seed-grid input')).map((i) => i.value));
check('gen2: pasted phrase splits into 12 lowercase words', pasted.join(' ') === PHRASE);
check('gen2: no BIP39 warnings for valid words', !(await page.isVisible('#seed-warning')));
await page.click('#seed-form button[type=submit]');
check('gen2: the seed entry has a badge in the list', (await page.textContent('.badge')).includes('SEED'));

// search matches the wallet — but never the words
await page.fill('#search', 'nano');
check('gen2: search matches the wallet of a seed entry', (await page.locator('#entry-list li').count()) === 1);
await page.fill('#search', 'zoo');
check('gen2: search NEVER matches the seed words', (await page.locator('#entry-list li').count()) === 0);
await page.fill('#search', '');

const gen3 = path.join(tmp, 'gen3.html');
await saveAndCapture(page, gen3);
await page.close();

// ---- Generation 3: second round-trip pass
const gen3src = readFileSync(gen3, 'utf8');
check('gen3: the seed phrase and wallet are not in the saved file in plaintext',
  !gen3src.includes(PHRASE) && !gen3src.includes('zoo wine') && !gen3src.includes('Ledger Nano X'));

page = await ctx.newPage();
await page.goto('file://' + gen3);
await page.fill('#unlock-password', PW);
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('gen3: all three entries exist after the second pass',
  (await page.locator('#entry-list li').count()) === 3);
const titles = await page.locator('.entry-title').allTextContents();
check('gen3: sorted alphabetically', titles[0] === 'Bank <script>alert(1)</script>'
  && titles[1] === 'Email' && titles[2] === 'Ledger');

// ---- Seed entry after round-trip: masked by default, Show gives the right order
await page.click('#entry-list li:has(.badge)');
await page.waitForSelector('#seed-dialog[open]');
const masked = await page.evaluate((words) => {
  const inputs = Array.from(document.querySelectorAll('#seed-grid input'));
  // the dialog's textContent contains no scripts — body's does (the BIP39 list)
  const dialogText = document.querySelector('#seed-dialog').textContent;
  return {
    count: inputs.length,
    allEmpty: inputs.every((i) => i.value === '' && i.placeholder === '•••••'),
    inDom: Array.from(document.querySelectorAll('input, textarea'))
        .some((i) => words.some((w) => i.value.includes(w)))
      || words.some((w) => dialogText.includes(w)),
  };
}, SEED_WORDS);
check('gen3: 12 numbered fields, masked by default (placeholders, empty values)',
  masked.count === 12 && masked.allEmpty);
check('gen3: the words are NOT in the DOM before Show', !masked.inDom);
check('gen3: the wallet field came along', (await page.inputValue('#seed-wallet')) === 'Ledger Nano X');

await page.click('#seed-toggle');
const shown = await page.evaluate(() =>
  Array.from(document.querySelectorAll('#seed-grid input')).map((i) => i.value));
check('gen3: Show reveals all 12 words in the right order', shown.join(' ') === PHRASE);
const nums = await page.locator('#seed-grid .word-num').allTextContents();
check('gen3: numbering runs 1–12 in order', nums.join(',') === '1,2,3,4,5,6,7,8,9,10,11,12');
await page.click('#seed-toggle');
const remasked = await page.evaluate(() =>
  Array.from(document.querySelectorAll('#seed-grid input')).every((i) => i.value === ''));
check('gen3: Hide empties the fields again', remasked);
await page.click('#seed-cancel');

// ---- Export (input for the import test): 3 entries at this point
await page.click('#settings-btn');
await page.waitForSelector('#settings-dialog[open]');
await page.click('#export-btn');
await page.waitForSelector('#confirm-dialog[open]');
check('gen3: the export warning mentions seed phrases',
  (await page.textContent('#confirm-message')).includes('SEED PHRASES'));
const exportDl = page.waitForEvent('download');
await page.click('#confirm-ok');
const exportFile = path.join(tmp, 'valv-export.json');
await (await exportDl).saveAs(exportFile);
const exported = JSON.parse(readFileSync(exportFile, 'utf8'));
check('gen3: the export holds 3 entries with intact seed words',
  exported.entries.length === 3
  && exported.entries.find((e) => e.type === 'seed').words.join(' ') === PHRASE);
await page.click('#settings-close');

// ---- Lock/unlock within the same session with an unsaved change
await page.click('#new-login-btn');
await page.fill('#entry-title', 'Wifi');
await page.fill('#entry-password', 'wifi-pw');
await page.click('#entry-form button[type=submit]');
await page.click('#lock-btn');
await page.waitForSelector('#unlock-form', { state: 'visible' });
check('gen3: locking shows the lock screen', true);
check('gen3: the list is cleared on lock', (await page.locator('#entry-list li').count()) === 0);
await page.fill('#unlock-password', PW);
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('gen3: the unsaved change survived lock/unlock (encrypted in the DOM)',
  (await page.locator('#entry-list li').count()) === 4);
check('gen3: the unsaved indicator persists across lock/unlock', await page.isVisible('#dirty-indicator'));

// ---- Generator
await page.click('#generator-btn');
const generated = await page.inputValue('#gen-output');
check('gen3: the generator produces 20 characters', generated.length === 20);
await page.click('#gen-regenerate');
const generated2 = await page.inputValue('#gen-output');
check('gen3: regenerating gives a new password', generated2 !== generated && generated2.length === 20);
await page.click('#gen-close');
await page.close();

// Helper: create a fresh empty app shell and unlock it with a new password
const PW2 = 'nytt-skal-lösenord-9!';
async function freshShell(file) {
  copyFileSync(DIST, file);
  const p = await ctx.newPage();
  await p.goto('file://' + file);
  await p.fill('#create-password', PW2);
  await p.fill('#create-password2', PW2);
  await p.click('#create-btn');
  await p.waitForSelector('#main-screen', { state: 'visible' });
  return p;
}

// ---- Solution A: import the JSON export into a fresh empty shell
page = await freshShell(path.join(tmp, 'shell-a.html'));
await page.click('#settings-btn');
const [chooserA] = await Promise.all([
  page.waitForEvent('filechooser'),
  page.click('#import-btn'),
]);
await chooserA.setFiles(exportFile);
await page.waitForSelector('#merge-dialog[open]');
check('import: the merge dialog shows the entry count',
  (await page.textContent('#merge-message')).includes('3 entries'));
await page.click('#merge-merge');
// the dialog's close event fires before renderList — wait for the list, not the dialog
await page.waitForFunction(() => document.querySelectorAll('#entry-list li').length === 3);
check('import: all 3 entries were brought in', true);
const importedTitles = await page.locator('.entry-title').allTextContents();
check('import: titles are identical',
  importedTitles.join('|') === 'Bank <script>alert(1)</script>|Email|Ledger');
await page.click('#entry-list li:has(.badge)');
await page.waitForSelector('#seed-dialog[open]');
await page.click('#seed-toggle');
const importedWords = await page.evaluate(() =>
  Array.from(document.querySelectorAll('#seed-grid input')).map((i) => i.value));
check('import: seed words identical and in order', importedWords.join(' ') === PHRASE);
check('import: wallet identical', (await page.inputValue('#seed-wallet')) === 'Ledger Nano X');
await page.click('#seed-cancel');
await page.click('#entry-list li:nth-child(2)'); // Email
await page.waitForSelector('#entry-dialog[open]');
check('import: login password identical', (await page.inputValue('#entry-password')) === 'other-password');
await page.click('#entry-cancel');
await page.close();

// ---- Solution B: upgrade from an old vault file into a fresh empty shell
page = await freshShell(path.join(tmp, 'shell-b.html'));
await page.click('#settings-btn');
const [chooserB] = await Promise.all([
  page.waitForEvent('filechooser'),
  page.click('#upgrade-btn'),
]);
await chooserB.setFiles(gen3); // old file, encrypted with PW (not PW2)
await page.waitForSelector('#upgrade-dialog[open]');
check('upgrade: the dialog shows the file name',
  (await page.textContent('#upgrade-filename')).includes('gen3.html'));

await page.fill('#upgrade-password', 'wrong-password');
await page.click('#upgrade-unlock');
await page.waitForSelector('#upgrade-error', { state: 'visible' });
check('upgrade: wrong password shows an error with another chance', true);

await page.fill('#upgrade-password', PW);
await page.click('#upgrade-unlock');
await page.waitForSelector('#merge-dialog[open]');
check('upgrade: the merge dialog shows the entry count',
  (await page.textContent('#merge-message')).includes('3 entries'));
await page.click('#merge-merge');
await page.waitForFunction(() => document.querySelectorAll('#entry-list li').length === 3);
check('upgrade: all 3 entries were brought in', true);

// round-trip: save the upgraded vault and open the saved file
const genB = path.join(tmp, 'gen-b.html');
await saveAndCapture(page, genB);
await page.close();

page = await ctx.newPage();
await page.goto('file://' + genB);
await page.fill('#unlock-password', PW2); // the NEW shell's password
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('upgrade: round-trip — the saved file opens with the new password and 3 entries',
  (await page.locator('#entry-list li').count()) === 3);
await page.click('#entry-list li:has(.badge)');
await page.waitForSelector('#seed-dialog[open]');
await page.click('#seed-toggle');
const upgradedWords = await page.evaluate(() =>
  Array.from(document.querySelectorAll('#seed-grid input')).map((i) => i.value));
check('upgrade: the seed words survived upgrade + round-trip', upgradedWords.join(' ') === PHRASE);
await page.click('#seed-cancel');
await page.close();

// ---- i18n: English by default, switch to Swedish, language survives round-trip
const i18nShell = path.join(tmp, 'shell-i18n.html');
copyFileSync(DIST, i18nShell);
page = await ctx.newPage();
await page.goto('file://' + i18nShell);
check('i18n: the lock screen defaults to English',
  (await page.textContent('#create-btn')) === 'Create vault'
  && (await page.textContent('.tagline')) === 'Encrypted password manager in a single file');
await page.fill('#create-password', PW2);
await page.fill('#create-password2', PW2);
await page.click('#create-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('i18n: the main view defaults to English',
  (await page.textContent('#settings-btn')) === 'Settings'
  && (await page.textContent('#new-login-btn')) === '+ Login');

await page.click('#new-login-btn');
await page.fill('#entry-title', 'Language test');
await page.fill('#entry-password', 'pw-i18n');
await page.click('#entry-form button[type=submit]');

await page.click('#settings-btn');
await page.selectOption('#language-select', 'sv');
check('i18n: switching to Swedish takes effect immediately',
  (await page.textContent('#settings-btn')) === 'Inställningar'
  && (await page.textContent('#save-btn')) === 'Spara'
  && (await page.textContent('#dirty-indicator')) === '● osparat');
await page.click('#settings-close');

const genI18n = path.join(tmp, 'gen-i18n.html');
await saveAndCapture(page, genI18n);
await page.close();

// The round-trip invariant: the saved file shows Swedish BEFORE unlock
page = await ctx.newPage();
await page.goto('file://' + genI18n);
check('i18n: the saved file shows Swedish on the lock screen before unlock',
  (await page.textContent('#unlock-btn')) === 'Lås upp'
  && (await page.textContent('label[for=unlock-password]')) === 'Master-lösenord');
check('i18n: html lang is set to sv', await page.evaluate(() => document.documentElement.lang) === 'sv');
await page.fill('#unlock-password', PW2);
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('i18n: the main view is Swedish after unlocking the saved file',
  (await page.textContent('#new-login-btn')) === '+ Inloggning');
check('i18n: the entry survived language switch + round-trip',
  (await page.textContent('.entry-title')) === 'Language test');
await page.close();

// ---- API keys: masked fields, expiry indicator, search exclusions, i18n
// Fixture values deliberately do not mimic real provider key formats
// (sk_test_/whsec_/AKIA…) — GitHub push protection rejects those patterns.
const KEY = 'valv-test-key-abc123xyz789';
const SECRET = 'valv-test-secret-456';
const inTenDays = new Date(Date.now() + 10 * 86400000).toISOString().slice(0, 10);
const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);

const apiShell = path.join(tmp, 'shell-api.html');
page = await freshShell(apiShell);
check('apikey: the new-entry button is in English by default',
  (await page.textContent('#new-apikey-btn')) === '+ API key');

// entry 1: secret + expiry within 30 days
await page.click('#new-apikey-btn');
await page.fill('#apikey-title', 'Stripe');
await page.fill('#apikey-service', 'Stripe Payments');
await page.fill('#apikey-key', KEY);
await page.fill('#apikey-secret', SECRET);
await page.fill('#apikey-environment', 'production');
await page.fill('#apikey-expires', inTenDays);
await page.click('#apikey-form button[type=submit]');

// entry 2: expired, no secret
await page.click('#new-apikey-btn');
await page.fill('#apikey-title', 'OldAPI');
await page.fill('#apikey-key', 'old_key_000');
await page.fill('#apikey-expires', yesterday);
await page.click('#apikey-form button[type=submit]');

check('apikey: both rows carry the API badge', (await page.locator('.badge.api').count()) === 2);
const stripeRow = page.locator('#entry-list li', { hasText: 'Stripe' });
const oldRow = page.locator('#entry-list li', { hasText: 'OldAPI' });
check('apikey: Key and Secret quick-copy buttons on the row with a secret',
  (await stripeRow.locator('button').allTextContents()).join(',') === 'Key,Secret');
check('apikey: no Secret button when the entry has no secret',
  (await oldRow.locator('button').allTextContents()).join(',') === 'Key');
check('apikey: subtle indicator for expiry within 30 days',
  /^Expires in (9|10) d$/.test(await stripeRow.locator('.expiry.warn').textContent()));
check('apikey: distinct indicator when expired',
  (await oldRow.locator('.expiry.expired').textContent()) === 'Expired');

// search: service matches, key/secret never do
await page.fill('#search', 'payments');
check('apikey: search matches the service', (await page.locator('#entry-list li').count()) === 1);
await page.fill('#search', 'abc123xyz');
check('apikey: search NEVER matches the key', (await page.locator('#entry-list li').count()) === 0);
await page.fill('#search', 'test-secret');
check('apikey: search NEVER matches the secret', (await page.locator('#entry-list li').count()) === 0);
await page.fill('#search', '');

// save -> reopen: masked by default, Show reveals, values never in file/DOM
const genApi = path.join(tmp, 'gen-api.html');
await saveAndCapture(page, genApi);
await page.close();

const genApiSrc = readFileSync(genApi, 'utf8');
check('apikey: key and secret are not in the saved file in plaintext',
  !genApiSrc.includes(KEY) && !genApiSrc.includes(SECRET));

page = await ctx.newPage();
await page.goto('file://' + genApi);
await page.fill('#unlock-password', PW2);
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
await page.locator('#entry-list li', { hasText: 'Stripe' }).click();
await page.waitForSelector('#apikey-dialog[open]');
const apiMasked = await page.evaluate(([key, secret]) => {
  const keyField = document.getElementById('apikey-key');
  const secretField = document.getElementById('apikey-secret');
  const dialogText = document.querySelector('#apikey-dialog').textContent;
  return {
    masked: keyField.value === '' && keyField.placeholder === '••••••••' && keyField.readOnly
      && secretField.value === '' && secretField.placeholder === '••••••••' && secretField.readOnly,
    inDom: Array.from(document.querySelectorAll('input, textarea'))
        .some((i) => i.value.includes(key) || i.value.includes(secret))
      || dialogText.includes(key) || dialogText.includes(secret),
  };
}, [KEY, SECRET]);
check('apikey: key and secret fields are masked by default after round-trip', apiMasked.masked);
check('apikey: the values are NOT in the DOM before Show', !apiMasked.inDom);
check('apikey: other fields came along',
  (await page.inputValue('#apikey-service')) === 'Stripe Payments'
  && (await page.inputValue('#apikey-environment')) === 'production');

await page.click('#apikey-toggle-key');
check('apikey: Show reveals the key', (await page.inputValue('#apikey-key')) === KEY);
await page.click('#apikey-toggle-secret');
check('apikey: Show reveals the secret', (await page.inputValue('#apikey-secret')) === SECRET);
await page.click('#apikey-toggle-key');
check('apikey: Hide empties the key field again', (await page.inputValue('#apikey-key')) === '');
await page.click('#apikey-cancel');

// i18n: the API key strings switch with the language
await page.click('#settings-btn');
await page.selectOption('#language-select', 'sv');
await page.click('#settings-close');
check('apikey: the new-entry button switches to Swedish',
  (await page.textContent('#new-apikey-btn')) === '+ API-nyckel');
check('apikey: the expiry indicator switches to Swedish',
  (await page.locator('#entry-list li', { hasText: 'OldAPI' }).locator('.expiry.expired').textContent()) === 'Utgången');

await page.close();
await browser.close();
console.log(failed ? `\n${failed} E2E CHECK(S) FAILED` : '\nAll E2E checks passed');
process.exit(failed ? 1 : 0);
