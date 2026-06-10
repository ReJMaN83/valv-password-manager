// test/e2e.mjs — frivillig E2E-verifiering av round-trip-invarianten
// i riktig Chromium. Kräver playwright-core (ingår INTE i repots
// beroenden) samt en nedladdad Playwright-Chromium:
//
//   npm i --no-save playwright-core   (eller kör från en miljö som har den)
//   node build.mjs && node test/e2e.mjs
//
// Flöde: generation 1 = dist/valv.html (first-run) -> skapa valv, lägg
// till post, spara -> generation 2. Öppna gen 2, lås upp, verifiera,
// ändra, spara -> generation 3. Öppna gen 3 och verifiera allt igen.
//
// OBS: i headless avvisar showSaveFilePicker med AbortError (= "avbrutet"),
// därför tas API:t bort i testet så att nedladdnings-fallbacken används.
import { homedir } from 'node:os';
import { copyFileSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

let chromium;
try {
  ({ chromium } = await import('playwright-core'));
} catch {
  console.log('e2e: hoppas över — playwright-core är inte installerat.');
  process.exit(0);
}

function findChromium() {
  if (process.env.CHROMIUM_PATH) return process.env.CHROMIUM_PATH;
  const cache = path.join(homedir(), '.cache/ms-playwright');
  for (const dir of readdirSync(cache).filter((d) => /^chromium-\d+$/.test(d)).sort().reverse()) {
    for (const sub of ['chrome-linux64/chrome', 'chrome-linux/chrome']) {
      const exe = path.join(cache, dir, sub);
      try { readFileSync(exe, { length: 1 }); return exe; } catch { /* prova nästa */ }
    }
  }
  return null;
}

const EXE = findChromium();
if (!EXE) {
  console.log('e2e: hoppas över — ingen Playwright-Chromium hittades (sätt CHROMIUM_PATH).');
  process.exit(0);
}

const DIST = new URL('../dist/valv.html', import.meta.url).pathname;
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

// ---- Generation 1: first-run, skapa valv, lägg till post, spara
const gen1 = path.join(tmp, 'gen1.html');
copyFileSync(DIST, gen1);
let page = await ctx.newPage();
await page.goto('file://' + gen1);
check('gen1: first-run-läget visas', await page.isVisible('#create-form'));
await page.fill('#create-password', PW);
await page.fill('#create-password2', PW);
await page.click('#create-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('gen1: huvudvyn visas efter skapande', true);
check('gen1: osparat-indikatorn visas', await page.isVisible('#dirty-indicator'));

await page.click('#new-login-btn');
await page.fill('#entry-title', 'Banken <script>alert(1)</script>');
await page.fill('#entry-username', 'daniel');
await page.fill('#entry-password', 'hemligt!');
await page.fill('#entry-url', 'https://banken.se');
await page.click('#entry-form button[type=submit]');
check('gen1: posten visas i listan (XSS-säkert via textContent)',
  (await page.textContent('.entry-title')) === 'Banken <script>alert(1)</script>');

const gen2 = path.join(tmp, 'gen2.html');
await saveAndCapture(page, gen2);
check('gen1: spara gav en nedladdad fil', true);
await page.close();

// ---- Generation 2: öppna den SPARADE filen — viktigaste invarianten
page = await ctx.newPage();
await page.goto('file://' + gen2);
check('gen2: upplåsningsläget visas (inte first-run)', await page.isVisible('#unlock-form'));

await page.fill('#unlock-password', 'fel-lösenord');
await page.click('#unlock-btn');
await page.waitForSelector('#unlock-error', { state: 'visible' });
check('gen2: fel lösenord ger felmeddelande', true);

await page.fill('#unlock-password', PW);
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('gen2: rätt lösenord låser upp', true);
check('gen2: posten överlevde round-trip',
  (await page.textContent('.entry-title')) === 'Banken <script>alert(1)</script>');
check('gen2: ingen osparat-indikator efter ren upplåsning', !(await page.isVisible('#dirty-indicator')));

const gen2src = readFileSync(gen2, 'utf8');
check('gen2: inga klartextlösenord i filen', !gen2src.includes('hemligt!') && !gen2src.includes('Banken <script>'));
check('gen2: ingen extern referens i filen', !/(?:src|href)\s*=\s*["']https?:/i.test(gen2src));

await page.click('#new-login-btn');
await page.fill('#entry-title', 'E-post');
await page.fill('#entry-username', 'daniel.sahlin');
await page.fill('#entry-password', 'annat-lösenord');
await page.click('#entry-form button[type=submit]');
check('gen2: osparat-indikatorn visas efter ändring', await page.isVisible('#dirty-indicator'));

await page.fill('#search', 'banken');
check('gen2: sökningen filtrerar', (await page.locator('#entry-list li').count()) === 1);
await page.fill('#search', '');

// ---- Seed-post: skapa via inklistring av hel fras
// OBS: frasen är medvetet INTE i alfabetisk ordning — BIP39-listan ligger
// inlinad (alfabetiskt) i appkoden, så en alfabetisk fras vore en substring
// av filen och klartextkontrollerna nedan skulle bli meningslösa.
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
}, PHRASE.toUpperCase()); // versaler: testar trim + lowercase
const pasted = await page.evaluate(() =>
  Array.from(document.querySelectorAll('#seed-grid input')).map((i) => i.value));
check('gen2: inklistrad fras splittas till 12 gemena ord', pasted.join(' ') === PHRASE);
check('gen2: inga BIP39-varningar för giltiga ord', !(await page.isVisible('#seed-warning')));
await page.click('#seed-form button[type=submit]');
check('gen2: seed-posten har badge i listan', (await page.textContent('.badge')).includes('SEED'));

// sök träffar wallet — men aldrig orden
await page.fill('#search', 'nano');
check('gen2: sök träffar wallet för seed-post', (await page.locator('#entry-list li').count()) === 1);
await page.fill('#search', 'zoo');
check('gen2: sök träffar ALDRIG seed-orden', (await page.locator('#entry-list li').count()) === 0);
await page.fill('#search', '');

const gen3 = path.join(tmp, 'gen3.html');
await saveAndCapture(page, gen3);
await page.close();

// ---- Generation 3: andra round-trip-varvet
const gen3src = readFileSync(gen3, 'utf8');
check('gen3: seed-frasen och wallet finns inte i klartext i den sparade filen',
  !gen3src.includes(PHRASE) && !gen3src.includes('zoo wine') && !gen3src.includes('Ledger Nano X'));

page = await ctx.newPage();
await page.goto('file://' + gen3);
await page.fill('#unlock-password', PW);
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('gen3: alla tre posterna finns efter andra varvet',
  (await page.locator('#entry-list li').count()) === 3);
const titles = await page.locator('.entry-title').allTextContents();
check('gen3: sorterad A–Ö', titles[0] === 'Banken <script>alert(1)</script>'
  && titles[1] === 'E-post' && titles[2] === 'Ledger');

// ---- Seed-post efter round-trip: dold som default, Visa ger rätt ordning
await page.click('#entry-list li:has(.badge)');
await page.waitForSelector('#seed-dialog[open]');
const masked = await page.evaluate((words) => {
  const inputs = Array.from(document.querySelectorAll('#seed-grid input'));
  // dialogens textContent innehåller inga script — body:s gör det (BIP39-listan)
  const dialogText = document.querySelector('#seed-dialog').textContent;
  return {
    count: inputs.length,
    allEmpty: inputs.every((i) => i.value === '' && i.placeholder === '•••••'),
    inDom: Array.from(document.querySelectorAll('input, textarea'))
        .some((i) => words.some((w) => i.value.includes(w)))
      || words.some((w) => dialogText.includes(w)),
  };
}, SEED_WORDS);
check('gen3: 12 numrerade fält, dolda som default (placeholder, tomma värden)',
  masked.count === 12 && masked.allEmpty);
check('gen3: orden finns INTE i DOM:en före Visa', !masked.inDom);
check('gen3: wallet-fältet följde med', (await page.inputValue('#seed-wallet')) === 'Ledger Nano X');

await page.click('#seed-toggle');
const shown = await page.evaluate(() =>
  Array.from(document.querySelectorAll('#seed-grid input')).map((i) => i.value));
check('gen3: Visa ger alla 12 ord i rätt ordning', shown.join(' ') === PHRASE);
const nums = await page.locator('#seed-grid .word-num').allTextContents();
check('gen3: numreringen är 1–12 i ordning', nums.join(',') === '1,2,3,4,5,6,7,8,9,10,11,12');
await page.click('#seed-toggle');
const remasked = await page.evaluate(() =>
  Array.from(document.querySelectorAll('#seed-grid input')).every((i) => i.value === ''));
check('gen3: Dölj tömmer fälten igen', remasked);
await page.click('#seed-cancel');

// ---- Export (underlag för import-testet): 3 poster i detta läge
await page.click('#settings-btn');
await page.waitForSelector('#settings-dialog[open]');
await page.click('#export-btn');
await page.waitForSelector('#confirm-dialog[open]');
check('gen3: exportvarningen nämner seed-fraser',
  (await page.textContent('#confirm-message')).includes('SEED-FRASER'));
const exportDl = page.waitForEvent('download');
await page.click('#confirm-ok');
const exportFile = path.join(tmp, 'valv-export.json');
await (await exportDl).saveAs(exportFile);
const exported = JSON.parse(readFileSync(exportFile, 'utf8'));
check('gen3: exporten innehåller 3 poster med intakta seed-ord',
  exported.entries.length === 3
  && exported.entries.find((e) => e.type === 'seed').words.join(' ') === PHRASE);
await page.click('#settings-close');

// lås/upplås i samma session med osparad ändring
await page.click('#new-login-btn');
await page.fill('#entry-title', 'Wifi');
await page.fill('#entry-password', 'wifi-pw');
await page.click('#entry-form button[type=submit]');
await page.click('#lock-btn');
await page.waitForSelector('#unlock-form', { state: 'visible' });
check('gen3: lås visar låsskärmen', true);
check('gen3: listan är tömd vid lås', (await page.locator('#entry-list li').count()) === 0);
await page.fill('#unlock-password', PW);
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('gen3: osparad ändring överlevde lås/upplås (krypterat i DOM)',
  (await page.locator('#entry-list li').count()) === 4);
check('gen3: osparat-indikatorn kvar efter lås/upplås', await page.isVisible('#dirty-indicator'));

// generator
await page.click('#generator-btn');
const generated = await page.inputValue('#gen-output');
check('gen3: generatorn ger 20 tecken', generated.length === 20);
await page.click('#gen-regenerate');
const generated2 = await page.inputValue('#gen-output');
check('gen3: nytt lösenord vid omgenerering', generated2 !== generated && generated2.length === 20);
await page.click('#gen-close');
await page.close();

// Hjälpare: skapa ett nytt tomt appskal och lås upp det med ett nytt lösenord
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

// ---- Lösning A: importera JSON-exporten i ett nytt tomt skal
page = await freshShell(path.join(tmp, 'shell-a.html'));
await page.click('#settings-btn');
const [chooserA] = await Promise.all([
  page.waitForEvent('filechooser'),
  page.click('#import-btn'),
]);
await chooserA.setFiles(exportFile);
await page.waitForSelector('#merge-dialog[open]');
check('import: merge-dialogen visar antal poster',
  (await page.textContent('#merge-message')).includes('3 poster'));
await page.click('#merge-merge');
// dialogens close-händelse kommer före renderList — vänta på listan, inte dialogen
await page.waitForFunction(() => document.querySelectorAll('#entry-list li').length === 3);
check('import: alla 3 poster togs in', true);
const importedTitles = await page.locator('.entry-title').allTextContents();
check('import: titlarna är identiska', importedTitles.join('|') === 'Banken <script>alert(1)</script>|E-post|Ledger');
await page.click('#entry-list li:has(.badge)');
await page.waitForSelector('#seed-dialog[open]');
await page.click('#seed-toggle');
const importedWords = await page.evaluate(() =>
  Array.from(document.querySelectorAll('#seed-grid input')).map((i) => i.value));
check('import: seed-orden identiska i rätt ordning', importedWords.join(' ') === PHRASE);
check('import: wallet identisk', (await page.inputValue('#seed-wallet')) === 'Ledger Nano X');
await page.click('#seed-cancel');
await page.click('#entry-list li:nth-child(2)'); // E-post
await page.waitForSelector('#entry-dialog[open]');
check('import: login-lösenordet identiskt', (await page.inputValue('#entry-password')) === 'annat-lösenord');
await page.click('#entry-cancel');
await page.close();

// ---- Lösning B: uppgradera från gammal valvfil i ett nytt tomt skal
page = await freshShell(path.join(tmp, 'shell-b.html'));
await page.click('#settings-btn');
const [chooserB] = await Promise.all([
  page.waitForEvent('filechooser'),
  page.click('#upgrade-btn'),
]);
await chooserB.setFiles(gen3); // gammal fil, krypterad med PW (inte PW2)
await page.waitForSelector('#upgrade-dialog[open]');
check('uppgradera: dialogen visar filnamnet',
  (await page.textContent('#upgrade-filename')).includes('gen3.html'));

await page.fill('#upgrade-password', 'fel-lösenord');
await page.click('#upgrade-unlock');
await page.waitForSelector('#upgrade-error', { state: 'visible' });
check('uppgradera: fel lösenord ger fel med ny chans', true);

await page.fill('#upgrade-password', PW);
await page.click('#upgrade-unlock');
await page.waitForSelector('#merge-dialog[open]');
check('uppgradera: merge-dialogen visar antal poster',
  (await page.textContent('#merge-message')).includes('3 poster'));
await page.click('#merge-merge');
await page.waitForFunction(() => document.querySelectorAll('#entry-list li').length === 3);
check('uppgradera: alla 3 poster togs in', true);

// round-trip: spara det uppgraderade valvet och öppna den sparade filen
const genB = path.join(tmp, 'gen-b.html');
await saveAndCapture(page, genB);
await page.close();

page = await ctx.newPage();
await page.goto('file://' + genB);
await page.fill('#unlock-password', PW2); // det NYA skalets lösenord
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('uppgradera: round-trip — sparad fil öppnas med nya lösenordet och 3 poster',
  (await page.locator('#entry-list li').count()) === 3);
await page.click('#entry-list li:has(.badge)');
await page.waitForSelector('#seed-dialog[open]');
await page.click('#seed-toggle');
const upgradedWords = await page.evaluate(() =>
  Array.from(document.querySelectorAll('#seed-grid input')).map((i) => i.value));
check('uppgradera: seed-orden överlevde uppgradering + round-trip', upgradedWords.join(' ') === PHRASE);
await page.click('#seed-cancel');

await page.close();
await browser.close();
console.log(failed ? `\n${failed} E2E-KONTROLLER MISSLYCKADES` : '\nAlla E2E-kontroller gick igenom');
process.exit(failed ? 1 : 0);
