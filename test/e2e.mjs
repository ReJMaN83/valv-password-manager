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

await page.click('#new-entry-btn');
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

await page.click('#new-entry-btn');
await page.fill('#entry-title', 'E-post');
await page.fill('#entry-username', 'daniel.sahlin');
await page.fill('#entry-password', 'annat-lösenord');
await page.click('#entry-form button[type=submit]');
check('gen2: osparat-indikatorn visas efter ändring', await page.isVisible('#dirty-indicator'));

await page.fill('#search', 'banken');
check('gen2: sökningen filtrerar', (await page.locator('#entry-list li').count()) === 1);
await page.fill('#search', '');

const gen3 = path.join(tmp, 'gen3.html');
await saveAndCapture(page, gen3);
await page.close();

// ---- Generation 3: andra round-trip-varvet
page = await ctx.newPage();
await page.goto('file://' + gen3);
await page.fill('#unlock-password', PW);
await page.click('#unlock-btn');
await page.waitForSelector('#main-screen', { state: 'visible' });
check('gen3: båda posterna finns efter andra varvet',
  (await page.locator('#entry-list li').count()) === 2);
const titles = await page.locator('.entry-title').allTextContents();
check('gen3: sorterad A–Ö', titles[0] === 'Banken <script>alert(1)</script>' && titles[1] === 'E-post');

// lås/upplås i samma session med osparad ändring
await page.click('#new-entry-btn');
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
  (await page.locator('#entry-list li').count()) === 3);
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
await browser.close();
console.log(failed ? `\n${failed} E2E-KONTROLLER MISSLYCKADES` : '\nAlla E2E-kontroller gick igenom');
process.exit(failed ? 1 : 0);
