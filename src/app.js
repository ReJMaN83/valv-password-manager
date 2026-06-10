// app.js — Valv applikationslogik
'use strict';

// ============================================================
// Orörd källkod — grunden för spara-mekanismen
//
// Vi läser document.documentElement.outerHTML EN gång, direkt när skriptet
// körs. Skripten ligger sist i <body>, så hela dokumentet är parsat men
// appen har ännu inte rört DOM:en. Detta är den robustaste metoden:
//
//  - Att läsa outerHTML först vid spara vore osäkert: då innehåller DOM:en
//    renderade poster i KLARTEXT (listan, öppna dialoger) som skulle
//    serialiseras med ut i den sparade filen.
//  - Att bära källkoden i en separat template skulle dubblera hela appen
//    i filen och riskera att template och faktisk kod glider isär.
//
// Ögonblicksbilden vid start innehåller bara appkod + det krypterade
// vault-blocket. Webbläsarens serialisering är stabil: en sparad fil som
// öppnas och sparas igen ger samma resultat (round-trip-invarianten).
// outerHTML innehåller inte doctype, därför läggs den till manuellt.
const PRISTINE_SOURCE = '<!DOCTYPE html>\n' + document.documentElement.outerHTML;

// Matchar vault-blocket i källkoden. Skrivet med <\/script> så att appkoden
// själv inte innehåller en avslutande script-tagg i klartext (det skulle
// avsluta inline-skriptet i den byggda filen).
const VAULT_BLOCK_RE =
  /(<script id="vault-data" type="application\/json">)([\s\S]*?)(<\/script>)/;

const $ = (id) => document.getElementById(id);

// Allt dekrypterat lever ENDAST här, i minnet. Aldrig localStorage,
// sessionStorage, IndexedDB, cookies eller disk.
const state = {
  key: null,        // CryptoKey (AES-GCM), ej extraherbar
  salt: null,       // Uint8Array
  iterations: KDF_ITERATIONS_DEFAULT,
  entries: null,    // null = låst
  settings: { autoLockMinutes: 5 },
  verifier: null,   // krypterad kontrollsträng, används av "byt lösenord"
  fileHandle: null, // File System Access-handtag, återanvänds mellan sparningar
  editingId: null,
  clipboardTimer: null,
  autoLockTimer: null,
};

// "dirty" = filen på disk är inte aktuell. Flaggan överlever lås/upplås
// (den avslöjar inget känsligt) så att indikatorn stämmer även efter
// auto-lås innan användaren hunnit spara.
let dirty = false;

function setDirty(value) {
  dirty = value;
  $('dirty-indicator').classList.toggle('hidden', !dirty);
}
const markDirty = () => setDirty(true);

// ============================================================
// Småhjälpare: toast och bekräftelsedialog
let toastTimer = null;
function toast(message) {
  const box = $('toast');
  box.textContent = message;
  box.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => box.classList.add('hidden'), 4000);
}

let confirmAnswer = false;
$('confirm-ok').addEventListener('click', () => { confirmAnswer = true; $('confirm-dialog').close(); });
$('confirm-cancel').addEventListener('click', () => $('confirm-dialog').close());

function confirmDialog(message, okLabel = 'OK') {
  return new Promise((resolve) => {
    $('confirm-message').textContent = message;
    $('confirm-ok').textContent = okLabel;
    confirmAnswer = false;
    const dlg = $('confirm-dialog');
    dlg.addEventListener('close', () => resolve(confirmAnswer), { once: true });
    dlg.showModal();
  });
}

// ============================================================
// Vault-blocket i DOM:en
function readVaultBlock() {
  const text = $('vault-data').textContent.trim();
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

async function currentVaultJson() {
  const payload = JSON.stringify({
    entries: state.entries,
    meta: { modified: new Date().toISOString(), settings: state.settings },
  });
  // encryptWithKey genererar en NY slumpad nonce vid varje anrop
  const { nonce, ciphertext } = await encryptWithKey(state.key, payload);
  return JSON.stringify({
    version: 1,
    kdf: 'PBKDF2-SHA256',
    iterations: state.iterations,
    salt: toBase64(state.salt),
    nonce,
    ciphertext,
  });
}

// Speglar aktuell (krypterad) data till DOM-blocket. Därmed använder
// lås/upplås i samma session alltid senaste datan — även ändringar som
// ännu inte skrivits till disk överlever ett (auto-)lås, krypterat.
async function updateLiveVaultBlock() {
  const json = await currentVaultJson();
  $('vault-data').textContent = json;
  return json;
}

// ============================================================
// Låsskärm: upplåsning och first-run
function init() {
  const blob = readVaultBlock();
  $('unlock-form').classList.toggle('hidden', !blob);
  $('create-form').classList.toggle('hidden', !!blob);
  (blob ? $('unlock-password') : $('create-password')).focus();
}

$('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const blob = readVaultBlock();
  const password = $('unlock-password').value;
  if (!blob || !password) return;
  const btn = $('unlock-btn');
  btn.disabled = true;
  btn.textContent = 'Låser upp…';
  $('unlock-error').classList.add('hidden');
  try {
    const salt = fromBase64(blob.salt);
    const key = await deriveKey(password, salt, blob.iterations);
    const payload = JSON.parse(await decryptWithKey(key, blob.nonce, blob.ciphertext));
    $('unlock-password').value = '';
    await openVault(key, salt, blob.iterations, payload);
  } catch {
    // GCM-taggen validerade inte => fel lösenord. Ingen korrupt data visas.
    $('unlock-error').classList.remove('hidden');
    $('unlock-password').select();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Lås upp';
  }
});

function passwordStrength(password) {
  if (!password) return { score: 0, label: '' };
  let classes = 0;
  for (const re of [/[a-zåäö]/, /[A-ZÅÄÖ]/, /[0-9]/, /[^A-Za-z0-9ÅÄÖåäö]/]) {
    if (re.test(password)) classes++;
  }
  let score = 1;
  if (password.length >= 8) score++;
  if (password.length >= 12 && classes >= 2) score++;
  if (password.length >= 14 && classes >= 3) score++;
  if (password.length >= 20) score = 4;
  score = Math.min(score, 4);
  return { score, label: ['', 'Mycket svagt', 'Svagt', 'Bra', 'Starkt'][score] };
}

$('create-password').addEventListener('input', () => {
  const { score, label } = passwordStrength($('create-password').value);
  const bar = $('strength-bar');
  bar.style.width = (score * 25) + '%';
  bar.dataset.score = score;
  $('strength-label').textContent = label || ' ';
});

$('create-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = $('create-password').value;
  const repeated = $('create-password2').value;
  const errorBox = $('create-error');
  const fail = (message) => { errorBox.textContent = message; errorBox.classList.remove('hidden'); };
  if (password.length < 8) return fail('Lösenordet måste vara minst 8 tecken.');
  if (password !== repeated) return fail('Lösenorden matchar inte.');
  errorBox.classList.add('hidden');
  const btn = $('create-btn');
  btn.disabled = true;
  btn.textContent = 'Skapar valv…';
  try {
    const salt = randomBytes(SALT_BYTES);
    const key = await deriveKey(password, salt, KDF_ITERATIONS_DEFAULT);
    $('create-password').value = '';
    $('create-password2').value = '';
    $('strength-bar').style.width = '0';
    $('strength-label').textContent = ' ';
    await openVault(key, salt, KDF_ITERATIONS_DEFAULT, { entries: [], meta: {} });
    await updateLiveVaultBlock(); // gör att lås/upplås fungerar redan före första sparningen
    setDirty(true);
    toast('Valvet är skapat — klicka Spara för att skriva det till fil.');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Skapa valv';
  }
});

async function openVault(key, salt, iterations, payload) {
  state.key = key;
  state.salt = salt;
  state.iterations = iterations;
  // normalizeEntry ger poster från äldre valv (utan type-fält) type "login"
  state.entries = (Array.isArray(payload.entries) ? payload.entries : []).map(normalizeEntry);
  state.settings = Object.assign({ autoLockMinutes: 5 }, payload.meta && payload.meta.settings);
  // Krypterad kontrollsträng: låter "byt lösenord" verifiera det nuvarande
  // lösenordet utan att lösenordet eller någon hash av det sparas.
  state.verifier = await encryptWithKey(key, 'valv-verifier');
  $('lock-screen').classList.add('hidden');
  $('main-screen').classList.remove('hidden');
  $('search').value = '';
  renderList();
  resetAutoLock();
}

// ============================================================
// Lås och auto-lås
async function lock() {
  if (!state.key) return;
  // Bevara senaste ändringarna (krypterat) i DOM-blocket innan minnet töms.
  if (dirty) await updateLiveVaultBlock();
  // Nollställning, best effort: referenserna släpps så att GC kan ta minnet.
  // JS-strängar är immutabla och kan inte skrivas över på plats — se README
  // för begränsningarna. CryptoKey är ej extraherbar och försvinner med GC.
  state.key = null;
  state.salt = null;
  state.entries = null;
  state.verifier = null;
  state.editingId = null;
  clearTimeout(state.autoLockTimer);
  if (state.clipboardTimer) {
    clearTimeout(state.clipboardTimer);
    clearClipboard();
  }
  for (const dlg of document.querySelectorAll('dialog')) if (dlg.open) dlg.close();
  $('entry-list').textContent = '';
  for (const field of document.querySelectorAll(
    'input[type="text"], input[type="password"], input[type="search"], textarea')) {
    field.value = '';
  }
  $('main-screen').classList.add('hidden');
  $('lock-screen').classList.remove('hidden');
  init();
}

$('lock-btn').addEventListener('click', lock);

function resetAutoLock() {
  clearTimeout(state.autoLockTimer);
  if (!state.key) return;
  const minutes = Math.min(30, Math.max(1, Number(state.settings.autoLockMinutes) || 5));
  state.autoLockTimer = setTimeout(async () => {
    await lock();
    toast('Valvet låstes automatiskt efter inaktivitet.');
  }, minutes * 60000);
}

let lastActivity = 0;
function onActivity() {
  const now = Date.now();
  if (now - lastActivity < 5000) return; // strypning: starta inte om timern för varje pixel
  lastActivity = now;
  resetAutoLock();
}
for (const eventName of ['pointermove', 'pointerdown', 'keydown', 'scroll', 'touchstart']) {
  document.addEventListener(eventName, onActivity, { passive: true });
}

// ============================================================
// Urklipp med automatisk rensning
async function copySecret(text, what, message) {
  if (!text) { toast(`Inget att kopiera — fältet är tomt.`); return; }
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast('Kunde inte komma åt urklipp.');
    return;
  }
  clearTimeout(state.clipboardTimer);
  state.clipboardTimer = setTimeout(clearClipboard, 30000);
  toast(message || `${what} kopierat — urklipp rensas om 30 s.`);
}

async function clearClipboard() {
  state.clipboardTimer = null;
  try {
    await navigator.clipboard.writeText('');
    toast('Urklipp rensat.');
  } catch {
    // dokumentet kan sakna fokus — rensningen är best effort
  }
}

// ============================================================
// Lista och sök
function renderList() {
  const query = $('search').value.trim().toLowerCase();
  const list = $('entry-list');
  list.textContent = '';
  if (!state.entries) return;
  // Sökindexet för seed-poster är titel + wallet — ALDRIG själva orden.
  const matchesQuery = (e) => {
    if (!query) return true;
    const haystacks = e.type === 'seed'
      ? [e.title, e.wallet]
      : [e.title, e.username, e.url];
    return haystacks.some((value) => (value || '').toLowerCase().includes(query));
  };
  const matches = state.entries
    .filter(matchesQuery)
    .sort((a, b) => (a.title || '').localeCompare(b.title || '', 'sv', { sensitivity: 'base' }));

  for (const entry of matches) {
    const li = document.createElement('li');
    li.tabIndex = 0;
    const isSeed = entry.type === 'seed';

    const info = document.createElement('div');
    info.className = 'entry-info';
    const title = document.createElement('span');
    title.className = 'entry-title';
    title.textContent = entry.title; // alltid textContent — aldrig innerHTML med användardata
    const sub = document.createElement('span');
    sub.className = 'entry-sub';
    sub.textContent = isSeed ? (entry.wallet || '') : (entry.username || entry.url || '');
    info.append(title, sub);

    const actions = document.createElement('div');
    actions.className = 'entry-actions';
    if (isSeed) {
      // Medvetet inga kopieringsknappar i listan för seed-poster: hela
      // frasen ska inte hamna i urklipp på ett felklick. Badge i stället.
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = '🌱 SEED';
      actions.append(badge);
    } else {
      actions.append(
        makeButton('Anv.', 'Kopiera användarnamn', (ev) => {
          ev.stopPropagation();
          copySecret(entry.username, 'Användarnamn');
        }),
        makeButton('Lösen', 'Kopiera lösenord', (ev) => {
          ev.stopPropagation();
          copySecret(entry.password, 'Lösenord');
        }),
      );
    }

    const open = () => (isSeed ? openSeedDialog(entry.id) : openEntryDialog(entry.id));
    li.append(info, actions);
    li.addEventListener('click', open);
    li.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' && ev.target === li) open();
    });
    list.append(li);
  }

  const hint = $('empty-hint');
  if (matches.length === 0) {
    hint.textContent = state.entries.length === 0
      ? 'Inga poster ännu. Klicka på ”+ Inloggning” eller ”+ Seed-fras”.'
      : 'Inga träffar på sökningen.';
    hint.classList.remove('hidden');
  } else {
    hint.classList.add('hidden');
  }
}

function makeButton(label, title, onClick) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = label;
  btn.title = title;
  btn.addEventListener('click', onClick);
  return btn;
}

$('search').addEventListener('input', renderList);

// ============================================================
// Post-dialogen: skapa, redigera, ta bort
const ENTRY_FIELDS = ['entry-title', 'entry-username', 'entry-password', 'entry-url', 'entry-notes'];

function openEntryDialog(id) {
  state.editingId = id || null;
  const entry = id ? state.entries.find((e) => e.id === id) : null;
  $('entry-dialog-title').textContent = entry ? 'Redigera post' : 'Ny post';
  $('entry-title').value = entry ? entry.title : '';
  $('entry-username').value = entry ? entry.username : '';
  $('entry-password').value = entry ? entry.password : '';
  $('entry-password').type = 'password';
  $('entry-toggle-password').textContent = 'Visa';
  $('entry-url').value = entry ? entry.url : '';
  $('entry-notes').value = entry ? entry.notes : '';
  $('entry-delete').classList.toggle('hidden', !entry);
  $('entry-dialog').showModal();
  $('entry-title').focus();
}

$('new-login-btn').addEventListener('click', () => openEntryDialog(null));
$('new-seed-btn').addEventListener('click', () => openSeedDialog(null));
$('entry-cancel').addEventListener('click', () => $('entry-dialog').close());

// Rensa fälten även när dialogen stängs med Escape, så att lösenord
// inte ligger kvar i DOM:en.
$('entry-dialog').addEventListener('close', () => {
  for (const fieldId of ENTRY_FIELDS) $(fieldId).value = '';
  state.editingId = null;
});

$('entry-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const now = new Date().toISOString();
  const values = {
    title: $('entry-title').value.trim(),
    username: $('entry-username').value,
    password: $('entry-password').value,
    url: $('entry-url').value.trim(),
    notes: $('entry-notes').value,
  };
  if (!values.title) return;
  if (state.editingId) {
    const entry = state.entries.find((e) => e.id === state.editingId);
    if (entry) Object.assign(entry, values, { modified: now });
  } else {
    state.entries.push({ id: crypto.randomUUID(), ...values, created: now, modified: now });
  }
  markDirty();
  $('entry-dialog').close();
  renderList();
});

$('entry-delete').addEventListener('click', async () => {
  const entry = state.entries && state.entries.find((e) => e.id === state.editingId);
  if (!entry) return;
  if (!(await confirmDialog(`Ta bort posten ”${entry.title}”?`, 'Ta bort'))) return;
  state.entries = state.entries.filter((e) => e.id !== entry.id);
  markDirty();
  $('entry-dialog').close();
  renderList();
});

$('entry-toggle-password').addEventListener('click', () => {
  const field = $('entry-password');
  const show = field.type === 'password';
  field.type = show ? 'text' : 'password';
  $('entry-toggle-password').textContent = show ? 'Dölj' : 'Visa';
});

$('entry-copy-username').addEventListener('click', () => {
  copySecret($('entry-username').value, 'Användarnamn');
});
$('entry-copy-password').addEventListener('click', () => {
  copySecret($('entry-password').value, 'Lösenord');
});

// ============================================================
// Seed-poster
//
// Säkerhetsmodell för orden: när en sparad seed-post öppnas är ordfälten
// TOMMA (value = '') med ”•••••” som placeholder och readonly — de
// riktiga orden finns inte i DOM:en förrän användaren klickar Visa.
// Vid Dölj töms fälten igen. Sparas posten utan att orden visats behålls
// de redan sparade orden oförändrade.
let seedEditingId = null;
let seedWordsShown = false;

const seedWordInputs = () => Array.from(document.querySelectorAll('#seed-grid input'));

function buildSeedGrid(count, masked) {
  const grid = $('seed-grid');
  grid.textContent = '';
  for (let i = 0; i < count; i++) {
    const cell = document.createElement('div');
    cell.className = 'word-cell';
    const num = document.createElement('span');
    num.className = 'word-num';
    num.textContent = String(i + 1); // numreringen är hela poängen — ordningen måste synas
    const input = document.createElement('input');
    input.type = 'text';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.setAttribute('autocapitalize', 'none');
    input.setAttribute('aria-label', `Ord ${i + 1}`);
    if (masked) {
      input.placeholder = '•••••';
      input.readOnly = true;
    }
    cell.append(num, input);
    grid.append(cell);
  }
}

function validateSeedWords() {
  let unknown = 0;
  for (const input of seedWordInputs()) {
    const word = input.value.trim().toLowerCase();
    const bad = word !== '' && !BIP39_SET.has(word);
    input.parentElement.classList.toggle('invalid', bad);
    if (bad) unknown++;
  }
  const warning = $('seed-warning');
  if (unknown > 0) {
    warning.textContent = `${unknown} ord finns inte i BIP39-ordlistan (engelska). `
      + 'Kontrollera stavningen — du kan ändå spara (andra ordlistor/språk finns).';
    warning.classList.remove('hidden');
  } else {
    warning.classList.add('hidden');
  }
}

function openSeedDialog(id) {
  seedEditingId = id || null;
  const entry = id ? state.entries.find((e) => e.id === id) : null;
  $('seed-dialog-title').textContent = entry ? 'Seed-fras' : 'Ny seed-fras';
  $('seed-title').value = entry ? entry.title : '';
  $('seed-wallet').value = entry ? entry.wallet || '' : '';
  $('seed-passphrase').value = entry ? entry.passphrase || '' : '';
  $('seed-passphrase').type = 'password';
  $('seed-toggle-passphrase').textContent = 'Visa';
  $('seed-derivation').value = entry ? entry.derivation || '' : '';
  $('seed-notes').value = entry ? entry.notes || '' : '';
  $('seed-delete').classList.toggle('hidden', !entry);
  $('seed-warning').classList.add('hidden');
  // ny post: skriv orden direkt; befintlig: dolda tills Visa klickas
  seedWordsShown = !entry;
  $('seed-toggle').classList.toggle('hidden', !entry);
  $('seed-toggle').textContent = 'Visa';
  $('seed-paste-hint').classList.toggle('hidden', !!entry);
  const count = entry ? entry.words.length : 12;
  $('seed-count').value = String(count);
  $('seed-count').disabled = !seedWordsShown;
  buildSeedGrid(count, !!entry);
  $('seed-dialog').showModal();
  $('seed-title').focus();
}

$('seed-toggle').addEventListener('click', () => {
  const entry = state.entries && state.entries.find((e) => e.id === seedEditingId);
  if (!entry) return;
  if (!seedWordsShown) {
    buildSeedGrid(entry.words.length, false);
    seedWordInputs().forEach((input, i) => { input.value = entry.words[i] || ''; });
    seedWordsShown = true;
    $('seed-toggle').textContent = 'Dölj';
    $('seed-count').value = String(entry.words.length);
    $('seed-count').disabled = false;
    $('seed-paste-hint').classList.remove('hidden');
    validateSeedWords();
  } else {
    // Dölj: tillbaka till placeholder — ordändringar i fälten förkastas
    buildSeedGrid(entry.words.length, true);
    seedWordsShown = false;
    $('seed-toggle').textContent = 'Visa';
    $('seed-count').value = String(entry.words.length);
    $('seed-count').disabled = true;
    $('seed-paste-hint').classList.add('hidden');
    $('seed-warning').classList.add('hidden');
  }
});

$('seed-count').addEventListener('change', () => {
  const kept = seedWordInputs().map((input) => input.value);
  buildSeedGrid(Number($('seed-count').value), false);
  seedWordInputs().forEach((input, i) => { input.value = kept[i] || ''; });
  validateSeedWords();
});

$('seed-grid').addEventListener('input', (event) => {
  if (event.target.matches('input')) validateSeedWords();
});

// Klistra in hela frasen i ett ordfält => splitta och fyll alla fält.
$('seed-grid').addEventListener('paste', (event) => {
  if (!event.target.matches('input') || event.target.readOnly) return;
  const words = parseSeedPhrase((event.clipboardData || window.clipboardData).getData('text'));
  if (words.length < 2) return; // ett ensamt ord klistras in som vanligt
  event.preventDefault();
  if (isValidSeedWordCount(words.length)) {
    $('seed-count').value = String(words.length);
    buildSeedGrid(words.length, false);
  } else {
    toast(`${words.length} ord är inget giltigt antal (12/15/18/21/24) — fyller i så långt det går.`);
  }
  seedWordInputs().forEach((input, i) => { input.value = words[i] || ''; });
  validateSeedWords();
});

$('seed-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const title = $('seed-title').value.trim();
  if (!title) return;
  const existing = seedEditingId ? state.entries.find((e) => e.id === seedEditingId) : null;
  let words;
  if (seedWordsShown) {
    words = seedWordInputs().map((input) => input.value.trim().toLowerCase());
    if (words.some((word) => word === '')) {
      const warning = $('seed-warning');
      warning.textContent = 'Alla ordfält måste fyllas i.';
      warning.classList.remove('hidden');
      return;
    }
  } else {
    words = existing.words; // orden visades aldrig — behåll de sparade orden
  }
  const now = new Date().toISOString();
  const values = {
    type: 'seed',
    title,
    wallet: $('seed-wallet').value.trim(),
    words,
    passphrase: $('seed-passphrase').value,
    derivation: $('seed-derivation').value.trim(),
    notes: $('seed-notes').value,
  };
  if (existing) {
    Object.assign(existing, values, { modified: now });
  } else {
    state.entries.push({ id: crypto.randomUUID(), ...values, created: now, modified: now });
  }
  markDirty();
  $('seed-dialog').close();
  renderList();
});

$('seed-cancel').addEventListener('click', () => $('seed-dialog').close());

// Töm allt vid stängning (även Escape) så att inga ord ligger kvar i DOM:en.
$('seed-dialog').addEventListener('close', () => {
  for (const id of ['seed-title', 'seed-wallet', 'seed-passphrase', 'seed-derivation', 'seed-notes']) {
    $(id).value = '';
  }
  $('seed-grid').textContent = '';
  seedEditingId = null;
  seedWordsShown = false;
});

$('seed-delete').addEventListener('click', async () => {
  const entry = state.entries && state.entries.find((e) => e.id === seedEditingId);
  if (!entry) return;
  const ok = await confirmDialog(
    `Ta bort seed-frasen ”${entry.title}”? Utan frasen kan plånboken inte återskapas.`,
    'Ta bort');
  if (!ok) return;
  state.entries = state.entries.filter((e) => e.id !== entry.id);
  markDirty();
  $('seed-dialog').close();
  renderList();
});

$('seed-toggle-passphrase').addEventListener('click', () => {
  const field = $('seed-passphrase');
  const show = field.type === 'password';
  field.type = show ? 'text' : 'password';
  $('seed-toggle-passphrase').textContent = show ? 'Dölj' : 'Visa';
});

$('seed-copy').addEventListener('click', () => {
  let words;
  if (seedWordsShown) {
    words = seedWordInputs().map((input) => input.value.trim().toLowerCase()).filter(Boolean);
  } else {
    const entry = state.entries && state.entries.find((e) => e.id === seedEditingId);
    words = entry ? entry.words : [];
  }
  if (!words.length) { toast('Inga ord att kopiera.'); return; }
  copySecret(words.join(' '), 'Seed-fras',
    'Seed-fras i urklipp — rensas om 30 s. Klistra aldrig in på webbsidor.');
});

// ============================================================
// Spara: bygg en komplett ny HTML-fil och skriv den till disk
function buildSavedHtml(vaultJson) {
  if (!VAULT_BLOCK_RE.test(PRISTINE_SOURCE)) {
    throw new Error('vault-data-blocket saknas i källkoden');
  }
  // Replacer-funktion så att $-tecken i JSON:en inte tolkas som
  // specialreferenser av String.prototype.replace.
  return PRISTINE_SOURCE.replace(VAULT_BLOCK_RE, (_m, open, _old, close) => open + vaultJson + close);
}

async function saveVault() {
  if (!state.key) return;
  const vaultJson = await updateLiveVaultBlock();
  const html = buildSavedHtml(vaultJson);

  // Primärt: File System Access API — kan skriva över filen på plats.
  // Handtaget återanvänds så att efterföljande sparningar inte frågar igen.
  if (window.showSaveFilePicker) {
    try {
      if (!state.fileHandle) {
        state.fileHandle = await window.showSaveFilePicker({
          suggestedName: 'valv.html',
          types: [{ description: 'HTML-fil', accept: { 'text/html': ['.html'] } }],
        });
      }
      const writable = await state.fileHandle.createWritable();
      await writable.write(html);
      await writable.close();
      setDirty(false);
      toast('Sparat.');
      return;
    } catch (err) {
      if (err && err.name === 'AbortError') {
        toast('Sparandet avbröts.');
        return; // användaren ångrade sig — fortfarande osparat
      }
      // Handtaget kan ha blivit ogiltigt (flyttad/raderad fil) eller API:t
      // blockerat — släpp handtaget och fall tillbaka på nedladdning.
      state.fileHandle = null;
    }
  }

  // Fallback: Blob + nedladdningslänk.
  downloadFile('valv.html', html, 'text/html');
  setDirty(false);
  toast('Nedladdad som valv.html — ersätt din gamla fil med den nya.');
}

function downloadFile(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

$('save-btn').addEventListener('click', saveVault);

// Varna om fönstret stängs med osparade ändringar.
window.addEventListener('beforeunload', (event) => {
  if (dirty) {
    event.preventDefault();
    event.returnValue = '';
  }
});

// ============================================================
// Lösenordsgenerator
const GEN_SETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!#$%&()*+,-./:;<=>?@[]^_{|}~',
};

// Slump enbart via crypto.getRandomValues, med rejection sampling så att
// modulo-operationen inte ger vissa tecken högre sannolikhet.
function generatePassword(length, pool) {
  const limit = Math.floor(256 / pool.length) * pool.length;
  let out = '';
  while (out.length < length) {
    for (const byte of randomBytes(length)) {
      if (byte < limit && out.length < length) out += pool[byte % pool.length];
    }
  }
  return out;
}

function genPool() {
  let pool = '';
  if ($('gen-upper').checked) pool += GEN_SETS.upper;
  if ($('gen-lower').checked) pool += GEN_SETS.lower;
  if ($('gen-digits').checked) pool += GEN_SETS.digits;
  if ($('gen-symbols').checked) pool += GEN_SETS.symbols;
  return pool;
}

function regenerate() {
  const pool = genPool();
  $('gen-length-value').textContent = $('gen-length').value;
  $('gen-output').value = pool
    ? generatePassword(Number($('gen-length').value), pool)
    : '';
  if (!pool) toast('Välj minst en teckentyp.');
}

function openGenerator(forEntry) {
  $('gen-use').classList.toggle('hidden', !forEntry);
  regenerate();
  $('generator-dialog').showModal();
}

$('generator-btn').addEventListener('click', () => openGenerator(false));
$('entry-generate').addEventListener('click', () => openGenerator(true));
$('gen-length').addEventListener('input', regenerate);
for (const id of ['gen-upper', 'gen-lower', 'gen-digits', 'gen-symbols']) {
  $(id).addEventListener('change', regenerate);
}
$('gen-regenerate').addEventListener('click', regenerate);
$('gen-copy').addEventListener('click', () => copySecret($('gen-output').value, 'Lösenord'));
$('gen-use').addEventListener('click', () => {
  $('entry-password').value = $('gen-output').value;
  $('generator-dialog').close();
});
$('gen-close').addEventListener('click', () => $('generator-dialog').close());
$('generator-dialog').addEventListener('close', () => { $('gen-output').value = ''; });

// ============================================================
// Inställningar: auto-lås, byt master-lösenord, export
$('settings-btn').addEventListener('click', () => {
  $('autolock-minutes').value = state.settings.autoLockMinutes;
  $('cp-message').classList.add('hidden');
  $('settings-dialog').showModal();
});
$('settings-close').addEventListener('click', () => $('settings-dialog').close());
$('settings-dialog').addEventListener('close', () => {
  for (const id of ['cp-current', 'cp-new', 'cp-new2']) $(id).value = '';
});

$('autolock-minutes').addEventListener('change', () => {
  const minutes = Math.min(30, Math.max(1, Number($('autolock-minutes').value) || 5));
  $('autolock-minutes').value = minutes;
  if (minutes !== state.settings.autoLockMinutes) {
    state.settings.autoLockMinutes = minutes;
    markDirty();
    resetAutoLock();
    toast(`Auto-lås satt till ${minutes} min. Glöm inte att spara.`);
  }
});

$('cp-submit').addEventListener('click', async () => {
  const message = $('cp-message');
  const show = (text, isError) => {
    message.textContent = text;
    message.classList.remove('hidden');
    message.classList.toggle('error', isError);
  };
  const current = $('cp-current').value;
  const next = $('cp-new').value;
  if (next.length < 8) return show('Det nya lösenordet måste vara minst 8 tecken.', true);
  if (next !== $('cp-new2').value) return show('De nya lösenorden matchar inte.', true);

  const btn = $('cp-submit');
  btn.disabled = true;
  btn.textContent = 'Byter…';
  try {
    // Verifiera nuvarande lösenord mot den krypterade kontrollsträngen.
    try {
      const candidate = await deriveKey(current, state.salt, state.iterations);
      await decryptWithKey(candidate, state.verifier.nonce, state.verifier.ciphertext);
    } catch {
      return show('Fel nuvarande lösenord.', true);
    }
    // Omkryptera med NYTT salt och dagens standard-iterationsantal.
    const salt = randomBytes(SALT_BYTES);
    const key = await deriveKey(next, salt, KDF_ITERATIONS_DEFAULT);
    state.salt = salt;
    state.key = key;
    state.iterations = KDF_ITERATIONS_DEFAULT;
    state.verifier = await encryptWithKey(key, 'valv-verifier');
    await updateLiveVaultBlock();
    markDirty();
    for (const id of ['cp-current', 'cp-new', 'cp-new2']) $(id).value = '';
    show('Lösenordet är bytt. Glöm inte att spara valvet till fil.', false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Byt lösenord';
  }
});

$('export-btn').addEventListener('click', async () => {
  const hasSeeds = state.entries.some((e) => e.type === 'seed');
  const message = hasSeeds
    ? 'VARNING: valvet innehåller SEED-FRASER. Exporten är HELT OKRYPTERAD — '
      + 'den som kommer över filen kan tömma dina plånböcker, och en seed-fras '
      + 'kan inte bytas som ett lösenord. Spara aldrig filen i molnet, och '
      + 'radera den säkert direkt efter användning. Fortsätt ändå?'
    : 'Exporten är HELT OKRYPTERAD — alla lösenord hamnar i klartext i filen. '
      + 'Spara den bara på en säker plats och radera den så fort du är klar. Fortsätt?';
  const ok = await confirmDialog(message, 'Exportera okrypterat');
  if (!ok) return;
  const json = JSON.stringify(
    { entries: state.entries, meta: { exported: new Date().toISOString() } },
    null, 2);
  downloadFile('valv-export.json', json, 'application/json');
});

// ============================================================
// Uppgradering och import
//
// Två vägar in i ett nytt (tomt) appskal:
//  A) Importera JSON — läser den okrypterade exporten.
//  B) Uppgradera från fil — läser #vault-data-blocket ur en äldre
//     valv.html och dekrypterar med DEN filens master-lösenord.
//     Datan förblir krypterad ända in i minnet, ingen okrypterad fil
//     behövs på disk. Därför rekommenderas B i UI:t.
// Den gamla filen läses enbart som TEXT (regex + JSON.parse) — dess
// HTML/skript renderas eller körs aldrig.

function pickFile(accept) {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = accept;
    input.classList.add('hidden');
    document.body.append(input);
    const done = (file) => { input.remove(); resolve(file); };
    input.addEventListener('change', () => done(input.files[0] || null), { once: true });
    input.addEventListener('cancel', () => done(null), { once: true });
    input.click();
  });
}

// Validerar att en vald fil är en valvfil och plockar ut det krypterade blocket.
function parseVaultFile(html) {
  const match = html.match(VAULT_BLOCK_RE);
  if (!match) return { error: 'Ingen valvdata hittades i filen — är det verkligen en valv.html?' };
  const text = match[2].trim();
  if (!text) return { error: 'Filen är ett tomt valvskal utan data.' };
  let blob;
  try { blob = JSON.parse(text); } catch { return { error: 'Valvdatan i filen är skadad.' }; }
  if (blob.version !== 1) {
    return { error: `Filen använder ett okänt valvformat (version ${blob.version ?? '?'}).` };
  }
  if (blob.kdf !== 'PBKDF2-SHA256' || !Number.isInteger(blob.iterations)
      || !blob.salt || !blob.nonce || !blob.ciphertext) {
    return { error: 'Valvdatan i filen är ofullständig.' };
  }
  return { blob };
}

let mergeChoice = null;
$('merge-merge').addEventListener('click', () => { mergeChoice = 'merge'; $('merge-dialog').close(); });
$('merge-replace').addEventListener('click', () => { mergeChoice = 'replace'; $('merge-dialog').close(); });
$('merge-cancel').addEventListener('click', () => $('merge-dialog').close());

function chooseMergeMode(message) {
  return new Promise((resolve) => {
    $('merge-message').textContent = message;
    mergeChoice = null;
    const dlg = $('merge-dialog');
    dlg.addEventListener('close', () => resolve(mergeChoice), { once: true });
    dlg.showModal();
  });
}

// Gemensam intagsväg för A och B: normalisera, fråga slå ihop/ersätt, ta in.
async function takeInEntries(rawEntries, sourceLabel) {
  const now = new Date().toISOString();
  const incoming = [];
  let skipped = 0;
  for (const raw of rawEntries) {
    if (!raw || typeof raw !== 'object' || typeof raw.title !== 'string') { skipped++; continue; }
    const entry = normalizeEntry(raw);
    if (typeof entry.id !== 'string' || !entry.id) entry.id = crypto.randomUUID();
    if (!entry.created) entry.created = now;
    if (!entry.modified) entry.modified = now;
    incoming.push(entry);
  }
  if (!incoming.length) {
    toast(`Inga giltiga poster hittades i ${sourceLabel}.`);
    return;
  }
  let message = `${incoming.length} poster hittades i ${sourceLabel}. `
    + `Slå ihop med dina ${state.entries.length} befintliga poster, eller ersätt allt?`;
  if (skipped > 0) message += ` (${skipped} poster hoppades över — ogiltigt format.)`;
  const mode = await chooseMergeMode(message);
  if (!mode) return;
  if (mode === 'replace') {
    if (state.entries.length > 0) {
      const ok = await confirmDialog(
        `Ersätta ALLT? Dina ${state.entries.length} befintliga poster tas bort.`, 'Ersätt');
      if (!ok) return;
    }
    state.entries = incoming;
  } else {
    const existingIds = new Set(state.entries.map((e) => e.id));
    for (const entry of incoming) {
      // id-krock (t.ex. samma export intagen två gånger): behåll båda
      // posterna med nytt id — aldrig tyst dataförlust.
      if (existingIds.has(entry.id)) entry.id = crypto.randomUUID();
      state.entries.push(entry);
    }
  }
  markDirty();
  renderList();
  $('settings-dialog').close();
  toast(`${incoming.length} poster intagna${mode === 'replace' ? ' (ersatte allt)' : ''}. Glöm inte att spara.`);
}

// A) Import av okrypterad JSON-export
$('import-btn').addEventListener('click', async () => {
  const file = await pickFile('.json,application/json');
  if (!file) return;
  let data;
  try { data = JSON.parse(await file.text()); } catch { toast('Filen är inte giltig JSON.'); return; }
  if (!data || typeof data !== 'object' || !Array.isArray(data.entries)) {
    toast('Filen ser inte ut som en Valv-export (fältet entries saknas).');
    return;
  }
  await takeInEntries(data.entries, 'JSON-filen');
});

// B) Uppgradera från en äldre valv.html
let upgradeBlob = null;

$('upgrade-btn').addEventListener('click', async () => {
  const file = await pickFile('.html,text/html');
  if (!file) return;
  const parsed = parseVaultFile(await file.text());
  if (parsed.error) { toast(parsed.error); return; }
  upgradeBlob = parsed.blob;
  $('upgrade-filename').textContent = `Fil: ${file.name}`;
  $('upgrade-password').value = '';
  $('upgrade-error').classList.add('hidden');
  $('upgrade-dialog').showModal();
  $('upgrade-password').focus();
});

$('upgrade-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!upgradeBlob) return;
  const password = $('upgrade-password').value;
  if (!password) return;
  const btn = $('upgrade-unlock');
  btn.disabled = true;
  btn.textContent = 'Dekrypterar…';
  try {
    const key = await deriveKey(password, fromBase64(upgradeBlob.salt), upgradeBlob.iterations);
    const payload = JSON.parse(await decryptWithKey(key, upgradeBlob.nonce, upgradeBlob.ciphertext));
    $('upgrade-dialog').close();
    await takeInEntries(Array.isArray(payload.entries) ? payload.entries : [], 'den gamla valvfilen');
  } catch {
    $('upgrade-error').textContent = 'Fel lösenord för den valda filen.';
    $('upgrade-error').classList.remove('hidden');
    $('upgrade-password').select();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Lås upp filen';
  }
});

$('upgrade-cancel').addEventListener('click', () => $('upgrade-dialog').close());
$('upgrade-dialog').addEventListener('close', () => {
  $('upgrade-password').value = '';
  upgradeBlob = null;
});

// ============================================================
// Start
init();
