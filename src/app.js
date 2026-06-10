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
  state.entries = Array.isArray(payload.entries) ? payload.entries : [];
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
async function copySecret(text, what) {
  if (!text) { toast(`Inget att kopiera — fältet är tomt.`); return; }
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast('Kunde inte komma åt urklipp.');
    return;
  }
  clearTimeout(state.clipboardTimer);
  state.clipboardTimer = setTimeout(clearClipboard, 30000);
  toast(`${what} kopierat — urklipp rensas om 30 s.`);
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
  const matches = state.entries
    .filter((e) => !query
      || (e.title || '').toLowerCase().includes(query)
      || (e.username || '').toLowerCase().includes(query)
      || (e.url || '').toLowerCase().includes(query))
    .sort((a, b) => (a.title || '').localeCompare(b.title || '', 'sv', { sensitivity: 'base' }));

  for (const entry of matches) {
    const li = document.createElement('li');
    li.tabIndex = 0;

    const info = document.createElement('div');
    info.className = 'entry-info';
    const title = document.createElement('span');
    title.className = 'entry-title';
    title.textContent = entry.title; // alltid textContent — aldrig innerHTML med användardata
    const sub = document.createElement('span');
    sub.className = 'entry-sub';
    sub.textContent = entry.username || entry.url || '';
    info.append(title, sub);

    const actions = document.createElement('div');
    actions.className = 'entry-actions';
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

    li.append(info, actions);
    li.addEventListener('click', () => openEntryDialog(entry.id));
    li.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' && ev.target === li) openEntryDialog(entry.id);
    });
    list.append(li);
  }

  const hint = $('empty-hint');
  if (matches.length === 0) {
    hint.textContent = state.entries.length === 0
      ? 'Inga poster ännu. Klicka på ”+ Ny post”.'
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

$('new-entry-btn').addEventListener('click', () => openEntryDialog(null));
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
// Start
init();
