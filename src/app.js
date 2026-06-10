// app.js — Valv application logic
'use strict';

// ============================================================
// Pristine source — the foundation of the save mechanism
//
// We read document.documentElement.outerHTML ONCE, as soon as this script
// executes. The scripts sit at the end of <body>, so the whole document is
// parsed but the app has not yet touched the DOM. This is the most robust
// approach:
//
//  - Reading outerHTML at save time would be dangerous: by then the DOM
//    contains rendered entries in PLAINTEXT (the list, open dialogs) that
//    would be serialized into the saved file.
//  - Carrying the source in a separate template would duplicate the whole
//    app inside the file and risk template and code drifting apart.
//
// The snapshot taken at load contains only app code + the encrypted vault
// block. Browser serialization is stable: a saved file that is opened and
// saved again produces the same result (the round-trip invariant).
// outerHTML does not include the doctype, so it is added manually.
const PRISTINE_SOURCE = '<!DOCTYPE html>\n' + document.documentElement.outerHTML;

// Matches the vault block in the source. Written with <\/script> so that
// the app code itself never contains a literal closing script tag (which
// would terminate the inline script in the built file).
const VAULT_BLOCK_RE =
  /(<script id="vault-data" type="application\/json">)([\s\S]*?)(<\/script>)/;

const $ = (id) => document.getElementById(id);

// ============================================================
// Language
//
// Sensitivity trade-off, documented on purpose: the language choice is
// stored UNENCRYPTED in the vault block (the `lang` field), unlike every
// other setting. It has to be readable before unlock so that the lock
// screen itself appears in the user's language, and which of two languages
// someone prefers reveals nothing about the vault's contents. Everything
// the user actually types (entries, auto-lock minutes, etc.) stays inside
// the encrypted payload.
let lang = 'en';

function t(key, ...args) {
  const table = STRINGS[lang] || STRINGS.en;
  const value = key in table ? table[key] : STRINGS.en[key];
  return typeof value === 'function' ? value(...args) : value;
}

// Static markup carries English text as fallback; elements tagged with
// data-i18n / data-i18n-placeholder / data-i18n-title are retranslated here.
function applyLanguage() {
  document.documentElement.lang = lang;
  for (const el of document.querySelectorAll('[data-i18n]')) {
    el.textContent = t(el.dataset.i18n);
  }
  for (const el of document.querySelectorAll('[data-i18n-placeholder]')) {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  }
  for (const el of document.querySelectorAll('[data-i18n-title]')) {
    el.title = t(el.dataset.i18nTitle);
  }
  if (state.entries) renderList(); // list rows contain translated buttons
}

// ============================================================
// State
//
// Everything decrypted lives ONLY here, in memory. Never localStorage,
// sessionStorage, IndexedDB, cookies or disk.
const state = {
  key: null,        // CryptoKey (AES-GCM), non-extractable
  salt: null,       // Uint8Array
  iterations: KDF_ITERATIONS_DEFAULT,
  entries: null,    // null = locked
  settings: { autoLockMinutes: 5 },
  verifier: null,   // encrypted check string, used by "change password"
  fileHandle: null, // File System Access handle, reused between saves
  editingId: null,
  clipboardTimer: null,
  autoLockTimer: null,
};

// "dirty" = the file on disk is stale. The flag survives lock/unlock (it
// reveals nothing sensitive) so the indicator stays correct even after an
// auto-lock before the user managed to save.
let dirty = false;

function setDirty(value) {
  dirty = value;
  $('dirty-indicator').classList.toggle('hidden', !dirty);
}
const markDirty = () => setDirty(true);

// ============================================================
// Small helpers: toast and confirmation dialog
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

function confirmDialog(message, okLabel) {
  return new Promise((resolve) => {
    $('confirm-message').textContent = message;
    $('confirm-ok').textContent = okLabel || t('ok');
    confirmAnswer = false;
    const dlg = $('confirm-dialog');
    dlg.addEventListener('close', () => resolve(confirmAnswer), { once: true });
    dlg.showModal();
  });
}

// ============================================================
// The vault block in the DOM
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
  // encryptWithKey generates a NEW random nonce on every call
  const { nonce, ciphertext } = await encryptWithKey(state.key, payload);
  return JSON.stringify({
    version: 1,
    kdf: 'PBKDF2-SHA256',
    iterations: state.iterations,
    salt: toBase64(state.salt),
    nonce,
    ciphertext,
    // Unencrypted on purpose — see the language comment at the top.
    lang,
  });
}

// Mirrors the current (encrypted) data into the DOM block. Lock/unlock
// within the same session therefore always uses the latest data — even
// changes not yet written to disk survive an (auto-)lock, encrypted.
async function updateLiveVaultBlock() {
  const json = await currentVaultJson();
  $('vault-data').textContent = json;
  return json;
}

// ============================================================
// Lock screen: unlock and first run
function init() {
  const blob = readVaultBlock();
  if (blob && STRINGS[blob.lang]) lang = blob.lang;
  applyLanguage();
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
  btn.textContent = t('lockUnlocking');
  $('unlock-error').classList.add('hidden');
  try {
    const salt = fromBase64(blob.salt);
    const key = await deriveKey(password, salt, blob.iterations);
    const payload = JSON.parse(await decryptWithKey(key, blob.nonce, blob.ciphertext));
    $('unlock-password').value = '';
    await openVault(key, salt, blob.iterations, payload);
  } catch {
    // The GCM tag did not validate => wrong password. No corrupt data shown.
    $('unlock-error').classList.remove('hidden');
    $('unlock-password').select();
  } finally {
    btn.disabled = false;
    btn.textContent = t('lockUnlock');
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
  return { score, label: t('strengthLabels')[score] };
}

$('create-password').addEventListener('input', () => {
  const { score, label } = passwordStrength($('create-password').value);
  const bar = $('strength-bar');
  bar.style.width = (score * 25) + '%';
  bar.dataset.score = score;
  $('strength-label').textContent = label || ' ';
});

$('create-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = $('create-password').value;
  const repeated = $('create-password2').value;
  const errorBox = $('create-error');
  const fail = (message) => { errorBox.textContent = message; errorBox.classList.remove('hidden'); };
  if (password.length < 8) return fail(t('createTooShort'));
  if (password !== repeated) return fail(t('createMismatch'));
  errorBox.classList.add('hidden');
  const btn = $('create-btn');
  btn.disabled = true;
  btn.textContent = t('createBusy');
  try {
    const salt = randomBytes(SALT_BYTES);
    const key = await deriveKey(password, salt, KDF_ITERATIONS_DEFAULT);
    $('create-password').value = '';
    $('create-password2').value = '';
    $('strength-bar').style.width = '0';
    $('strength-label').textContent = ' ';
    await openVault(key, salt, KDF_ITERATIONS_DEFAULT, { entries: [], meta: {} });
    await updateLiveVaultBlock(); // makes lock/unlock work even before the first save
    setDirty(true);
    toast(t('toastCreated'));
  } finally {
    btn.disabled = false;
    btn.textContent = t('createButton');
  }
});

async function openVault(key, salt, iterations, payload) {
  state.key = key;
  state.salt = salt;
  state.iterations = iterations;
  // normalizeEntry gives entries from older vaults (no type field) type "login"
  state.entries = (Array.isArray(payload.entries) ? payload.entries : []).map(normalizeEntry);
  state.settings = Object.assign({ autoLockMinutes: 5 }, payload.meta && payload.meta.settings);
  // Encrypted check string: lets "change password" verify the current
  // password without the password, or any hash of it, being stored anywhere.
  state.verifier = await encryptWithKey(key, 'valv-verifier');
  $('lock-screen').classList.add('hidden');
  $('main-screen').classList.remove('hidden');
  $('search').value = '';
  renderList();
  resetAutoLock();
}

// ============================================================
// Lock and auto-lock
async function lock() {
  if (!state.key) return;
  // Preserve the latest changes (encrypted) in the DOM block before
  // clearing memory.
  if (dirty) await updateLiveVaultBlock();
  // Best-effort zeroing: references are dropped so GC can reclaim them.
  // JavaScript strings are immutable and cannot be overwritten in place —
  // see README for the limitations. The CryptoKey is non-extractable and
  // disappears with GC.
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
    toast(t('toastAutoLocked'));
  }, minutes * 60000);
}

let lastActivity = 0;
function onActivity() {
  const now = Date.now();
  if (now - lastActivity < 5000) return; // throttle: don't restart the timer per pixel
  lastActivity = now;
  resetAutoLock();
}
for (const eventName of ['pointermove', 'pointerdown', 'keydown', 'scroll', 'touchstart']) {
  document.addEventListener(eventName, onActivity, { passive: true });
}

// ============================================================
// Clipboard with automatic clearing
async function copySecret(text, what, message) {
  if (!text) { toast(t('nothingToCopy')); return; }
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast(t('clipboardUnavailable'));
    return;
  }
  clearTimeout(state.clipboardTimer);
  state.clipboardTimer = setTimeout(clearClipboard, 30000);
  toast(message || t('copiedMessage', what));
}

async function clearClipboard() {
  state.clipboardTimer = null;
  try {
    await navigator.clipboard.writeText('');
    toast(t('clipboardCleared'));
  } catch {
    // the document may lack focus — clearing is best effort
  }
}

// ============================================================
// List and search
function renderList() {
  const query = $('search').value.trim().toLowerCase();
  const list = $('entry-list');
  list.textContent = '';
  if (!state.entries) return;
  // The search index for seed entries is title + wallet — NEVER the words.
  const matchesQuery = (e) => {
    if (!query) return true;
    const haystacks = e.type === 'seed'
      ? [e.title, e.wallet]
      : [e.title, e.username, e.url];
    return haystacks.some((value) => (value || '').toLowerCase().includes(query));
  };
  const matches = state.entries
    .filter(matchesQuery)
    .sort((a, b) => (a.title || '').localeCompare(b.title || '', lang, { sensitivity: 'base' }));

  for (const entry of matches) {
    const li = document.createElement('li');
    li.tabIndex = 0;
    const isSeed = entry.type === 'seed';

    const info = document.createElement('div');
    info.className = 'entry-info';
    const title = document.createElement('span');
    title.className = 'entry-title';
    title.textContent = entry.title; // always textContent — never innerHTML with user data
    const sub = document.createElement('span');
    sub.className = 'entry-sub';
    sub.textContent = isSeed ? (entry.wallet || '') : (entry.username || entry.url || '');
    info.append(title, sub);

    const actions = document.createElement('div');
    actions.className = 'entry-actions';
    if (isSeed) {
      // Deliberately no copy buttons in the list for seed entries: a whole
      // phrase should not end up in the clipboard on a misclick. Badge instead.
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = '🌱 SEED';
      actions.append(badge);
    } else {
      actions.append(
        makeButton(t('listCopyUser'), t('copyUserTitle'), (ev) => {
          ev.stopPropagation();
          copySecret(entry.username, t('usernameWord'));
        }),
        makeButton(t('listCopyPassword'), t('copyPasswordTitle'), (ev) => {
          ev.stopPropagation();
          copySecret(entry.password, t('passwordWord'));
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
    hint.textContent = state.entries.length === 0 ? t('emptyNone') : t('emptyNoMatches');
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
// Entry dialog: create, edit, delete (logins)
const ENTRY_FIELDS = ['entry-title', 'entry-username', 'entry-password', 'entry-url', 'entry-notes'];

function openEntryDialog(id) {
  state.editingId = id || null;
  const entry = id ? state.entries.find((e) => e.id === id) : null;
  $('entry-dialog-title').textContent = entry ? t('entryTitleEdit') : t('entryTitleNew');
  $('entry-title').value = entry ? entry.title : '';
  $('entry-username').value = entry ? entry.username : '';
  $('entry-password').value = entry ? entry.password : '';
  $('entry-password').type = 'password';
  $('entry-toggle-password').textContent = t('show');
  $('entry-url').value = entry ? entry.url : '';
  $('entry-notes').value = entry ? entry.notes : '';
  $('entry-delete').classList.toggle('hidden', !entry);
  $('entry-dialog').showModal();
  $('entry-title').focus();
}

$('new-login-btn').addEventListener('click', () => openEntryDialog(null));
$('new-seed-btn').addEventListener('click', () => openSeedDialog(null));
$('entry-cancel').addEventListener('click', () => $('entry-dialog').close());

// Clear the fields even when the dialog is closed with Escape, so that
// passwords do not linger in the DOM.
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
    state.entries.push({ id: crypto.randomUUID(), type: 'login', ...values, created: now, modified: now });
  }
  markDirty();
  $('entry-dialog').close();
  renderList();
});

$('entry-delete').addEventListener('click', async () => {
  const entry = state.entries && state.entries.find((e) => e.id === state.editingId);
  if (!entry) return;
  if (!(await confirmDialog(t('deleteEntryConfirm', entry.title), t('deleteBtn')))) return;
  state.entries = state.entries.filter((e) => e.id !== entry.id);
  markDirty();
  $('entry-dialog').close();
  renderList();
});

$('entry-toggle-password').addEventListener('click', () => {
  const field = $('entry-password');
  const show = field.type === 'password';
  field.type = show ? 'text' : 'password';
  $('entry-toggle-password').textContent = show ? t('hide') : t('show');
});

$('entry-copy-username').addEventListener('click', () => {
  copySecret($('entry-username').value, t('usernameWord'));
});
$('entry-copy-password').addEventListener('click', () => {
  copySecret($('entry-password').value, t('passwordWord'));
});

// ============================================================
// Seed entries
//
// Security model for the words: when a saved seed entry is opened, the word
// fields are EMPTY (value = '') with "•••••" as placeholder and readonly —
// the real words are not in the DOM until the user clicks Show. Hiding
// empties the fields again. If the entry is saved without the words ever
// having been shown, the already-stored words are kept unchanged.
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
    num.textContent = String(i + 1); // the numbering is the whole point — order must be visible
    const input = document.createElement('input');
    input.type = 'text';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.setAttribute('autocapitalize', 'none');
    input.setAttribute('aria-label', t('wordAria', i + 1));
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
    warning.textContent = t('seedUnknownWords', unknown);
    warning.classList.remove('hidden');
  } else {
    warning.classList.add('hidden');
  }
}

function openSeedDialog(id) {
  seedEditingId = id || null;
  const entry = id ? state.entries.find((e) => e.id === id) : null;
  $('seed-dialog-title').textContent = entry ? t('seedTitleView') : t('seedTitleNew');
  $('seed-title').value = entry ? entry.title : '';
  $('seed-wallet').value = entry ? entry.wallet || '' : '';
  $('seed-passphrase').value = entry ? entry.passphrase || '' : '';
  $('seed-passphrase').type = 'password';
  $('seed-toggle-passphrase').textContent = t('show');
  $('seed-derivation').value = entry ? entry.derivation || '' : '';
  $('seed-notes').value = entry ? entry.notes || '' : '';
  $('seed-delete').classList.toggle('hidden', !entry);
  $('seed-warning').classList.add('hidden');
  // new entry: type the words right away; existing: hidden until Show
  seedWordsShown = !entry;
  $('seed-toggle').classList.toggle('hidden', !entry);
  $('seed-toggle').textContent = t('show');
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
    $('seed-toggle').textContent = t('hide');
    $('seed-count').value = String(entry.words.length);
    $('seed-count').disabled = false;
    $('seed-paste-hint').classList.remove('hidden');
    validateSeedWords();
  } else {
    // Hide: back to placeholders — any word edits in the fields are discarded
    buildSeedGrid(entry.words.length, true);
    seedWordsShown = false;
    $('seed-toggle').textContent = t('show');
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

// Paste a whole phrase into any word field => split and fill all fields.
$('seed-grid').addEventListener('paste', (event) => {
  if (!event.target.matches('input') || event.target.readOnly) return;
  const words = parseSeedPhrase((event.clipboardData || window.clipboardData).getData('text'));
  if (words.length < 2) return; // a single word pastes as usual
  event.preventDefault();
  if (isValidSeedWordCount(words.length)) {
    $('seed-count').value = String(words.length);
    buildSeedGrid(words.length, false);
  } else {
    toast(t('seedInvalidCount', words.length));
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
      warning.textContent = t('seedFillAll');
      warning.classList.remove('hidden');
      return;
    }
  } else {
    words = existing.words; // the words were never shown — keep the stored ones
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

// Clear everything on close (including Escape) so no words remain in the DOM.
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
  if (!(await confirmDialog(t('seedDeleteConfirm', entry.title), t('deleteBtn')))) return;
  state.entries = state.entries.filter((e) => e.id !== entry.id);
  markDirty();
  $('seed-dialog').close();
  renderList();
});

$('seed-toggle-passphrase').addEventListener('click', () => {
  const field = $('seed-passphrase');
  const show = field.type === 'password';
  field.type = show ? 'text' : 'password';
  $('seed-toggle-passphrase').textContent = show ? t('hide') : t('show');
});

$('seed-copy').addEventListener('click', () => {
  let words;
  if (seedWordsShown) {
    words = seedWordInputs().map((input) => input.value.trim().toLowerCase()).filter(Boolean);
  } else {
    const entry = state.entries && state.entries.find((e) => e.id === seedEditingId);
    words = entry ? entry.words : [];
  }
  if (!words.length) { toast(t('seedNoWords')); return; }
  copySecret(words.join(' '), t('seedPhraseWord'), t('seedClipboardWarning'));
});

// ============================================================
// Save: build a complete new HTML file and write it to disk
function buildSavedHtml(vaultJson) {
  if (!VAULT_BLOCK_RE.test(PRISTINE_SOURCE)) {
    throw new Error('vault-data block missing from source');
  }
  // Replacer function so that $ characters in the JSON are not interpreted
  // as special replacement patterns by String.prototype.replace.
  return PRISTINE_SOURCE.replace(VAULT_BLOCK_RE, (_m, open, _old, close) => open + vaultJson + close);
}

async function saveVault() {
  if (!state.key) return;
  const vaultJson = await updateLiveVaultBlock();
  const html = buildSavedHtml(vaultJson);

  // Primary: File System Access API — can overwrite the file in place.
  // The handle is reused so subsequent saves don't ask again.
  if (window.showSaveFilePicker) {
    try {
      if (!state.fileHandle) {
        state.fileHandle = await window.showSaveFilePicker({
          suggestedName: 'valv.html',
          types: [{ description: 'HTML file', accept: { 'text/html': ['.html'] } }],
        });
      }
      const writable = await state.fileHandle.createWritable();
      await writable.write(html);
      await writable.close();
      setDirty(false);
      toast(t('toastSaved'));
      return;
    } catch (err) {
      if (err && err.name === 'AbortError') {
        toast(t('toastSaveAborted'));
        return; // the user changed their mind — still unsaved
      }
      // The handle may have become invalid (file moved/deleted) or the API
      // blocked — drop the handle and fall back to download.
      state.fileHandle = null;
    }
  }

  // Fallback: Blob + download link.
  downloadFile('valv.html', html, 'text/html');
  setDirty(false);
  toast(t('toastDownloaded'));
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

// Warn if the window is closed with unsaved changes.
window.addEventListener('beforeunload', (event) => {
  if (dirty) {
    event.preventDefault();
    event.returnValue = '';
  }
});

// ============================================================
// Password generator
const GEN_SETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!#$%&()*+,-./:;<=>?@[]^_{|}~',
};

// Randomness only via crypto.getRandomValues, with rejection sampling so the
// modulo operation does not bias some characters over others.
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
  if (!pool) toast(t('genPickOne'));
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
$('gen-copy').addEventListener('click', () => copySecret($('gen-output').value, t('passwordWord')));
$('gen-use').addEventListener('click', () => {
  $('entry-password').value = $('gen-output').value;
  $('generator-dialog').close();
});
$('gen-close').addEventListener('click', () => $('generator-dialog').close());
$('generator-dialog').addEventListener('close', () => { $('gen-output').value = ''; });

// ============================================================
// Settings: language, auto-lock, change master password, export
$('settings-btn').addEventListener('click', () => {
  $('language-select').value = lang;
  $('autolock-minutes').value = state.settings.autoLockMinutes;
  $('cp-message').classList.add('hidden');
  $('settings-dialog').showModal();
});
$('settings-close').addEventListener('click', () => $('settings-dialog').close());
$('settings-dialog').addEventListener('close', () => {
  for (const id of ['cp-current', 'cp-new', 'cp-new2']) $(id).value = '';
});

$('language-select').addEventListener('change', () => {
  const chosen = $('language-select').value;
  if (!STRINGS[chosen] || chosen === lang) return;
  lang = chosen;
  applyLanguage();
  // The choice is persisted in the vault block on save — mark as unsaved.
  markDirty();
});

$('autolock-minutes').addEventListener('change', () => {
  const minutes = Math.min(30, Math.max(1, Number($('autolock-minutes').value) || 5));
  $('autolock-minutes').value = minutes;
  if (minutes !== state.settings.autoLockMinutes) {
    state.settings.autoLockMinutes = minutes;
    markDirty();
    resetAutoLock();
    toast(t('setAutoLockToast', minutes));
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
  if (next.length < 8) return show(t('cpTooShort'), true);
  if (next !== $('cp-new2').value) return show(t('cpMismatch'), true);

  const btn = $('cp-submit');
  btn.disabled = true;
  btn.textContent = t('setChanging');
  try {
    // Verify the current password against the encrypted check string.
    try {
      const candidate = await deriveKey(current, state.salt, state.iterations);
      await decryptWithKey(candidate, state.verifier.nonce, state.verifier.ciphertext);
    } catch {
      return show(t('cpWrongCurrent'), true);
    }
    // Re-encrypt with a NEW salt and today's default iteration count.
    const salt = randomBytes(SALT_BYTES);
    const key = await deriveKey(next, salt, KDF_ITERATIONS_DEFAULT);
    state.salt = salt;
    state.key = key;
    state.iterations = KDF_ITERATIONS_DEFAULT;
    state.verifier = await encryptWithKey(key, 'valv-verifier');
    await updateLiveVaultBlock();
    markDirty();
    for (const id of ['cp-current', 'cp-new', 'cp-new2']) $(id).value = '';
    show(t('cpChanged'), false);
  } finally {
    btn.disabled = false;
    btn.textContent = t('setChangeBtn');
  }
});

$('export-btn').addEventListener('click', async () => {
  const hasSeeds = state.entries.some((e) => e.type === 'seed');
  const ok = await confirmDialog(hasSeeds ? t('expWarningSeeds') : t('expWarning'), t('expOk'));
  if (!ok) return;
  const json = JSON.stringify(
    { entries: state.entries, meta: { exported: new Date().toISOString() } },
    null, 2);
  downloadFile('valv-export.json', json, 'application/json');
});

// ============================================================
// Upgrade and import
//
// Two ways into a new (empty) app shell:
//  A) Import JSON — reads the unencrypted export.
//  B) Upgrade from file — reads the #vault-data block from an older
//     valv.html and decrypts it with THAT file's master password.
//     The data stays encrypted all the way into memory; no unencrypted
//     file ever needs to touch disk. This is why B is recommended in the UI.
// The old file is read as TEXT only (regex + JSON.parse) — its HTML and
// scripts are never rendered or executed.

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

// Validates that a chosen file is a vault file and extracts the encrypted block.
function parseVaultFile(html) {
  const match = html.match(VAULT_BLOCK_RE);
  if (!match) return { error: t('upErrNotVault') };
  const text = match[2].trim();
  if (!text) return { error: t('upErrEmpty') };
  let blob;
  try { blob = JSON.parse(text); } catch { return { error: t('upErrCorrupt') }; }
  if (blob.version !== 1) {
    return { error: t('upErrVersion', blob.version ?? '?') };
  }
  if (blob.kdf !== 'PBKDF2-SHA256' || !Number.isInteger(blob.iterations)
      || !blob.salt || !blob.nonce || !blob.ciphertext) {
    return { error: t('upErrIncomplete') };
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

// Shared intake path for A and B: normalize, ask merge/replace, bring in.
async function takeInEntries(rawEntries) {
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
    toast(t('mergeNoEntries'));
    return;
  }
  let message = t('mergeMessage', incoming.length, state.entries.length);
  if (skipped > 0) message += t('mergeSkippedSuffix', skipped);
  const mode = await chooseMergeMode(message);
  if (!mode) return;
  if (mode === 'replace') {
    if (state.entries.length > 0) {
      const ok = await confirmDialog(t('mergeReplaceConfirm', state.entries.length), t('mergeReplaceOk'));
      if (!ok) return;
    }
    state.entries = incoming;
  } else {
    const existingIds = new Set(state.entries.map((e) => e.id));
    for (const entry of incoming) {
      // id collision (e.g. the same export brought in twice): keep both
      // entries under a new id — never silent data loss.
      if (existingIds.has(entry.id)) entry.id = crypto.randomUUID();
      state.entries.push(entry);
    }
  }
  markDirty();
  renderList();
  $('settings-dialog').close();
  toast(t('mergeTakenIn', incoming.length, mode === 'replace'));
}

// A) Import an unencrypted JSON export
$('import-btn').addEventListener('click', async () => {
  const file = await pickFile('.json,application/json');
  if (!file) return;
  let data;
  try { data = JSON.parse(await file.text()); } catch { toast(t('impInvalidJson')); return; }
  if (!data || typeof data !== 'object' || !Array.isArray(data.entries)) {
    toast(t('impNotExport'));
    return;
  }
  await takeInEntries(data.entries);
});

// B) Upgrade from an older valv.html
let upgradeBlob = null;

$('upgrade-btn').addEventListener('click', async () => {
  const file = await pickFile('.html,text/html');
  if (!file) return;
  const parsed = parseVaultFile(await file.text());
  if (parsed.error) { toast(parsed.error); return; }
  upgradeBlob = parsed.blob;
  $('upgrade-filename').textContent = t('upFileLabel', file.name);
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
  btn.textContent = t('upDecrypting');
  try {
    const key = await deriveKey(password, fromBase64(upgradeBlob.salt), upgradeBlob.iterations);
    const payload = JSON.parse(await decryptWithKey(key, upgradeBlob.nonce, upgradeBlob.ciphertext));
    $('upgrade-dialog').close();
    await takeInEntries(Array.isArray(payload.entries) ? payload.entries : []);
  } catch {
    $('upgrade-error').textContent = t('upWrongPassword');
    $('upgrade-error').classList.remove('hidden');
    $('upgrade-password').select();
  } finally {
    btn.disabled = false;
    btn.textContent = t('upUnlockBtn');
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
