# Valv — project rules

Single-file encrypted password manager (`dist/valv.html`). The file contains
both the app code and the user's encrypted data.

## Hard requirements

- **The round-trip invariant (most important):** a file saved from the app
  must, when opened, work identically to the original and in turn be able to
  save a new working file. Verify this on every change to the save mechanism.
- **No runtime dependencies:** no CDN, fetch, frameworks or third-party
  libraries. Web Crypto API only. Must work offline via double-click
  (`file://`).
- **Crypto:** PBKDF2-SHA256 with 600 000 iterations (16 B random salt) →
  AES-256-GCM with a 12 B random nonce. **Fresh nonce on every encryption.**
  The iteration count is read from the file format (the `iterations` field),
  never hardcoded at decryption time.
- **Plaintext never touches disk:** no localStorage/sessionStorage/IndexedDB/
  cookies. Decrypted data lives only in JS variables. The master password is
  never stored, hashed to disk, or logged.
- **Code security:** no eval, no inline event handlers in HTML, user data is
  always rendered via `textContent` (never `innerHTML`), randomness always
  via `crypto.getRandomValues` (never `Math.random`).
- **File format** (script block `#vault-data`, JSON):
  `{"version":1,"kdf":"PBKDF2-SHA256","iterations":600000,"salt":b64,"nonce":b64,"ciphertext":b64,"lang":"en"}`
  An empty block ⇒ first-run mode. `lang` is deliberately unencrypted (the
  lock screen must be able to follow it before unlock); everything else the
  user enters stays inside the encrypted payload.

## i18n convention

- All user-facing strings live in `src/i18n.js` as `STRINGS = { en, sv }`.
  **Every new string must be added to BOTH locales** — the Node test suite
  fails if the key sets differ. English is the default language.
- Static markup carries English fallback text plus `data-i18n`
  (or `data-i18n-placeholder` / `data-i18n-title`) attributes; dynamic
  messages go through `t(key, ...args)`. Parameterized messages are
  functions in the strings table.
- No hardcoded user-facing strings in markup or app code.

## Structure & workflow

- Develop modularly in `src/` (index.html, style.css, crypto.js, i18n.js,
  seed.js, app.js); `node build.mjs` inlines everything into `dist/valv.html`
  and validates that no external references remain. `dist/` is gitignored —
  it is attached to GitHub releases instead.
- `crypto.js`, `i18n.js` and `seed.js` are dual-environment (browser + Node
  ≥ 19): the build strips the trailing ESM export line. Do not add
  import/export statements in the middle of those files.
- Run `npm test` (build + Node tests) before every commit; run
  `npm run test:e2e` (Playwright Chromium) when behavior changes.
- All code comments in English. Commit messages may be English or Swedish.
- `HANDOVER.md` is a local working file (gitignored) — overwrite it, never
  append.
