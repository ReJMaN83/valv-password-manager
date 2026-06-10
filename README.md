[🇬🇧 English](README.md) | [🇸🇪 Svenska](README.sv.md)

# Valv

**Single-file encrypted password manager — the file is both the app and the vault.**

[![CI](https://github.com/ReJMaN83/valv-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/ReJMaN83/valv-password-manager/actions/workflows/ci.yml)

> 📸 *Screenshot/GIF placeholder — dark-mode main view with the entry list and seed phrase grid.*

`valv.html` is a complete password manager in one HTML file: the application
code and your encrypted data travel together. Double-click the file and it
runs — offline, from `file://`, in any modern browser.

## Why

- **Zero runtime dependencies.** No server, no browser extension, no CDN, no
  framework, no network requests — the only cryptography provider is the
  browser's built-in Web Crypto API.
- **Backup = copy the file.** Every copy is a complete encrypted vault. Put it
  on a USB stick, a cloud drive, an email to yourself — the contents stay
  encrypted wherever the file goes.
- **Nothing to install, nothing to trust but the file.** Auditable by opening
  it in a text editor: one HTML file, ~90 kB, readable source.

## Security model

| Aspect | Choice |
|---|---|
| Encryption | AES-256-GCM (authenticated encryption) |
| Key derivation | PBKDF2-SHA256, **600 000 iterations**, 16-byte random salt |
| Nonce | 12 bytes, freshly random **on every save** |
| Integrity | GCM tag — a wrong password or tampered data fails decryption cleanly; corrupt plaintext is never shown |
| Format versioning | The iteration count and format version are fields in the file, so they can be raised in future versions without breaking old vaults |

Plaintext never touches disk, `localStorage`, `sessionStorage`, IndexedDB or
cookies. Decrypted data lives only in JavaScript variables while the vault is
unlocked; the master password is never stored or logged anywhere. The only
unencrypted metadata in the file is the **UI language choice** — it has to be
readable before unlock so the lock screen can follow it, and which of two
languages you prefer reveals nothing about the vault's contents.

**Protects against:** someone obtaining the file (theft, leaked cloud
account, lost USB stick) — given a strong master password; tampering with the
encrypted data (GCM detects every change); network-based attacks (there is no
network activity, plus a strict Content Security Policy).

**Does not protect against:** malware on your device (keyloggers, memory
dumps), malicious browser extensions, someone modifying the *app code* in
your copy of the file (encryption protects the data, not the code), weak
master passwords, or a forgotten master password — **there is no recovery;
the data is gone.**

**Honest limitations:** JavaScript cannot guarantee memory wiping — strings
are immutable and garbage collection decides when memory is reclaimed, so a
process memory dump shortly after locking may in theory contain remnants.
Clipboard auto-clear requires the tab to be focused, and OS clipboard
history is outside the app's control. Seed phrases deserve extra caution:
unlike passwords they cannot be rotated after a leak — for significant
holdings keep the primary backup on paper or metal, offline, and treat Valv
as a complement.

## Features

- **Login entries** — title, username, password, URL, notes; copy buttons
  with **30-second clipboard auto-clear**.
- **Seed phrase entries (BIP39)** — 12/15/18/21/24 words in a numbered grid,
  paste-to-split a whole phrase, validation against the official English
  word list (warns, never blocks), optional passphrase and derivation path.
  Stored phrases open **masked**: the words are not even present in the DOM
  until you click Show. Search covers title and wallet — never the words.
- **Password generator** — length 8–64, character-class toggles,
  `crypto.getRandomValues` with rejection sampling (no modulo bias).
- **Auto-lock** after 1–30 minutes of inactivity (default 5), plus manual
  lock. Unsaved changes survive a lock — re-encrypted into the page.
- **Change master password** — verifies the current password, re-encrypts
  with a fresh salt.
- **Upgrade from file** — point a new app shell at your old `valv.html`,
  enter its master password, and the entries are brought in without any
  unencrypted data ever touching disk. JSON import/export also available
  (with a stern warning) for migration to/from other managers.
- **English and Swedish** UI, dark theme, responsive layout.

## Architecture

```
src/
  index.html   markup (English fallback text + data-i18n attributes)
  style.css    dark, minimal, responsive
  crypto.js    PBKDF2 + AES-GCM module — runs in browser AND Node
  i18n.js      all UI strings, { en, sv }
  seed.js      BIP39 word list + seed helpers — DOM-free, dual-environment
  app.js       application logic
build.mjs      inlines src/ into dist/valv.html, validates no external refs
test/
  roundtrip.mjs  crypto + format tests (plain Node, no dependencies)
  e2e.mjs        full browser verification (Playwright Chromium)
```

`node build.mjs` produces `dist/valv.html` and fails the build if any
external reference survives inlining. The dual-environment modules export
ESM for the Node tests; the build strips the export line for the browser.
`dist/` is not committed — grab it from a release or build it yourself.

### The self-serialization mechanism

The technically interesting part: how does a running page save *itself* with
new data? Valv captures `document.documentElement.outerHTML` **once, at
load time**, before the app has touched the DOM. Saving means replacing the
contents of the embedded `<script id="vault-data">` block in that pristine
string and writing the result to disk (File System Access API where
available, download fallback elsewhere).

Capturing at load — rather than at save time — matters: by save time the DOM
contains decrypted entries rendered in plaintext, which would otherwise be
serialized straight into the saved file. The snapshot contains only app code
and the encrypted block, and browser serialization is stable across
generations, which the E2E suite proves by saving and reopening the file
twice in a row.

## Testing

- **Node** (`npm test`): 13 tests — encrypt/decrypt round-trips at the full
  600 000 iterations, wrong-password and tamper rejection, nonce uniqueness,
  format versioning, BIP39 validation, backward compatibility with vaults
  from older versions, i18n key parity.
- **E2E** (`npm run test:e2e`): 55 checks in real Chromium — among them the
  project's core invariant: **a saved file, opened, must work identically
  and be able to save a working file in turn.** The suite runs two full
  save→reopen generations, plus seed phrase masking, upgrade-from-file,
  import/export and language round-trips.

## Getting started

1. Download `valv.html` from the [latest release](../../releases/latest)
   (attached as a release artifact — no build step needed), or build it
   yourself: `node build.mjs`.
2. Open the file in a browser (double-click).
3. Choose a master password — done.

On Chrome and Edge, **Save** overwrites the file in place via the File
System Access API. On Firefox and Safari the save arrives as a downloaded
`valv.html` — replace your old file with it; the download *is* your new
vault.

## Disclaimer

This is a hobby/portfolio project. The cryptographic design is conservative
(WebCrypto primitives only, authenticated encryption, high-iteration KDF),
but the code has **not** been independently audited. For critical needs,
use an established, audited password manager such as
[KeePassXC](https://keepassxc.org/) or [Bitwarden](https://bitwarden.com/).

## License

[MIT](LICENSE)
