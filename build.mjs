// build.mjs — inlines src/ into a single self-contained file: dist/valv.html
// No npm dependencies. Run: node build.mjs
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(fileURLToPath(import.meta.url));
const src = (file) => readFile(path.join(root, 'src', file), 'utf8');

// The CSP is injected at build time instead of living in src/index.html —
// during development index.html references external files (style.css, *.js)
// that a strict CSP would block. The finished file is fully inline and
// therefore gets the hardest policy that works for an inline app.
const CSP =
  '<meta http-equiv="Content-Security-Policy" content="' +
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
  "img-src data:; base-uri 'none'; form-action 'none'" +
  '">';

let html = await src('index.html');
const css = await src('style.css');
// The export line in the dual-environment modules is only needed when they
// are imported as ES modules by the Node tests; in the browser their
// declarations become plain globals.
const stripExport = (code) => code.replace(/^export\s*\{[\s\S]*?\};?\s*$/m, '');
const cryptoJs = stripExport(await src('crypto.js'));
const i18nJs = stripExport(await src('i18n.js'));
const seedJs = stripExport(await src('seed.js'));
const appJs = await src('app.js');

const replaceOnce = (haystack, needle, replacement) => {
  if (!haystack.includes(needle)) throw new Error(`build: cannot find "${needle}" in index.html`);
  // Replacer function so $ characters in the content are not interpreted
  // as special replacement patterns.
  return haystack.replace(needle, () => replacement);
};

html = replaceOnce(html, '<link rel="stylesheet" href="style.css">', `<style>\n${css}</style>`);
html = replaceOnce(html, '<script src="crypto.js"></script>', `<script>\n${cryptoJs}</script>`);
html = replaceOnce(html, '<script src="i18n.js"></script>', `<script>\n${i18nJs}</script>`);
html = replaceOnce(html, '<script src="seed.js"></script>', `<script>\n${seedJs}</script>`);
html = replaceOnce(html, '<script src="app.js"></script>', `<script>\n${appJs}</script>`);
html = replaceOnce(html, '<!--BUILD:CSP-->', CSP);

// Validation: the finished file must not contain any external references.
const problems = [];
if (/(?:src|href)\s*=\s*["']?https?:/i.test(html)) problems.push('external http(s) reference');
if (/<script[^>]*\ssrc\s*=/i.test(html)) problems.push('script tag with src remains');
if (/<link(?![^>]*href="data:)[^>]*>/i.test(html)) problems.push('link tag with external href remains');
if (/^export\s/m.test(html)) problems.push('export statement remains in inlined JS');
if (problems.length) {
  console.error('Build rejected:', problems.join(', '));
  process.exit(1);
}

await mkdir(path.join(root, 'dist'), { recursive: true });
const outFile = path.join(root, 'dist', 'valv.html');
await writeFile(outFile, html);
console.log(`Wrote ${outFile} (${(Buffer.byteLength(html) / 1024).toFixed(1)} kB)`);
