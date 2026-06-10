// build.mjs — inlinar src/ till en enda fristående fil: dist/valv.html
// Inga npm-beroenden. Kör: node build.mjs
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(fileURLToPath(import.meta.url));
const src = (file) => readFile(path.join(root, 'src', file), 'utf8');

// CSP injiceras vid bygget i stället för att ligga i src/index.html —
// under utveckling refererar index.html externa filer (style.css, *.js)
// som en strikt CSP skulle blockera. Den färdiga filen är helt inline
// och får därför den hårdaste policy som fungerar för en inline-app.
const CSP =
  '<meta http-equiv="Content-Security-Policy" content="' +
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
  "img-src data:; base-uri 'none'; form-action 'none'" +
  '">';

let html = await src('index.html');
const css = await src('style.css');
// export-raden i crypto.js behövs bara när modulen importeras som ESM
// i Node-testerna; i webbläsaren blir funktionerna vanliga globaler.
const stripExport = (code) => code.replace(/^export\s*\{[\s\S]*?\};?\s*$/m, '');
const cryptoJs = stripExport(await src('crypto.js'));
const i18nJs = stripExport(await src('i18n.js'));
const seedJs = stripExport(await src('seed.js'));
const appJs = await src('app.js');

const replaceOnce = (haystack, needle, replacement) => {
  if (!haystack.includes(needle)) throw new Error(`build: hittar inte "${needle}" i index.html`);
  // replacer-funktion så att $-tecken i innehållet inte tolkas som referenser
  return haystack.replace(needle, () => replacement);
};

html = replaceOnce(html, '<link rel="stylesheet" href="style.css">', `<style>\n${css}</style>`);
html = replaceOnce(html, '<script src="crypto.js"></script>', `<script>\n${cryptoJs}</script>`);
html = replaceOnce(html, '<script src="i18n.js"></script>', `<script>\n${i18nJs}</script>`);
html = replaceOnce(html, '<script src="seed.js"></script>', `<script>\n${seedJs}</script>`);
html = replaceOnce(html, '<script src="app.js"></script>', `<script>\n${appJs}</script>`);
html = replaceOnce(html, '<!--BUILD:CSP-->', CSP);

// Validering: den färdiga filen får inte ha några externa referenser.
const problems = [];
if (/(?:src|href)\s*=\s*["']?https?:/i.test(html)) problems.push('extern http(s)-referens');
if (/<script[^>]*\ssrc\s*=/i.test(html)) problems.push('script-tagg med src kvar');
if (/<link(?![^>]*href="data:)[^>]*>/i.test(html)) problems.push('link-tagg med extern href kvar');
if (/^export\s/m.test(html)) problems.push('export-sats kvar i inlinead JS');
if (problems.length) {
  console.error('Bygget underkänt:', problems.join(', '));
  process.exit(1);
}

await mkdir(path.join(root, 'dist'), { recursive: true });
const outFile = path.join(root, 'dist', 'valv.html');
await writeFile(outFile, html);
console.log(`Skrev ${outFile} (${(Buffer.byteLength(html) / 1024).toFixed(1)} kB)`);
