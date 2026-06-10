# HANDOVER — sessionsöverlämning

> Levande dokument: skrivs över vid varje session, appendas inte.

## Nuläge (2026-06-10)

Projektet är **komplett enligt spec** och alla tester är gröna.

- `node build.mjs` → `dist/valv.html` (~39 kB), validerar inga externa referenser.
- `node test/roundtrip.mjs` → 8/8 gröna (kryptomodul + spara-simulering).
- `node test/e2e.mjs` → 22/22 gröna i riktig Chromium (kräver playwright-core,
  hoppas annars över): två fulla spara→öppna-generationer, fel lösenord,
  lås/upplås med osparade ändringar, sök, XSS-test, generator.

Implementerat: first-run, upplåsning, CRUD med bekräftad borttagning,
realtidssök, A–Ö-sortering, kopiera med 30 s urklippsrensning, generator
(8–64, teckentyper, rejection sampling), auto-lås 1–30 min (default 5),
manuellt lås, byt master-lösenord (verifieras mot krypterad kontrollsträng,
nytt salt), okrypterad export bakom varning, osparat-indikator,
beforeunload-varning, CSP, mörkt responsivt tema, svensk UI-text.

## Arkitekturbeslut värda att känna till

- **Spara-mekanismen:** `outerHTML` fångas EN gång vid skriptstart (orörd
  DOM) i `PRISTINE_SOURCE`; vid spara regex-byts innehållet i `#vault-data`.
  Läs kommentaren överst i `src/app.js` innan du rör detta.
- **Krypterad spegling till DOM:** vid skapande, spara och lås skrivs
  aktuell krypterad data till `#vault-data` i DOM:en, så att lås/upplås i
  samma session bevarar osparade ändringar. Dirty-flaggan överlever lås
  (filen på disk är ju fortfarande inaktuell).
- **Byt lösenord** verifierar nuvarande lösenord mot en krypterad
  kontrollsträng (`state.verifier`) som skapas i minnet vid upplåsning —
  inget lösenordsmaterial sparas någonsin.
- **crypto.js är dubbelmiljö** (browser + Node): bygget strippar
  ESM-export-raden. Ändra inte till `import`/`export` i mitten av filen.
- **CSP injiceras av build.mjs** (placeholder `<!--BUILD:CSP-->` i
  index.html) eftersom dev-källorna refererar varandra externt.
- I headless Chromium avvisar `showSaveFilePicker` med `AbortError`;
  e2e-testet tar därför bort API:t för att testa nedladdnings-fallbacken.

## Senaste commits

1. Skelett: src-struktur, build.mjs och tom fungerande valv.html
2. Kryptomodul med PBKDF2-SHA256 + AES-256-GCM samt Node-tester
3. Låsskärm, first-run, CRUD, sök och auto-lås
4. Spara-mekanism: komplett ny HTML-fil med round-trip-garanti
5. Generator, inställningar, byt master-lösenord och export
6. Dokumentation: README (hotmodell, checklista), HANDOVER, E2E-test

## Nästa steg (förslag, inget påbörjat)

- Manuell körning av README-checklistan i Firefox/Safari (E2E körs i
  Chromium; FS Access-vägen är bara manuellt testbar).
- Ev. import av tidigare exporterad JSON (motsats till exporten).
- Ev. höjning av PBKDF2-iterationer i framtiden — filformatets
  `iterations`-fält gör det bakåtkompatibelt; lägg då till omkryptering
  vid upplåsning av äldre valv.
- Ingen git-remote är konfigurerad; lägg till origin om repot ska pushas.
