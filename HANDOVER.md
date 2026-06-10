# HANDOVER — sessionsöverlämning

> Levande dokument: skrivs över vid varje session, appendas inte.

## Nuläge (2026-06-10)

Grundappen + **seed-frasposter** är klara enligt spec, alla tester gröna.

- `node build.mjs` → `dist/valv.html` (~66 kB, varav ~14 kB BIP39-lista).
- `node test/roundtrip.mjs` → 12/12 gröna (krypto, seed-round-trip,
  bakåtkompatibilitet, paste-splitting, BIP39-validering).
- `node test/e2e.mjs` → 34/34 gröna i riktig Chromium (kräver
  playwright-core, hoppas annars över): två fulla spara→öppna-generationer
  inkl. seed-post (paste-skapande, dold som default, Visa ger rätt
  ordning, orden aldrig i DOM före Visa, aldrig i klartext i filen).

## Posttyper

`entry.type`: `"login"` (default) | `"seed"`. Poster utan `type` (valv
från äldre version) normaliseras till login av `normalizeEntry` vid
upplåsning — testat utan dataförlust över öppna→spara→öppna.

Seed-fält: `wallet`, `words` (12/15/18/21/24 st), `passphrase`,
`derivation`, `notes`.

## Arkitekturbeslut värda att känna till

- **Spara-mekanismen:** `outerHTML` fångas EN gång vid skriptstart i
  `PRISTINE_SOURCE`; vid spara regex-byts innehållet i `#vault-data`.
  Läs kommentaren överst i `src/app.js` innan du rör detta.
- **Seed-maskering:** sparade seed-poster öppnas med TOMMA ordfält
  (placeholder `•••••`, readonly) — orden läggs i DOM:en först vid Visa
  och töms vid Dölj/stängning. Sparas posten utan att orden visats
  behålls de redan sparade orden (`seedWordsShown`-flaggan i app.js).
- **Sökindexet** för seed-poster är endast titel + wallet, aldrig orden.
  Inga kopieringsknappar för seed i listvyn (medvetet — inget felklick
  ska lägga frasen i urklipp).
- **BIP39-listan** ligger i `src/seed.js` (DOM-fri dubbelmiljömodul som
  crypto.js), genererad från officiella bitcoin/bips english.txt,
  SHA256 2f5eed53…dbda, verifierad ord-för-ord vid genereringen.
  Validering varnar bara — blockerar aldrig sparande.
- **E2E-testfrasen är medvetet inte alfabetisk**: BIP39-listan ligger
  alfabetiskt i appkoden, så en alfabetisk fras vore en substring av
  filen och klartextkontrollerna bleve meningslösa.
- **Krypterad spegling till DOM** (`#vault-data`) vid skapa/spara/lås gör
  att osparade ändringar överlever lås/upplås; dirty-flaggan överlever
  också. CSP injiceras av build.mjs. `crypto.js`/`seed.js` är dubbelmiljö —
  bygget strippar ESM-export-raden; inga import/export mitt i filerna.
- I headless Chromium avvisar `showSaveFilePicker` med `AbortError`;
  e2e tar bort API:t för att testa nedladdnings-fallbacken.

## Senaste commits

1. Skelett: src-struktur, build.mjs och tom fungerande valv.html
2. Kryptomodul med PBKDF2-SHA256 + AES-256-GCM samt Node-tester
3. Låsskärm, first-run, CRUD, sök och auto-lås
4. Spara-mekanism: komplett ny HTML-fil med round-trip-garanti
5. Generator, inställningar, byt master-lösenord och export
6. Dokumentation: README (hotmodell, checklista), HANDOVER, E2E-test
7. Seed-datamodell: BIP39-ordlista, hjälpfunktioner och Node-tester
8. Seed-UI: numrerad ordgrid, maskering, paste-splitting och badge
9. Seed: E2E-tester och uppdaterad hotmodell i README

## Nästa steg (förslag, inget påbörjat)

- Manuell körning av README-checklistan i Firefox/Safari (E2E körs i
  Chromium; FS Access-vägen är bara manuellt testbar).
- Ev. import av exporterad JSON (motsats till exporten).
- Ev. BIP39-checksumvalidering av hela frasen (sista ordet innehåller
  checksumbitar) — kräver SHA-256 över entropin, görbart med WebCrypto;
  i dag valideras bara ord-för-ord mot listan.
- Ingen git-remote är konfigurerad; lägg till origin om repot ska pushas.
