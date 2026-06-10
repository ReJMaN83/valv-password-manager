# Valv — statiska regler

Fristående krypterad lösenordshanterare i EN HTML-fil (`dist/valv.html`).
Filen innehåller både appkoden och användarens krypterade data.

## Orubbliga krav

- **Round-trip-invarianten (viktigast):** en fil som sparas från appen måste,
  när den öppnas, fungera identiskt med originalet och i sin tur kunna spara
  en ny fungerande fil. Verifiera detta vid varje ändring av spara-mekanismen.
- **Inga externa beroenden i runtime:** inga CDN, fetch, ramverk eller
  tredjepartsbibliotek. Endast Web Crypto API. Måste fungera offline via
  dubbelklick (`file://`).
- **Krypto:** PBKDF2-SHA256 med 600 000 iterationer (16 B slumpat salt) →
  AES-256-GCM med 12 B slumpad nonce. **Ny nonce vid varje kryptering.**
  Iterationsantalet läses ur filformatet (fältet `iterations`), aldrig
  hårdkodat vid dekryptering.
- **Klartext aldrig till disk:** ingen localStorage/sessionStorage/IndexedDB/
  cookies. Dekrypterad data lever endast i JS-variabler. Master-lösenordet
  sparas/hashas/loggas aldrig.
- **Säkerhet i koden:** ingen eval, inga inline event-handlers i HTML,
  användardata renderas alltid via `textContent` (aldrig `innerHTML`),
  slump alltid via `crypto.getRandomValues` (aldrig `Math.random`).
- **Filformat** (script-block `#vault-data`, JSON):
  `{"version":1,"kdf":"PBKDF2-SHA256","iterations":600000,"salt":b64,"nonce":b64,"ciphertext":b64}`
  Tomt block ⇒ first-run-läge.

## Struktur & arbetsflöde

- Utveckla modulärt i `src/` (index.html, style.css, crypto.js, app.js);
  `node build.mjs` inlinar till `dist/valv.html` och validerar att inga
  externa referenser finns. `dist/` är gitignorad.
- `crypto.js` ska kunna köras både i webbläsare och Node ≥ 19
  (ESM-exporten på sista raden strippas av bygget).
- Kör `node build.mjs && node test/roundtrip.mjs` innan varje commit.
- All UI-text på svenska. Mörkt tema är default.
- `HANDOVER.md` är levande sessionsöverlämning — skriv över den, appenda inte.
