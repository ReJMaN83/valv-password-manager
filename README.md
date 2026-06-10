# Valv

En fristående, krypterad lösenordshanterare i **en enda HTML-fil**.
Filen `valv.html` innehåller både hela applikationen och din krypterade
data. Ingen server, inga konton, inga externa beroenden — den fungerar
offline genom att du dubbelklickar på filen.

## Hur den fungerar

- Din data krypteras med **AES-256-GCM**. Nyckeln härleds från ditt
  master-lösenord med **PBKDF2-SHA256 och 600 000 iterationer** (slumpat salt).
- Vid varje sparning krypteras allt om med en ny slumpad nonce, och appen
  bygger en komplett ny HTML-fil med den nya krypterade datan inbäddad.
- Allt dekrypterat lever **endast i minnet** medan valvet är upplåst.
  Ingenting skrivs någonsin i klartext till disk, localStorage, cookies
  eller liknande. Master-lösenordet sparas aldrig någonstans.
- Fel lösenord ger alltid ett tydligt fel (GCM-taggen validerar inte) —
  aldrig korrupt data.

## Användning

1. Öppna `valv.html` i en modern webbläsare (dubbelklicka på filen).
2. **Första gången:** välj ett master-lösenord (minst 8 tecken) och klicka
   *Skapa valv*. Klicka sedan **Spara** för att skriva valvet till fil.
3. **Därefter:** skriv ditt master-lösenord och tryck Enter.
4. Lägg till poster med *+ Ny post*. Sök i realtid, kopiera användarnamn
   och lösenord med knapparna (urklippet rensas automatiskt efter 30 s).
5. Klicka **Spara** efter ändringar:
   - I Chrome/Edge kan filen skrivas över direkt (File System Access API).
   - I Firefox/Safari laddas en ny `valv.html` ner — **ersätt din gamla
     fil med den nya**. Den nedladdade filen är ditt nya valv.
6. Indikatorn *● osparat* visas tills ändringarna har sparats till fil,
   och webbläsaren varnar om du försöker stänga med osparade ändringar.
7. Valvet låser sig själv efter inaktivitet (standard 5 min, ställbart
   1–30 min under *Inställningar*). Osparade ändringar överlever ett lås —
   de ligger kvar krypterade i sidan — men inte att fliken stängs.

## Backup

Backup = **kopiera filen**. Lägg `valv.html` på t.ex. Google Drive, ett
USB-minne eller i valfri mapp som säkerhetskopieras. Varje kopia är ett
komplett, krypterat valv. Spara gärna flera generationer.

## ⚠️ Viktigt

- **Glömt master-lösenord = datan är borta för alltid.** Det finns ingen
  återställning, ingen bakdörr, inget konto. Det är hela poängen.
- Exportfunktionen (*Inställningar → Export*) skriver en **okrypterad**
  JSON-fil. Använd den bara för migrering och radera den direkt efteråt.

## Hotmodell

**Skyddar mot:**

- Att någon kommer över filen (stöld, läckt molnkonto, borttappat USB):
  innehållet är AES-256-GCM-krypterat och nyckelderiveringen med 600 000
  PBKDF2-iterationer gör gissningsattacker dyra — förutsatt ett starkt
  master-lösenord.
- Manipulation av den krypterade datan: GCM upptäcker varje ändring och
  vägrar dekryptera.
- Nätverksattacker vid användning: appen gör inga nätverksanrop alls och
  har en strikt Content Security Policy.

**Skyddar INTE mot:**

- Skadlig kod på din egen dator (keyloggers, minnesdumpar) — är enheten
  komprometterad kan lösenorden läsas när valvet är upplåst.
- Skadliga webbläsartillägg, som kan läsa och ändra alla sidor du öppnar.
- Någon som ändrar **appkoden** i din HTML-fil: krypteringen skyddar
  datan, inte koden. Förvara filen så att obehöriga inte kan skriva till
  den, och öppna inga kopior du inte litar på.
- Svaga master-lösenord — välj långt och unikt.
- Att du glömmer master-lösenordet (se ovan).

**Tekniska begränsningar (best effort):**

- Vid lås släpps alla referenser till dekrypterad data, men JavaScript
  ger ingen möjlighet att garanterat skriva över minne (strängar är
  immutabla och GC styr). En minnesdump av webbläsarprocessen strax efter
  lås kan i teorin innehålla rester.
- Rensningen av urklipp efter 30 s kräver att webbläsarfliken har fokus;
  vissa system har dessutom urklippshistorik som appen inte kan tömma.

## Utveckling

```
src/            index.html, style.css, crypto.js, app.js (modulär källkod)
build.mjs       inlinar allt till dist/valv.html, validerar inga externa referenser
test/roundtrip.mjs   kryptotester + spara-simulering (ren Node, inga beroenden)
test/e2e.mjs    frivillig browser-verifiering (kräver playwright-core)
```

```bash
node build.mjs            # bygger dist/valv.html
node test/roundtrip.mjs   # kryptotester (Node >= 19)
node test/e2e.mjs         # round-trip i riktig Chromium (frivillig)
```

`crypto.js` körs oförändrad i både webbläsaren och Node — bygget strippar
bara ESM-exporten. CSP-metataggen injiceras av bygget eftersom källfilerna
under utveckling refererar varandra externt.

### Spara-mekanismen (varför den ser ut som den gör)

Appen läser `document.documentElement.outerHTML` **en gång vid start**,
innan någon DOM-mutation skett, och sparar den som "orörd källkod". Vid
spara byts innehållet i `<script id="vault-data">`-blocket ut i den
strängen. Att läsa `outerHTML` vid spara-tillfället vore farligt — då
innehåller DOM:en renderade poster i klartext som skulle följa med ut i
filen. En separat template hade dubblerat hela appen. Webbläsarens
serialisering är stabil mellan generationer, vilket E2E-testet verifierar
över två fullständiga spara/öppna-varv.

## Manuell testchecklista

- [ ] **First-run:** öppna en nybyggd `valv.html` → skapa-läget visas,
      styrkemätaren reagerar, olika lösenord i fälten ger fel.
- [ ] **Skapa + spara:** skapa valv, lägg till en post, spara.
- [ ] **Round-trip (viktigast):** öppna den **sparade/nedladdade** filen,
      lås upp, verifiera posten, ändra något, spara igen och öppna även
      den filen.
- [ ] **Fel lösenord:** ger "Fel lösenord", aldrig kraschad/korrupt vy.
- [ ] **Lås/upplås:** manuellt lås tömmer listan; upplåsning visar datan
      igen; osparad ändring finns kvar efter lås → upplås.
- [ ] **Auto-lås:** ställ 1 min, vänta — valvet låser sig.
- [ ] **Kopiera:** kopiera lösenord, klistra in; efter 30 s är urklippet tomt.
- [ ] **Generator:** längd och teckentyper påverkar resultatet.
- [ ] **Byt lösenord:** kräver rätt nuvarande; gamla filen på disk öppnas
      med gamla lösenordet, nysparad fil med det nya.
- [ ] **Export:** varningsdialog visas; JSON innehåller posterna.
- [ ] **Mobilvy:** smal skärm — knappar och dialoger användbara.
- [ ] **Offline/file://:** allt ovan med nätverket avslaget.
