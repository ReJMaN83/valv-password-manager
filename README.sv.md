[🇬🇧 English](README.md) | [🇸🇪 Svenska](README.sv.md)

# Valv

**Krypterad lösenordshanterare i en enda fil — filen är både appen och valvet.**

[![CI](https://github.com/ReJMaN83/valv-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/ReJMaN83/valv-password-manager/actions/workflows/ci.yml)

<img width="1070" height="492" alt="image" src="https://github.com/user-attachments/assets/6ad2d2c0-00e7-4d8d-a5b2-788d88c95acc" />

`valv.html` är en komplett lösenordshanterare i en HTML-fil: appkoden och din
krypterade data reser tillsammans. Dubbelklicka på filen så kör den —
offline, från `file://`, i alla moderna webbläsare.

## Varför

- **Noll beroenden i runtime.** Ingen server, inget webbläsartillägg, ingen
  CDN, inget ramverk, inga nätverksanrop — den enda kryptoleverantören är
  webbläsarens inbyggda Web Crypto API.
- **Backup = kopiera filen.** Varje kopia är ett komplett krypterat valv.
  Lägg den på ett USB-minne, en molndisk, ett mejl till dig själv —
  innehållet förblir krypterat vart filen än tar vägen.
- **Inget att installera, inget att lita på utom filen.** Granskningsbar i en
  textredigerare: en HTML-fil, ~90 kB, läsbar källkod.

## Säkerhetsmodell

| Aspekt | Val |
|---|---|
| Kryptering | AES-256-GCM (autentiserad kryptering) |
| Nyckelderivering | PBKDF2-SHA256, **600 000 iterationer**, 16 byte slumpat salt |
| Nonce | 12 byte, ny slumpad **vid varje sparning** |
| Integritet | GCM-taggen — fel lösenord eller manipulerad data ger ett rent dekrypteringsfel; korrupt klartext visas aldrig |
| Formatversionering | Iterationsantal och formatversion är fält i filen och kan höjas i framtida versioner utan att gamla valv slutar fungera |

Klartext rör aldrig disk, `localStorage`, `sessionStorage`, IndexedDB eller
cookies. Dekrypterad data lever bara i JavaScript-variabler medan valvet är
upplåst; master-lösenordet sparas eller loggas aldrig någonstans. Filens enda
okrypterade metadata är **UI-språkvalet** — det måste gå att läsa före
upplåsning för att låsskärmen ska följa det, och vilket av två språk du
föredrar avslöjar ingenting om valvets innehåll.

**Skyddar mot:** att någon kommer över filen (stöld, läckt molnkonto,
borttappat USB-minne) — förutsatt ett starkt master-lösenord; manipulation av
den krypterade datan (GCM upptäcker varje ändring); nätverksattacker (det
finns ingen nätverkstrafik, plus en strikt Content Security Policy).

**Skyddar inte mot:** skadlig kod på din egen enhet (keyloggers,
minnesdumpar), skadliga webbläsartillägg, att någon ändrar *appkoden* i din
kopia av filen (krypteringen skyddar datan, inte koden), svaga
master-lösenord, eller ett glömt master-lösenord — **det finns ingen
återställning; datan är borta.**

**Ärliga begränsningar:** JavaScript kan inte garantera minnesrensning —
strängar är immutabla och skräpinsamlingen avgör när minne återvinns, så en
minnesdump av processen strax efter låsning kan i teorin innehålla rester.
Urklippsrensningen kräver att fliken har fokus, och operativsystemets
urklippshistorik ligger utanför appens kontroll. Seed-fraser förtjänar extra
försiktighet: till skillnad från lösenord kan de inte roteras efter en läcka
— ha den primära backupen på papper eller metall, offline, för innehav som
betyder något, och se Valv som ett komplement.

## Funktioner

- **Inloggningsposter** — titel, användarnamn, lösenord, URL, anteckningar;
  kopieringsknappar med **30 sekunders automatisk urklippsrensning**.
- **Seed-frasposter (BIP39)** — 12/15/18/21/24 ord i numrerad grid, klistra
  in hela frasen så splittas den automatiskt, validering mot officiella
  engelska ordlistan (varnar, blockerar aldrig), valfri passphrase och
  derivation path. Sparade fraser öppnas **maskerade**: orden finns inte ens
  i DOM:en förrän du klickar Visa. Sökningen omfattar titel och wallet —
  aldrig orden.
- **Lösenordsgenerator** — längd 8–64, teckenklass-val,
  `crypto.getRandomValues` med rejection sampling (ingen modulo-bias).
- **Auto-lås** efter 1–30 minuters inaktivitet (standard 5), plus manuellt
  lås. Osparade ändringar överlever ett lås — omkrypterade in i sidan.
- **Byt master-lösenord** — verifierar nuvarande lösenord, omkrypterar med
  nytt salt.
- **Uppgradera från fil** — peka ett nytt appskal på din gamla `valv.html`,
  ange dess master-lösenord, och posterna tas in utan att okrypterad data
  någonsin rör disken. JSON-import/export finns också (bakom skarp varning)
  för flytt till/från andra hanterare.
- **Engelska och svenska** i UI:t, mörkt tema, responsiv layout.

## Arkitektur

```
src/
  index.html   markup (engelsk fallback-text + data-i18n-attribut)
  style.css    mörkt, minimalt, responsivt
  crypto.js    PBKDF2 + AES-GCM-modul — körs i webbläsare OCH Node
  i18n.js      alla UI-strängar, { en, sv }
  seed.js      BIP39-ordlistan + seed-hjälpare — DOM-fri, dubbelmiljö
  app.js       applikationslogik
build.mjs      inlinar src/ till dist/valv.html, validerar inga externa referenser
test/
  roundtrip.mjs  krypto- och formattester (ren Node, inga beroenden)
  e2e.mjs        full webbläsarverifiering (Playwright Chromium)
```

`node build.mjs` producerar `dist/valv.html` och fäller bygget om någon
extern referens överlever inliningen. Dubbelmiljömodulerna exporterar ESM
för Node-testerna; bygget strippar export-raden för webbläsaren. `dist/`
committas inte — hämta den från en release eller bygg själv.

### Självserialiseringsmekanismen

Den tekniskt intressantaste delen: hur sparar en körande sida *sig själv*
med ny data? Valv fångar `document.documentElement.outerHTML` **en gång,
vid laddning**, innan appen rört DOM:en. Att spara innebär att ersätta
innehållet i det inbäddade `<script id="vault-data">`-blocket i den orörda
strängen och skriva resultatet till disk (File System Access API där det
finns, nedladdning som fallback).

Att fånga vid laddning — i stället för vid sparning — är poängen: vid
spartillfället innehåller DOM:en dekrypterade poster renderade i klartext,
som annars hade serialiserats rakt in i den sparade filen. Ögonblicksbilden
innehåller bara appkod och det krypterade blocket, och webbläsarens
serialisering är stabil över generationer — vilket E2E-sviten bevisar genom
att spara och återöppna filen två varv i rad.

## Tester

- **Node** (`npm test`): 13 tester — encrypt/decrypt-round-trips med fulla
  600 000 iterationer, avvisning av fel lösenord och manipulerad data,
  nonce-unikhet, formatversionering, BIP39-validering, bakåtkompatibilitet
  med valv från äldre versioner, i18n-nyckelparitet.
- **E2E** (`npm run test:e2e`): 55 kontroller i riktig Chromium — bland dem
  projektets kärnkrav: **en sparad fil som öppnas ska fungera identiskt och
  i sin tur kunna spara en fungerande fil.** Sviten kör två fulla
  spara→återöppna-generationer, plus seed-frasmaskering, uppgradera-från-fil,
  import/export och språk-round-trips.

## Kom igång

1. Ladda ner `valv.html` från [senaste releasen](../../releases/latest)
   (bifogad som release-artefakt — inget byggsteg behövs), eller bygg
   själv: `node build.mjs`.
2. Öppna filen i en webbläsare (dubbelklicka).
3. Välj ett master-lösenord — klart.

I Chrome och Edge skriver **Spara** över filen på plats via File System
Access API. I Firefox och Safari kommer sparningen som en nedladdad
`valv.html` — ersätt din gamla fil med den; nedladdningen *är* ditt nya
valv.

## Friskrivning

Det här är ett hobby-/portfolioprojekt. Kryptodesignen är konservativ
(enbart WebCrypto-primitiver, autentiserad kryptering, KDF med högt
iterationsantal), men koden har **inte** granskats av oberoende part. För
kritiska behov, använd en etablerad och granskad lösenordshanterare som
[KeePassXC](https://keepassxc.org/) eller [Bitwarden](https://bitwarden.com/).

## Licens

[MIT](LICENSE)
