// i18n.js — all user-facing strings for Valv, English (default) and Swedish.
//
// Like crypto.js/seed.js this file is environment-neutral (no DOM access)
// so the Node test suite can verify that both locales define the same keys.
// The export line at the bottom is stripped by build.mjs.
//
// Conventions (see CLAUDE.md):
//  - Every new UI string MUST be added to BOTH locales here. No hardcoded
//    user-facing strings in markup or app code.
//  - Parameterized messages are functions; everything else is a string.
//  - Static markup carries the English text as fallback plus a data-i18n
//    attribute (or data-i18n-placeholder / data-i18n-title) naming the key.
'use strict';

const STRINGS = {
  en: {
    // Lock screen
    tagline: 'Encrypted password manager in a single file',
    lockPasswordLabel: 'Master password',
    lockWrongPassword: 'Wrong password. Try again.',
    lockUnlock: 'Unlock',
    lockUnlocking: 'Unlocking…',
    createIntro: 'Welcome! This vault is empty. Choose a master password to create it.',
    createPasswordLabel: 'Master password (at least 8 characters)',
    createRepeatLabel: 'Repeat the password',
    createForgetWarning: 'A forgotten master password means the data is gone forever. There is no recovery.',
    createButton: 'Create vault',
    createBusy: 'Creating vault…',
    createTooShort: 'The password must be at least 8 characters.',
    createMismatch: 'The passwords do not match.',
    strengthLabels: ['', 'Very weak', 'Weak', 'Good', 'Strong'],

    // Main view
    dirtyIndicator: '● unsaved',
    dirtyTitle: 'Changes have not been saved to file',
    save: 'Save',
    lockBtn: 'Lock',
    searchPlaceholder: 'Search title, username or URL…',
    newLogin: '+ Login',
    newSeed: '+ Seed phrase',
    generator: 'Generator',
    settings: 'Settings',
    emptyNone: 'No entries yet. Use the buttons above to add one.',
    emptyNoMatches: 'Nothing matches your search.',
    listCopyUser: 'User',
    listCopyPassword: 'Pass',
    copyUserTitle: 'Copy username',
    copyPasswordTitle: 'Copy password',

    // Entry dialog (logins)
    entryTitleNew: 'New entry',
    entryTitleEdit: 'Edit entry',
    labelTitle: 'Title',
    labelUsername: 'Username',
    labelPassword: 'Password',
    labelUrl: 'URL',
    labelNotes: 'Notes',
    show: 'Show',
    hide: 'Hide',
    generate: 'Generate',
    copy: 'Copy',
    deleteBtn: 'Delete',
    cancel: 'Cancel',
    saveEntry: 'Save entry',
    trashConfirm: (title) => `Move “${title}” to the trash?`,
    showHidePasswordTitle: 'Show or hide the password',
    openGeneratorTitle: 'Open the password generator',
    labelTotp: 'TOTP secret (optional)',
    totpPlaceholder: 'Base32 or otpauth:// URI',
    showHideTotpTitle: 'Show or hide the TOTP secret',
    totpInvalid: 'Invalid TOTP secret — use base32 or an otpauth:// URI.',
    totpCurrentCode: 'Current code',
    totpCodeWord: 'TOTP code',
    listCopyTotp: '2FA',
    copyTotpTitle: 'Copy current TOTP code',

    // Seed phrase dialog
    seedTitleNew: 'New seed phrase',
    seedTitleView: 'Seed phrase',
    labelWallet: 'Wallet',
    walletPlaceholder: 'e.g. MetaMask, Ledger',
    labelWordCount: 'Word count',
    seedPasteHint: 'Tip: paste the whole phrase into the first field and all words are filled in automatically.',
    labelPassphrase: 'Passphrase (optional, the “25th word”)',
    showHidePassphraseTitle: 'Show or hide the passphrase',
    labelDerivation: 'Derivation path (optional)',
    derivationPlaceholder: "e.g. m/44'/60'/0'/0/0",
    copyPhrase: 'Copy phrase',
    seedUnknownWords: (n) => `${n} word${n === 1 ? ' is' : 's are'} not in the BIP39 word list (English). `
      + 'Check the spelling — you can still save (other word lists/languages exist).',
    seedFillAll: 'All word fields must be filled in.',
    seedInvalidCount: (n) => `${n} words is not a valid count (12/15/18/21/24) — filling in as far as possible.`,
    seedNoWords: 'No words to copy.',
    seedClipboardWarning: 'Seed phrase in clipboard — cleared in 30 s. Never paste it into a website.',
    wordAria: (n) => `Word ${n}`,

    // API key entries
    newApikey: '+ API key',
    apikeyTitleNew: 'New API key',
    apikeyTitleEdit: 'API key',
    labelService: 'Service',
    servicePlaceholder: 'e.g. Stripe, AWS',
    labelApiKey: 'API key',
    labelApiSecret: 'Secret (optional)',
    labelEnvironment: 'Environment',
    labelScopes: 'Scopes',
    scopesPlaceholder: 'e.g. read:users write:orders',
    labelExpires: 'Expires (optional)',
    apikeyKeyRequired: 'The API key field must be filled in.',
    apiKeyWord: 'API key',
    apiSecretWord: 'Secret',
    listCopyKey: 'Key',
    listCopySecret: 'Secret',
    copyKeyTitle: 'Copy API key',
    copySecretTitle: 'Copy secret',
    showHideKeyTitle: 'Show or hide the API key',
    showHideSecretTitle: 'Show or hide the secret',
    expiryExpired: 'Expired',
    expiryToday: 'Expires today',
    expiryDays: (n) => `Expires in ${n} d`,

    // Secure notes
    newNote: '+ Note',
    noteTitleNew: 'New note',
    noteTitleEdit: 'Note',
    labelBody: 'Text',
    copyBody: 'Copy text',
    noteWord: 'Note',

    // Recovery codes
    newRecovery: '+ Recovery codes',
    recoveryTitleNew: 'New recovery codes',
    recoveryTitleEdit: 'Recovery codes',
    labelCodesPaste: 'Paste codes (split on lines and spaces)',
    addCodesBtn: 'Add codes',
    recoveryNoCodes: 'Add at least one code.',
    markUsedTitle: 'Mark as used',
    removeCodeTitle: 'Remove this code',
    copyNextUnused: 'Copy next unused',
    noUnusedCodes: 'No unused codes left.',
    recoveryLeft: (left, total) => `${left} of ${total} left`,
    recoveryCodeWord: 'Recovery code',

    // Trash
    trashBtn: (n) => `Trash (${n})`,
    trashTitle: 'Trash',
    trashRetentionNote: 'Entries in the trash are removed permanently after 30 days.',
    trashEmptyState: 'The trash is empty.',
    trashDeletedOn: (date) => `Deleted ${date}`,
    restoreBtn: 'Restore',
    deleteForeverBtn: 'Delete permanently',
    deleteForeverConfirm: (title) => `Permanently delete “${title}”? This cannot be undone.`,
    emptyTrashBtn: 'Empty trash',
    emptyTrashConfirm: (n) => `Permanently delete all ${n} entries in the trash? This cannot be undone.`,
    trashAutoPurged: (n) => `${n} entries older than 30 days were removed from the trash.`,

    // Clipboard
    usernameWord: 'Username',
    passwordWord: 'Password',
    seedPhraseWord: 'Seed phrase',
    copiedMessage: (what) => `${what} copied — clipboard is cleared in 30 s.`,
    clipboardCleared: 'Clipboard cleared.',
    clipboardUnavailable: 'Could not access the clipboard.',
    nothingToCopy: 'Nothing to copy — the field is empty.',

    // Toasts
    toastCreated: 'Vault created — click Save to write it to a file.',
    toastAutoLocked: 'The vault locked itself after inactivity.',
    toastSaved: 'Saved.',
    toastSaveAborted: 'Saving was cancelled.',
    toastDownloaded: 'Downloaded as valv.html — replace your old file with the new one.',

    // Generator
    genTitle: 'Password generator',
    genLength: 'Length:',
    genUpper: 'Uppercase (A–Z)',
    genLower: 'Lowercase (a–z)',
    genDigits: 'Digits (0–9)',
    genSymbols: 'Symbols (!#%…)',
    genNew: 'New',
    genNewTitle: 'Generate a new password',
    genUse: 'Use in entry',
    close: 'Close',
    genPickOne: 'Select at least one character type.',

    // Settings
    setTitle: 'Settings',
    setLanguageLabel: 'Language',
    setAutoLockLabel: 'Auto-lock after inactivity (minutes, 1–30)',
    setAutoLockToast: (m) => `Auto-lock set to ${m} min. Remember to save.`,
    setChangeTitle: 'Change master password',
    setCurrentLabel: 'Current password',
    setNewLabel: 'New password (at least 8 characters)',
    setNewRepeatLabel: 'Repeat the new password',
    setChangeBtn: 'Change password',
    setChanging: 'Changing…',
    cpTooShort: 'The new password must be at least 8 characters.',
    cpMismatch: 'The new passwords do not match.',
    cpWrongCurrent: 'Wrong current password.',
    cpChanged: 'The password has been changed. Remember to save the vault to file.',
    setUpgradeTitle: 'Upgrade / import',
    setUpgradeDesc: 'Bring entries in from an earlier vault, e.g. after downloading a new version of the app. '
      + '“Upgrade from file” reads your old valv.html directly — the data stays encrypted all the way (recommended). '
      + '“Import JSON” reads an unencrypted export.',
    setUpgradeBtn: 'Upgrade from file… (recommended)',
    setImportBtn: 'Import JSON…',
    setExportTitle: 'Export',
    setExportDesc: 'Downloads all entries as unencrypted JSON, e.g. for moving to another manager.',
    setExportBtn: 'Export unencrypted…',

    // Export warnings
    expWarning: 'The export is COMPLETELY UNENCRYPTED — every password ends up in plain text in the file. '
      + 'Keep it somewhere safe and delete it as soon as you are done. Continue?',
    expWarningSeeds: 'WARNING: the vault contains SEED PHRASES. The export is COMPLETELY UNENCRYPTED — '
      + 'anyone who gets the file can empty your wallets, and a seed phrase cannot be rotated like a password. '
      + 'Never store the file in the cloud, and securely delete it right after use. Continue anyway?',
    expWarningApikeys: 'WARNING: the vault contains API KEYS. The export is COMPLETELY UNENCRYPTED — '
      + 'anyone who gets the file can call services as you. Rotate any key that may have been exposed, '
      + 'keep the file off the cloud, and securely delete it right after use. Continue anyway?',
    expOk: 'Export unencrypted',

    // Upgrade from file
    upTitle: 'Upgrade from file',
    upFileLabel: (name) => `File: ${name}`,
    upPasswordLabel: 'Master password for the selected file',
    upWrongPassword: 'Wrong password for the selected file.',
    upUnlockBtn: 'Unlock file',
    upDecrypting: 'Decrypting…',
    upErrNotVault: 'No vault data found in the file — is it really a valv.html?',
    upErrEmpty: 'The file is an empty vault shell with no data.',
    upErrCorrupt: 'The vault data in the file is damaged.',
    upErrVersion: (v) => `The file uses an unknown vault format (version ${v}).`,
    upErrIncomplete: 'The vault data in the file is incomplete.',

    // Merge dialog (shared by import and upgrade)
    mergeTitle: 'Bring in entries',
    mergeMessage: (count, existing) => `${count} entries found in the file. `
      + `Merge with your ${existing} existing entries, or replace everything?`,
    mergeSkippedSuffix: (n) => ` (${n} entries were skipped — invalid format.)`,
    mergeReplace: 'Replace everything',
    mergeMerge: 'Merge',
    mergeReplaceConfirm: (n) => `Replace EVERYTHING? Your ${n} existing entries will be removed.`,
    mergeReplaceOk: 'Replace',
    mergeNoEntries: 'No valid entries were found in the file.',
    mergeTakenIn: (n, replaced) => `${n} entries brought in${replaced ? ' (replaced everything)' : ''}. Remember to save.`,

    // Import
    impInvalidJson: 'The file is not valid JSON.',
    impNotExport: 'The file does not look like a Valv export (the entries field is missing).',

    ok: 'OK',
  },

  sv: {
    // Lock screen
    tagline: 'Krypterad lösenordshanterare i en fil',
    lockPasswordLabel: 'Master-lösenord',
    lockWrongPassword: 'Fel lösenord. Försök igen.',
    lockUnlock: 'Lås upp',
    lockUnlocking: 'Låser upp…',
    createIntro: 'Välkommen! Det här valvet är tomt. Välj ett master-lösenord för att skapa det.',
    createPasswordLabel: 'Master-lösenord (minst 8 tecken)',
    createRepeatLabel: 'Upprepa lösenordet',
    createForgetWarning: 'Glömt master-lösenord = datan är borta för alltid. Det finns ingen återställning.',
    createButton: 'Skapa valv',
    createBusy: 'Skapar valv…',
    createTooShort: 'Lösenordet måste vara minst 8 tecken.',
    createMismatch: 'Lösenorden matchar inte.',
    strengthLabels: ['', 'Mycket svagt', 'Svagt', 'Bra', 'Starkt'],

    // Main view
    dirtyIndicator: '● osparat',
    dirtyTitle: 'Ändringarna är inte sparade till fil',
    save: 'Spara',
    lockBtn: 'Lås',
    searchPlaceholder: 'Sök titel, användarnamn eller URL…',
    newLogin: '+ Inloggning',
    newSeed: '+ Seed-fras',
    generator: 'Generator',
    settings: 'Inställningar',
    emptyNone: 'Inga poster ännu. Använd knapparna ovan för att lägga till en.',
    emptyNoMatches: 'Inga träffar på sökningen.',
    listCopyUser: 'Anv.',
    listCopyPassword: 'Lösen',
    copyUserTitle: 'Kopiera användarnamn',
    copyPasswordTitle: 'Kopiera lösenord',

    // Entry dialog (logins)
    entryTitleNew: 'Ny post',
    entryTitleEdit: 'Redigera post',
    labelTitle: 'Titel',
    labelUsername: 'Användarnamn',
    labelPassword: 'Lösenord',
    labelUrl: 'URL',
    labelNotes: 'Anteckningar',
    show: 'Visa',
    hide: 'Dölj',
    generate: 'Generera',
    copy: 'Kopiera',
    deleteBtn: 'Ta bort',
    cancel: 'Avbryt',
    saveEntry: 'Spara post',
    trashConfirm: (title) => `Flytta ”${title}” till papperskorgen?`,
    showHidePasswordTitle: 'Visa eller dölj lösenordet',
    openGeneratorTitle: 'Öppna lösenordsgeneratorn',
    labelTotp: 'TOTP-secret (valfri)',
    totpPlaceholder: 'Base32 eller otpauth://-URI',
    showHideTotpTitle: 'Visa eller dölj TOTP-secreten',
    totpInvalid: 'Ogiltig TOTP-secret — använd base32 eller en otpauth://-URI.',
    totpCurrentCode: 'Aktuell kod',
    totpCodeWord: 'TOTP-kod',
    listCopyTotp: '2FA',
    copyTotpTitle: 'Kopiera aktuell TOTP-kod',

    // Seed phrase dialog
    seedTitleNew: 'Ny seed-fras',
    seedTitleView: 'Seed-fras',
    labelWallet: 'Wallet',
    walletPlaceholder: 't.ex. MetaMask, Ledger',
    labelWordCount: 'Antal ord',
    seedPasteHint: 'Tips: klistra in hela frasen i första fältet så fylls alla ord i automatiskt.',
    labelPassphrase: 'Passphrase (valfri, ”25:e ordet”)',
    showHidePassphraseTitle: 'Visa eller dölj passphrasen',
    labelDerivation: 'Derivation path (valfri)',
    derivationPlaceholder: "t.ex. m/44'/60'/0'/0/0",
    copyPhrase: 'Kopiera fras',
    seedUnknownWords: (n) => `${n} ord finns inte i BIP39-ordlistan (engelska). `
      + 'Kontrollera stavningen — du kan ändå spara (andra ordlistor/språk finns).',
    seedFillAll: 'Alla ordfält måste fyllas i.',
    seedInvalidCount: (n) => `${n} ord är inget giltigt antal (12/15/18/21/24) — fyller i så långt det går.`,
    seedNoWords: 'Inga ord att kopiera.',
    seedClipboardWarning: 'Seed-fras i urklipp — rensas om 30 s. Klistra aldrig in den på en webbsida.',
    wordAria: (n) => `Ord ${n}`,

    // API key entries
    newApikey: '+ API-nyckel',
    apikeyTitleNew: 'Ny API-nyckel',
    apikeyTitleEdit: 'API-nyckel',
    labelService: 'Tjänst',
    servicePlaceholder: 't.ex. Stripe, AWS',
    labelApiKey: 'API-nyckel',
    labelApiSecret: 'Secret (valfri)',
    labelEnvironment: 'Miljö',
    labelScopes: 'Scopes',
    scopesPlaceholder: 't.ex. read:users write:orders',
    labelExpires: 'Går ut (valfritt)',
    apikeyKeyRequired: 'Fältet API-nyckel måste fyllas i.',
    apiKeyWord: 'API-nyckel',
    apiSecretWord: 'Secret',
    listCopyKey: 'Nyckel',
    listCopySecret: 'Secret',
    copyKeyTitle: 'Kopiera API-nyckeln',
    copySecretTitle: 'Kopiera secret',
    showHideKeyTitle: 'Visa eller dölj API-nyckeln',
    showHideSecretTitle: 'Visa eller dölj secret',
    expiryExpired: 'Utgången',
    expiryToday: 'Går ut idag',
    expiryDays: (n) => `Går ut om ${n} d`,

    // Secure notes
    newNote: '+ Anteckning',
    noteTitleNew: 'Ny anteckning',
    noteTitleEdit: 'Anteckning',
    labelBody: 'Text',
    copyBody: 'Kopiera text',
    noteWord: 'Anteckning',

    // Recovery codes
    newRecovery: '+ Återställningskoder',
    recoveryTitleNew: 'Nya återställningskoder',
    recoveryTitleEdit: 'Återställningskoder',
    labelCodesPaste: 'Klistra in koder (delas på rader och mellanslag)',
    addCodesBtn: 'Lägg till koder',
    recoveryNoCodes: 'Lägg till minst en kod.',
    markUsedTitle: 'Markera som använd',
    removeCodeTitle: 'Ta bort koden',
    copyNextUnused: 'Kopiera nästa oanvända',
    noUnusedCodes: 'Inga oanvända koder kvar.',
    recoveryLeft: (left, total) => `${left} av ${total} kvar`,
    recoveryCodeWord: 'Återställningskod',

    // Trash
    trashBtn: (n) => `Papperskorg (${n})`,
    trashTitle: 'Papperskorg',
    trashRetentionNote: 'Poster i papperskorgen tas bort permanent efter 30 dagar.',
    trashEmptyState: 'Papperskorgen är tom.',
    trashDeletedOn: (date) => `Raderad ${date}`,
    restoreBtn: 'Återställ',
    deleteForeverBtn: 'Ta bort permanent',
    deleteForeverConfirm: (title) => `Ta bort ”${title}” permanent? Detta kan inte ångras.`,
    emptyTrashBtn: 'Töm papperskorgen',
    emptyTrashConfirm: (n) => `Ta bort alla ${n} poster i papperskorgen permanent? Detta kan inte ångras.`,
    trashAutoPurged: (n) => `${n} poster äldre än 30 dagar togs bort ur papperskorgen.`,

    // Clipboard
    usernameWord: 'Användarnamn',
    passwordWord: 'Lösenord',
    seedPhraseWord: 'Seed-fras',
    copiedMessage: (what) => `${what} kopierat — urklippet rensas om 30 s.`,
    clipboardCleared: 'Urklippet rensat.',
    clipboardUnavailable: 'Kunde inte komma åt urklippet.',
    nothingToCopy: 'Inget att kopiera — fältet är tomt.',

    // Toasts
    toastCreated: 'Valvet är skapat — klicka Spara för att skriva det till fil.',
    toastAutoLocked: 'Valvet låstes automatiskt efter inaktivitet.',
    toastSaved: 'Sparat.',
    toastSaveAborted: 'Sparandet avbröts.',
    toastDownloaded: 'Nedladdad som valv.html — ersätt din gamla fil med den nya.',

    // Generator
    genTitle: 'Lösenordsgenerator',
    genLength: 'Längd:',
    genUpper: 'Versaler (A–Z)',
    genLower: 'Gemener (a–z)',
    genDigits: 'Siffror (0–9)',
    genSymbols: 'Symboler (!#%…)',
    genNew: 'Nytt',
    genNewTitle: 'Generera ett nytt lösenord',
    genUse: 'Använd i posten',
    close: 'Stäng',
    genPickOne: 'Välj minst en teckentyp.',

    // Settings
    setTitle: 'Inställningar',
    setLanguageLabel: 'Språk',
    setAutoLockLabel: 'Auto-lås efter inaktivitet (minuter, 1–30)',
    setAutoLockToast: (m) => `Auto-lås satt till ${m} min. Glöm inte att spara.`,
    setChangeTitle: 'Byt master-lösenord',
    setCurrentLabel: 'Nuvarande lösenord',
    setNewLabel: 'Nytt lösenord (minst 8 tecken)',
    setNewRepeatLabel: 'Upprepa nytt lösenord',
    setChangeBtn: 'Byt lösenord',
    setChanging: 'Byter…',
    cpTooShort: 'Det nya lösenordet måste vara minst 8 tecken.',
    cpMismatch: 'De nya lösenorden matchar inte.',
    cpWrongCurrent: 'Fel nuvarande lösenord.',
    cpChanged: 'Lösenordet är bytt. Glöm inte att spara valvet till fil.',
    setUpgradeTitle: 'Uppgradera / importera',
    setUpgradeDesc: 'Flytta in poster från ett tidigare valv, t.ex. när du laddat ner en ny version av appen. '
      + '”Uppgradera från fil” läser din gamla valv.html direkt — datan förblir krypterad hela vägen (rekommenderas). '
      + '”Importera JSON” läser en okrypterad export.',
    setUpgradeBtn: 'Uppgradera från fil… (rekommenderas)',
    setImportBtn: 'Importera JSON…',
    setExportTitle: 'Export',
    setExportDesc: 'Laddar ner alla poster som okrypterad JSON, t.ex. för flytt till en annan hanterare.',
    setExportBtn: 'Exportera okrypterat…',

    // Export warnings
    expWarning: 'Exporten är HELT OKRYPTERAD — alla lösenord hamnar i klartext i filen. '
      + 'Spara den bara på en säker plats och radera den så fort du är klar. Fortsätt?',
    expWarningSeeds: 'VARNING: valvet innehåller SEED-FRASER. Exporten är HELT OKRYPTERAD — '
      + 'den som kommer över filen kan tömma dina plånböcker, och en seed-fras kan inte bytas som ett lösenord. '
      + 'Spara aldrig filen i molnet, och radera den säkert direkt efter användning. Fortsätt ändå?',
    expWarningApikeys: 'VARNING: valvet innehåller API-NYCKLAR. Exporten är HELT OKRYPTERAD — '
      + 'den som kommer över filen kan anropa tjänster som du. Rotera nycklar som kan ha exponerats, '
      + 'håll filen borta från molnet och radera den säkert direkt efter användning. Fortsätt ändå?',
    expOk: 'Exportera okrypterat',

    // Upgrade from file
    upTitle: 'Uppgradera från fil',
    upFileLabel: (name) => `Fil: ${name}`,
    upPasswordLabel: 'Master-lösenord för den valda filen',
    upWrongPassword: 'Fel lösenord för den valda filen.',
    upUnlockBtn: 'Lås upp filen',
    upDecrypting: 'Dekrypterar…',
    upErrNotVault: 'Ingen valvdata hittades i filen — är det verkligen en valv.html?',
    upErrEmpty: 'Filen är ett tomt valvskal utan data.',
    upErrCorrupt: 'Valvdatan i filen är skadad.',
    upErrVersion: (v) => `Filen använder ett okänt valvformat (version ${v}).`,
    upErrIncomplete: 'Valvdatan i filen är ofullständig.',

    // Merge dialog (shared by import and upgrade)
    mergeTitle: 'Ta in poster',
    mergeMessage: (count, existing) => `${count} poster hittades i filen. `
      + `Slå ihop med dina ${existing} befintliga poster, eller ersätt allt?`,
    mergeSkippedSuffix: (n) => ` (${n} poster hoppades över — ogiltigt format.)`,
    mergeReplace: 'Ersätt allt',
    mergeMerge: 'Slå ihop',
    mergeReplaceConfirm: (n) => `Ersätta ALLT? Dina ${n} befintliga poster tas bort.`,
    mergeReplaceOk: 'Ersätt',
    mergeNoEntries: 'Inga giltiga poster hittades i filen.',
    mergeTakenIn: (n, replaced) => `${n} poster intagna${replaced ? ' (ersatte allt)' : ''}. Glöm inte att spara.`,

    // Import
    impInvalidJson: 'Filen är inte giltig JSON.',
    impNotExport: 'Filen ser inte ut som en Valv-export (fältet entries saknas).',

    ok: 'OK',
  },
};

export { STRINGS };
