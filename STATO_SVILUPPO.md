# Stato sviluppo — 25 ottobre 2026

## Sintesi corrente

> **Nota post-push:** correzione XCTest, B9 e documenti pubblicati in un unico commit **`6e18f64ca8837cfa0fd29514acc9bd072b7b7dd5`** su `main` (la sintesi sotto descrive lo stesso contenuto, prima "locale non committato"). Unica lista post-push: [iOS completo 40214226132](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40214226132) (dispatch, `bootstrap_interop=false`) queued; [iOS ordinario 40214216705](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40214216705) e [PoC 40214216683](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40214216683) in_progress. Esiti letti una volta da conclusi, senza polling: iOS ordinario e PoC **success**. Il completo 40214226132 è **failure** nel passo "Test iOS Keychain and TLS on simulator", con 201 XCTest e 199 riusciti. Sono riusciti framework, Native, export, app e compilazione Swift/XCTest, compresi il test ACK corretto e `testRosterTextLaterAdmissionKeepsOriginalCopyForFrozenRecipientsOnly`.
>
> L'unico test fallito è `testRosterTextFacadeSavedCopyRequiresValidSignatureCurrentRunAndExactACK`, con due asserzioni: "Conflicting observations for the same session". La causa è nel test. La seconda installazione, quella della copia, avveniva dopo `prepareOutgoing`: l'autore aveva già segnato la sessione `used`, mentre il ricevente non aveva mai ricevuto l'originale. Le due offerte stabilite della stessa sessione erano quindi diverse e `SessionSelector` le rifiuta. Ora il test installa la coppia copia prima di firmare; la produzione è invariata. Correzione pubblicata nel commit successivo a `6e18f64`, **non eseguita** (Windows non esegue Swift): va attestata nel prossimo completo Apple.
>
> Osservazione da valutare a parte (B6/B8, non introdotta da B9): se una consegna si interrompe dopo che l'autore ha segnato `used` e prima che il ricevente lo faccia, un nuovo tentativo nella stessa run fra quei due dispositivi viene rifiutato come contraddittorio finché la run non viene azzerata.

Ultimo codice pubblicato: **`3d22698c2bcb6ccbd4bfd4bd8f304e0ec243576f`**, branch `main`, B8 Bonjour/iOS. Sopra di esso, **lavoro locale non committato**: correzione dell'unico XCTest fallito e blocco **B9** (copia originale dopo nuovi ingressi). Prototipo reale multipiattaforma, app di prodotto ancora incompleta. [Piano e accettazione](PIANO_SVILUPPO.md), [ripartenza](PASSAGGIO_CONSEGNE.md), [indice documentale](docs/STATO_DOCUMENTAZIONE.md).

| Capacità | Implementazione e integrazione | Evidenza e limite |
|---|---|---|
| Identità, SQLite, nome dispositivo, TLS, associazione e testo PoC | Android, desktop, iOS; adattatori OS e contratti Kotlin esistenti | Comunicazione fisica Android ↔ Windows riuscita; PoC Apple verificato in simulatore. Non ricominciare il lavoro concluso |
| Fondazione e appartenenza durevoli, inviti delegati B1–B3 | Servizi Node e Bonjour/UI; commit locale A e prove OS, fondatore non sempre necessario online | Verificati automaticamente nei checkpoint precedenti; non commit distribuito né consenso ripristinabile dal journal |
| Verifica membro B4, prima sessione B5 | Nuova prova sul TLS vivo e una sessione in memoria per run | Verificati su JVM/Apple; risultati diagnostici non riusabili come autorità; gestione completa sessioni ancora aperta |
| Testo durevole B6 | Firma, destinatari congelati, contatori e ricevute separate dal PoC, schema 5 | `fcec8f7`, completo Apple 39965540210: 182 XCTest complessivi riusciti; una busta per tentativo, non chat persistente |
| Roster autenticato B7 | Attestazioni proprie, offline conservati, unione monotona e accordo esatto; Node/Bonjour/UI | `ba5e929`, completo Apple 40118469089 riuscito, Native/export/app/simulatore; nessun nuovo hardware |
| Testo con roster B8 | Nuovo testo/Ricevi/Consegna copia su Android/desktop/iOS; stesso autore/busta e ACK per dispositivo | Node verificato localmente e da CI. Completo Apple 40209149857 **failure**: 200/201 XCTest riusciti; il fallito era un difetto del test, corretto localmente e non ancora rieseguito su Apple |
| Copia originale dopo nuovi ingressi B9 | Implementato in core, Node/owner JVM, facciate iOS Kotlin e owner/sessione Swift, [ADR 019](docs/ADR-019-COPIA-ORIGINALE-DOPO-NUOVI-INGRESSI.md) | JVM con TLS/P-256/SQLite reali e compilazione host delle facciate iOS verificati localmente; **Native/Swift/simulatore e hardware non verificati** |

## Checkpoint Apple 3d22698 — esito e correzione

[iOS completo 40209149857](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40209149857), letto una volta in corso e una volta da concluso, senza polling: **failure** nel passo "Test iOS Keychain and TLS on simulator". Framework condiviso, test Native protocollo/persistenza, generazione progetto e compilazione app/XCTest riusciti; 201 XCTest eseguiti, **un solo test fallito** con due asserzioni: `GroupAdmissionSessionTests.testRosterTextRejectsAlteredACKAfterDurableReceive` (riga 561 "No valid recipient ACK", riga 603 "Expected exact agreement rejection").

Causa: l'owner `HandshakeV1Channel` passa l'ACK grezzo al callback `acknowledged`; in produzione `GroupAdmissionSession` lo valida con `transfer.acknowledge(...)` e un ACK alterato fa lanciare l'eccezione, quindi `adapterFailed()`. Il callback del test registrava solo `XCTFail` senza validare né lanciare, e l'owner chiudeva con `.cancelled`. **Codice di produzione invariato**; ora il callback del test valida come la produzione. Correzione da attestare nel prossimo completo Apple. [PoC 40209117434](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40209117434) success, già attestato.

## B9 — copia originale dopo nuovi ingressi

**Implementato (locale):** feature `group-roster-text-copy`, che l'autore della copia supporta e richiede, i riceventi ROSTER_TEXT supportano senza richiederla e un nuovo testo non dichiara; LTC versione 2 (stessi 324 byte); `GroupRosterTextContext(savedCopy)` accetta solo lo snapshot firmato contenuto nel roster vivo, con il destinatario incluso; `expectedRecipients` per l'inbox. Preflight prima del pin invariato (C rifiutato), nessuna rifirma né contatore, LGA/busta/LTX/schema 5 invariati. Swift riceve la modalità dall'owner e `checkBinding` la ricontrolla.

**Testato automaticamente su questo host (JDK 17 Temurin, Gradle Wrapper):**

```powershell
.\gradlew.bat -Pandroid=true :protocol:jvmTest :protocol:testDebugUnitTest :connectivity:jvmTest :ui:jvmTest :ui:testDebugUnitTest :androidApp:assembleDebug :desktopApp:classes --console=plain
```

**3 min 42 s success**: protocollo **427 JVM / 391 Android**, connettività **245** (un mDNS opt-in skipped), UI **15 JVM / 15 Android**; **1092 passati**, zero failure/error, APK e classi desktop compilati. Persistenza non modificata e non rieseguita. Nuove regressioni: due test comuni (negoziazione della modalità, scope v2, sottoinsieme/destinatario/sessione/autore) e due JVM reali: copia a un destinatario originale dopo l'ingresso di C con C rifiutato; quattro nodi con A offline che rientra dopo C e riceve per la prima volta la copia {A,B,D}, duplicato idempotente e contatore successivo 3. `GroupTextTransferServiceTest` riuscita anche da sola (17/17).

**Osservazione aperta:** una prima esecuzione della sola classe si è bloccata oltre 10 minuti in `Node.close` (un `accept` TLS non chiuso) dentro il test preesistente `unsignedLegacyOfflineParticipantCannotDisappearWhenThirdMemberJoins`, che non usa il nuovo percorso. Le riesecuzioni successive (due isolate, una dell'intera classe) e la suite integrata sono riuscite. Blocco intermittente in chiusura non diagnosticato: da indagare separatamente, non attribuito a B9 né corretto.

**Compilato sull'host, non Native:** K2JVMCompiler su tutte le facciate `iosMain` salvo `IosEntry`, controller comune e boundary di persistenza di test: success. **Non Kotlin/Native, export Objective-C, Swift, XCTest o TLS Apple.** XCTest aggiornati ma non compilati né eseguiti: facciata con coppia copia separata (LTC 1/2, copia senza contatori, nuovo testo fuori dallo scope copia), copia originale verso A dopo l'ingresso di C con C rifiutato prima del pin, `selectRoster` a tre argomenti. Windows non esegue Xcode/Swift.

**Limite dichiarato:** il ricevente non può dimostrare che lo snapshot firmato preceda gli ingressi successivi (le join B7 non sono ordinate); la garanzia contro sottoinsiemi firmati dopo l'ingresso resta del client autore. Un ricevente senza la nuova feature rifiuta in HELLO anche copie con roster identico.

## Garanzie correnti e limiti

B8 ripete TLS/pin, membership, sessione e roster completo prima di LTC/testo/LGA nello stesso owner, reader e timer originale. Preflight della copia prima del pin; marker/revisione/run ricontrollati ai confini OS/SQL. Kotlin custodisce protocollo, memoria e passi durevoli; Swift gestisce OS/I/O/lifecycle. Received dopo commit/write ACK; Sent dopo ACK esatto e ricevuta persistita. Used conservativo; drain prima della chiusura DB. Stop di tutti non riattiva sessioni dalla storia. Una consegna esplicita per TLS, nessuna distribuzione automatica/connessione persistente. Schema 5/4.sqm, identità, dipendenze, lock e workflow preservati.

## Prossimo blocco e lavoro aperto

Con autorizzazione: unico commit/push raggruppato e un solo checkpoint Apple completo, letto da concluso senza polling; correggere eventuali errori prima di ampliare. Poi **recupero esplicito di una copia da un altro destinatario autorizzato**; criteri in PASSAGGIO.

Restano obbligatori, senza estendere automaticamente il prossimo blocco: distribuzione automatica, controllo persistente/reconnect/cambio LAN e collegamento manuale, scelta operativa fra sessioni usate, paginazione oltre budget, uscita durevole dal gruppo, cronologia/ricerca/pulizia, immagini/file/ripresa/integrità, background/notifiche/condivisione/integrazioni OS, UI completa/accessibilità, packaging/firme/beta e matrice di prodotto. Requisiti completi nel piano; nessuna percentuale di completamento ricavata dai test.

**Fase 0 chiusa**, prova fisica Android ↔ Windows. **Fase 1 aperta**: WAN disattivata, bidirezionalità/riavvio e regressione del blocco Android, iPhone, Mac Intel e Apple Silicon. Hardware rinviato dall'utente, non superato; gate UI completa invariato. Nessuna nuova interazione UI, installazione fisica o interop Apple↔JVM attestata.

## Storico ed evidenze conservate

[Stato integrale prima del riordino](docs/archivio/STATO_SVILUPPO_FINO_2026-10-25.md), [passaggio integrale](docs/archivio/PASSAGGIO_CONSEGNE_FINO_2026-10-25.md). Conservati comandi, errori corretti, run, conteggi e note post-push locali precedenti; le vecchie sezioni “corrente/prossimo” sono storiche. Aggiornare in futuro questa sintesi e i riferimenti pertinenti, senza duplicare lo storico.
