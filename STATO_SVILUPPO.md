# Stato sviluppo — 25 ottobre 2026

## Sintesi corrente

Ultimo codice pubblicato: **`1fabae6`**, branch `main` (B9 in `6e18f64` più correzione del test di facciata). Il commit successivo pubblica il blocco **B10**, copia inoltrata da un destinatario, non ancora attestato su Apple. Prototipo reale multipiattaforma, app di prodotto ancora incompleta. [Piano e accettazione](PIANO_SVILUPPO.md), [ripartenza](PASSAGGIO_CONSEGNE.md), [indice documentale](docs/STATO_DOCUMENTAZIONE.md).

| Capacità | Implementazione e integrazione | Evidenza e limite |
|---|---|---|
| Identità, SQLite, nome dispositivo, TLS, associazione e testo PoC | Android, desktop, iOS; adattatori OS e contratti Kotlin esistenti | Comunicazione fisica Android ↔ Windows riuscita; PoC Apple verificato in simulatore. Non ricominciare il lavoro concluso |
| Fondazione e appartenenza durevoli, inviti delegati B1–B3 | Servizi Node e Bonjour/UI; commit locale A e prove OS, fondatore non sempre necessario online | Verificati automaticamente nei checkpoint precedenti; non commit distribuito né consenso ripristinabile dal journal |
| Verifica membro B4, prima sessione B5 | Nuova prova sul TLS vivo e una sessione in memoria per run | Verificati su JVM/Apple; risultati diagnostici non riusabili come autorità; gestione completa sessioni ancora aperta |
| Testo durevole B6 | Firma, destinatari congelati, contatori e ricevute separate dal PoC, schema 5 | `fcec8f7`, completo Apple 39965540210: 182 XCTest complessivi riusciti; una busta per tentativo, non chat persistente |
| Roster autenticato B7 | Attestazioni proprie, offline conservati, unione monotona e accordo esatto; Node/Bonjour/UI | `ba5e929`, completo Apple 40118469089 riuscito, Native/export/app/simulatore; nessun nuovo hardware |
| Testo con roster B8 e copia dell'autore dopo nuovi ingressi B9 | Nuovo testo/Ricevi/Consegna copia su Android/desktop/iOS; copia con snapshot firmato contenuto nel roster vivo, [ADR 018](docs/ADR-018-CONSEGNA-TESTO-CON-ROSTER.md)–[019](docs/ADR-019-COPIA-ORIGINALE-DOPO-NUOVI-INGRESSI.md) | `1fabae6`: [completo Apple 40220901275](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40220901275) **success**, 201/201 XCTest, Native/export/app/simulatore; iOS ordinario e PoC success. Non hardware |
| Copia inoltrata da destinatario B10 | Implementato in core, Node/owner JVM, facciate iOS Kotlin e owner/sessione Swift, [ADR 020](docs/ADR-020-COPIA-INOLTRATA-DA-DESTINATARIO.md) | JVM con TLS/P-256/SQLite reali e compilazione host delle facciate iOS verificati localmente; **Native/Swift/simulatore e hardware non verificati** |

## Checkpoint Apple di B9

[Completo 40214226132](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40214226132) su `6e18f64`, letto una volta da concluso: failure con 199/201 XCTest. Il test ACK corretto e il test della copia dopo l'ingresso di C erano riusciti; l'unico test fallito era `testRosterTextFacadeSavedCopyRequiresValidSignatureCurrentRunAndExactACK` ("Conflicting observations for the same session"). Causa nel test: la coppia copia veniva installata dopo che l'autore aveva segnato la sessione `used`, mentre il ricevente non aveva mai ricevuto l'originale, e `SessionSelector` rifiuta le due offerte discordanti. In `1fabae6` il test installa la coppia prima di firmare; produzione invariata. [Completo 40220901275](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40220901275) letto una volta da concluso: **success**, 201/201 XCTest; [iOS ordinario 40220892408](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40220892408) e [PoC 40220892398](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40220892398) success.

**Osservazione aperta (B6/B8, non introdotta da B9/B10):** se una consegna si interrompe dopo che l'autore ha segnato `used` e prima che il ricevente lo faccia, un nuovo tentativo nella stessa run fra quei due dispositivi viene rifiutato come contraddittorio finché la run non viene azzerata.

## B10 — copia inoltrata da un destinatario

**Implementato:** feature `group-roster-text-relay`, richiesta da chi inoltra, supportata e mai richiesta dai riceventi, esclusiva con `group-roster-text-copy`; LTC versione 3 (stessi 324 byte). `GroupRosterTextContext(relayedCopy)` accetta solo autore diverso da mittente e destinatario TLS, entrambi nello snapshot firmato contenuto nel roster vivo; `authorCertificate` restituisce il certificato della join dell'autore e la firma si verifica con il verificatore OS dei certificati di gruppo, non con il certificato TLS di chi inoltra. Overload esplicito di `GroupTextReceiver.receive`, chiamate precedenti invariate. Preflight prima del pin su Node e Swift: copia salvata con ricevuta locale, peer fra i destinatari e diverso dall'autore; la modalità richiesta deriva dalla copia locale, quella applicata dagli HELLO (`checkBinding` la ricontrolla su iOS). La ricevuta del destinatario resta locale a chi inoltra; LGA/busta/LTX/schema 5 invariati. UI: etichette della consegna copia aggiornate.

**Testato automaticamente su questo host (JDK 17 Temurin, Gradle Wrapper):**

```powershell
.\gradlew.bat -Pandroid=true :protocol:jvmTest :protocol:testDebugUnitTest :connectivity:jvmTest :ui:jvmTest :ui:testDebugUnitTest :androidApp:assembleDebug :desktopApp:classes --console=plain
```

**3 min 53 s success**: protocollo **430 JVM / 394 Android**, connettività **246** (1 skipped, mDNS opt-in), UI **15 JVM / 15 Android**; **1099 passati**, zero failure/error, APK e classi desktop compilati. Persistenza non modificata e non rieseguita. Nuove regressioni: tre test comuni (contesto e certificato dell'autore, negoziazione esclusiva, receiver con mittente TLS diverso solo in inoltro) e un test JVM reale a quattro nodi: B firma per {A, B, C} con A offline; C rifiuta l'inoltro verso B (autore) e verso D (ammesso dopo) senza tentare il messaggio; A rientra senza memoria di run e riceve da C, in assenza di B, gli stessi byte; ricevuta registrata da C, ricevute di B invariate, duplicato idempotente, contatore successivo di B 2.

**Osservazione aperta, ripetuta:** una prima esecuzione della classe `GroupTextTransferServiceTest` è fallita in `reopenedMembersTransferBothDirectionsAndPreserveUsedScopeAndHistoryInBothTlsOrders` con `NoSuchElementException` in `Node.selectGroupConnection`; la seconda si è bloccata oltre 14 minuti in `Node.close` dentro `threeMemberRosterRetainsOfflineFounderThenOfflineDelegateWithoutRetroactiveRecipients`, con un thread fermo in `SSLServerSocket.accept` (`Node.kt:121`). Entrambi i test sono preesistenti e testo legacy/roster, senza percorso di copia. La terza esecuzione della classe (18/18) e la suite integrata sono riuscite. Problema intermittente di avvio/chiusura dei Node nei test, non diagnosticato né corretto: da trattare in un blocco separato.

**Compilato sull'host, non Native:** K2JVMCompiler su tutte le facciate `iosMain` salvo `IosEntry`, controller comune e boundary di persistenza di test: success. **Non Kotlin/Native, export Objective-C, Swift, XCTest o TLS Apple.** XCTest aggiornati ma non compilati né eseguiti: nuovo `testRosterTextOriginalRecipientRelaysSameEnvelopeToReturningFounder` (rifiuto verso l'autore prima del pin, inoltro C → A con B assente, stessi byte e ricevute separate) e closure `selectRoster` a quattro argomenti.

**Limiti dichiarati:** quelli di ADR 019 sull'ordine temporale; l'autore deve avere una join firmata nel roster vivo (anche conservata da altri); un ricevente B9 senza la nuova feature rifiuta in HELLO gli inoltri.

## Garanzie correnti e limiti

B8 ripete TLS/pin, membership, sessione e roster completo prima di LTC/testo/LGA nello stesso owner, reader e timer originale. Preflight della copia prima del pin; marker/revisione/run ricontrollati ai confini OS/SQL. Kotlin custodisce protocollo, memoria e passi durevoli; Swift gestisce OS/I/O/lifecycle. Received dopo commit/write ACK; Sent dopo ACK esatto e ricevuta persistita. Used conservativo; drain prima della chiusura DB. Stop di tutti non riattiva sessioni dalla storia. Una consegna esplicita per TLS, nessuna distribuzione automatica/connessione persistente. Schema 5/4.sqm, identità, dipendenze, lock e workflow preservati.

## Prossimo blocco e lavoro aperto

B10 pubblicato con autorizzazione e un solo checkpoint Apple completo, da leggere una volta da concluso senza polling; correggere eventuali errori prima di ampliare. Prossimo blocco proposto in PASSAGGIO.

Restano obbligatori, senza estendere automaticamente il prossimo blocco: distribuzione automatica, controllo persistente/reconnect/cambio LAN e collegamento manuale, scelta operativa fra sessioni usate, paginazione oltre budget, uscita durevole dal gruppo, cronologia/ricerca/pulizia, immagini/file/ripresa/integrità, background/notifiche/condivisione/integrazioni OS, UI completa/accessibilità, packaging/firme/beta e matrice di prodotto. Requisiti completi nel piano; nessuna percentuale di completamento ricavata dai test.

**Fase 0 chiusa**, prova fisica Android ↔ Windows. **Fase 1 aperta**: WAN disattivata, bidirezionalità/riavvio e regressione del blocco Android, iPhone, Mac Intel e Apple Silicon. Hardware rinviato dall'utente, non superato; gate UI completa invariato. Nessuna nuova interazione UI, installazione fisica o interop Apple↔JVM attestata.

## Storico ed evidenze conservate

[Stato integrale prima del riordino](docs/archivio/STATO_SVILUPPO_FINO_2026-10-25.md), [passaggio integrale](docs/archivio/PASSAGGIO_CONSEGNE_FINO_2026-10-25.md). Conservati comandi, errori corretti, run, conteggi e note post-push locali precedenti; le vecchie sezioni “corrente/prossimo” sono storiche. Aggiornare in futuro questa sintesi e i riferimenti pertinenti, senza duplicare lo storico.
