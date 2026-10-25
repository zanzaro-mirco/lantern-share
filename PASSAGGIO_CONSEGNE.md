# Passaggio di consegne — 25 ottobre 2026

## Ripartenza corrente

Repository pubblico: https://github.com/zanzaro-mirco/lantern-share. Cartella: `C:/Users/mzanz/codex_projects/lantern-share`, branch `main`, ultimo commit di codice pubblicato **`3d22698c2bcb6ccbd4bfd4bd8f304e0ec243576f`**. Non ripartire da uno scheletro: identità, SQLite, TLS, associazione e comunicazione PoC sono già implementati. La vecchia cartella `app_condivisione_kmp` non è più il progetto corrente.

Leggere `AGENTS.md`, [piano](PIANO_SVILUPPO.md), [architettura](ARCHITETTURA_E_QUALITA.md) e la sola [sintesi corrente](STATO_SVILUPPO.md). Per la funzionalità corrente servono ADR 015–019 e i sorgenti indicati sotto. [Indice aggiornato di tutti i documenti](docs/STATO_DOCUMENTAZIONE.md).

La guida dettagliata per il passaggio a Claude Code è **`../LANTERN_RIPARTENZA_CLAUDE_CODE.md`**, nella cartella superiore su questa macchina. È una fotografia di consegna, esterna a Git. `CLAUDE.md` nel repository richiama le regole comuni; piano/stato nel repository restano le fonti da aggiornare nei prossimi incrementi.

## Capacità disponibile e verifica

- B1–B7 integrati: ammissione durevole locale con politica A, inviti delegati, verifica di appartenenza, prima scelta di sessione, testo durevole e roster autenticato che conserva gli offline. Ultimo completo Apple riuscito attestato: `ba5e929`, [40118469089](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40118469089), Native/framework/app/simulatore. Non hardware.
- B8 (`3d22698`): **Nuovo testo / Ricevi / Consegna copia** su Node/Android/desktop e Bonjour/iOS. [PoC 40209117434](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40209117434) success. [iOS completo 40209149857](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40209149857) letto da concluso: **failure**, 201 XCTest, unico fallito `testRosterTextRejectsAlteredACKAfterDurableReceive` (due asserzioni). Causa nel test: il callback `acknowledged` non validava l'ACK grezzo come fa la produzione (`GroupAdmissionSession` → `transfer.acknowledge`), quindi chiusura `.cancelled` invece di `.adapter`. Corretto localmente nel test; produzione invariata. Da riverificare nel prossimo completo Apple.
- **B9 locale, non committato:** copia originale dell'autore dopo nuovi ingressi, [ADR 019](docs/ADR-019-COPIA-ORIGINALE-DOPO-NUOVI-INGRESSI.md). Feature `group-roster-text-copy` richiesta dall'autore e supportata dai riceventi, LTC versione 2, snapshot firmato contenuto nel roster vivo con destinatario incluso; C rifiutato prima del pin, nessuna rifirma/contatore/destinatario retroattivo. Implementato in core, Node/owner JVM, facciate iOS Kotlin e owner/sessione Swift; test comuni, JVM reali e XCTest aggiornati. Evidenze precise in [STATO](STATO_SVILUPPO.md): JVM/host verificati localmente, **Native/Swift/simulatore e hardware non verificati**.

Nessun commit, push o run CI avviati in questa ripresa; nessuna release o firma reale.

## Unico prossimo blocco

1. **Fatto:** commit/push unico `6e18f64ca8837cfa0fd29514acc9bd072b7b7dd5` e dispatch del [completo Apple 40214226132](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40214226132) (queued all'unica lettura; [iOS ordinario 40214216705](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40214216705) e [PoC 40214216683](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40214216683) in_progress). Letto da concluso: ordinario e PoC **success**; completo **failure**, con 199/201 XCTest e un solo test, quello di facciata della copia B9, che riportava "Conflicting observations for the same session". La causa era l'ordine nel test: la coppia copia veniva installata dopo che l'autore aveva segnato la sessione `used`. La correzione nel solo test è pubblicata con autorizzazione nel commit successivo, **non ancora eseguita**: un nuovo completo Apple va letto una volta da concluso. Dettagli e osservazione sul flag `used` in [STATO](STATO_SVILUPPO.md).
2. Se riuscito: **recupero esplicito di una copia da un altro destinatario autorizzato (non autore)**, con prova distinta dalla consegna dell'autore, stessi byte firmati, nessun destinatario retroattivo né riattivazione di sessioni archiviate. Specificare prove e contesto in un ADR prima del codice; nuova decisione esplicita per incompatibilità.

Esclusi dal blocco: distribuzione automatica, connessione persistente/reconnect, paginazione, scelta fra sessioni usate e UI completa. Limite noto di B9: il ricevente non può dimostrare che lo snapshot firmato preceda gli ingressi successivi (vedi ADR 019).

## Sorgenti da cui ripartire

- Copia B9: `protocol/src/commonMain/kotlin/lantern/protocol/GroupRosterText.kt` (`savedCopy`, `COPY_FEATURE`, `expectedRecipients`) e relativi test comuni; `GroupTextTransferServiceTest` per le copie dopo nuovi ingressi.
- Contratti: `domain/src/commonMain/kotlin/lantern/domain/GroupRosterTextController.kt`, `GroupTextRepository.kt` e controller sessione/roster.
- Regole: `protocol/src/commonMain/kotlin/lantern/protocol/GroupRosterText.kt`, `GroupTextTransfer.kt`, `GroupTextReceiver.kt`, `GroupSessionRoster.kt`, relativi codec/decoder e test `commonTest`.
- JVM/Android: `connectivity/src/jvmAndAndroidMain/kotlin/lantern/connectivity/GroupAdmissionService.kt`, `HandshakeV1Connection.kt`, `Node.kt`; integrazione reale in `connectivity/src/jvmTest/.../GroupTextTransferServiceTest.kt`.
- iOS: `IosGroupTextTransfer.kt`, `IosGroupRoster.kt` in `ui/src/iosMain/...`; `IosGroupAdmissionController.kt` in `ui/src/commonMain/...`; `iosApp/GroupAdmissionSession.swift`, `HandshakeV1Channel.swift`, `BonjourProbe.swift` e `iosApp/Tests/GroupAdmissionSessionTests.swift`.
- Archivio: `persistence/src/commonMain/sqldelight/lantern/persistence/GroupText.sq`, `SqliteGroupTextStore.kt`, repository OS. Schema **5**, ultima migrazione **4.sqm**; preservare dati e wire precedenti.

## Metodo da mantenere

Italiano, letture mirate, niente subagenti, refactoring estranei o aggiornamenti di dipendenze. Un solo blocco con risultato osservabile e criteri definiti prima di modificare; procedere autonomamente per gli strati necessari senza consegne ogni due minuti. Test mirati durante il lavoro e controllo integrato finale, regressioni versionate. JDK/JBR **17** e **Gradle Wrapper**, non Java 25 né installazione Gradle locale.

Controllare `git status`; preservare lavoro locale e identità/database. Un push raggruppato quando autorizzato, mai forzato; niente build per sole modifiche Markdown. **Nessun polling CI**, attesa, monitor o automazione. Apple ordinario compila, completo esegue Native/simulatore, interop è opt-in separato: non confondere i livelli.

Fase **0 chiusa** per la prova fisica Android ↔ Windows. Fase **1 aperta**: residui Android ↔ Windows (WAN spenta, direzioni, riavvio, blocco locale), iPhone e Mac Intel/Apple Silicon obbligatori, rinviati dall'utente. Il gate sullo sviluppo completo UI resta valido. Simulatore e loopback non chiudono il collaudo hardware.

## Storico preservato

[Passaggio precedente integrale](docs/archivio/PASSAGGIO_CONSEGNE_FINO_2026-10-25.md) e [stato precedente integrale](docs/archivio/STATO_SVILUPPO_FINO_2026-10-25.md). Le loro vecchie sezioni “corrente/prossimo” sono storiche; non seguire le code superate.
