# Passaggio di consegne — 25 ottobre 2026

## Ripartenza corrente

Repository pubblico: https://github.com/zanzaro-mirco/lantern-share. Cartella: `C:/Users/mzanz/codex_projects/lantern-share`, branch `main`, ultimo commit di codice pubblicato **`1fabae6`**. Non ripartire da uno scheletro: identità, SQLite, TLS, associazione e comunicazione PoC sono già implementati. La vecchia cartella `app_condivisione_kmp` non è più il progetto corrente.

Leggere `AGENTS.md`, [piano](PIANO_SVILUPPO.md), [architettura](ARCHITETTURA_E_QUALITA.md) e la sola [sintesi corrente](STATO_SVILUPPO.md). Per la funzionalità corrente servono ADR 015–020 e i sorgenti indicati sotto. [Indice aggiornato di tutti i documenti](docs/STATO_DOCUMENTAZIONE.md).

La guida dettagliata per il passaggio a Claude Code è **`../LANTERN_RIPARTENZA_CLAUDE_CODE.md`**, nella cartella superiore su questa macchina. È una fotografia di consegna, esterna a Git. `CLAUDE.md` nel repository richiama le regole comuni; piano/stato nel repository restano le fonti da aggiornare nei prossimi incrementi.

## Capacità disponibile e verifica

- B1–B7 integrati: ammissione durevole locale con politica A, inviti delegati, verifica di appartenenza, prima scelta di sessione, testo durevole e roster autenticato che conserva gli offline. Non hardware.
- B8 e B9: **Nuovo testo / Ricevi / Consegna copia** su Node/Android/desktop e Bonjour/iOS, copia dell'autore anche dopo nuovi ingressi con destinatari congelati. `1fabae6`: [completo Apple 40220901275](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40220901275) **success**, 201/201 XCTest, Native/framework/app/simulatore; iOS ordinario e PoC success. Non hardware.
- **B10, pubblicato nel commit successivo a `1fabae6`, non ancora attestato su Apple:** copia inoltrata da un destinatario originale non autore, [ADR 020](docs/ADR-020-COPIA-INOLTRATA-DA-DESTINATARIO.md). Feature `group-roster-text-relay`, LTC versione 3, firma verificata con il certificato della join dell'autore nel roster vivo; mai verso l'autore, membri successivi o non destinatari; nessuna rifirma, contatore o destinatario retroattivo. Implementato in core, Node/owner JVM, facciate iOS Kotlin e owner/sessione Swift. Evidenze in [STATO](STATO_SVILUPPO.md): JVM/host verificati localmente (1099 test integrati), **Native/Swift/simulatore e hardware non verificati**.

Un solo checkpoint Apple completo autorizzato per B10; nessuna release o firma reale.

## Unico prossimo blocco

1. Leggere **una volta** da concluso il completo Apple avviato dopo il push di B10; se fallisce, leggere i soli errori del job e correggere prima di ampliare.
2. Se riuscito, proposta da confermare: **stabilità di avvio/chiusura dei Node nei test JVM** (blocco intermittente in `Node.close` con `accept` TLS attivo e `NoSuchElementException` in `selectGroupConnection`, vedi STATO), oppure il **nuovo tentativo dopo una consegna interrotta** quando le due offerte della stessa sessione divergono su `used`. Specificare criteri prima del codice; scelta dell'utente.

Esclusi dal blocco: distribuzione automatica o a catena, sincronizzazione della cronologia, propagazione delle ricevute all'autore, connessione persistente/reconnect, paginazione, scelta fra sessioni usate e UI completa. Limiti noti di B9/B10: ordine temporale della firma non dimostrabile dal ricevente; l'autore deve avere una join nel roster vivo (ADR 019–020).

## Sorgenti da cui ripartire

- Copie B9/B10: `protocol/src/commonMain/kotlin/lantern/protocol/GroupRosterText.kt` (`savedCopy`, `relayedCopy`, `COPY_FEATURE`, `RELAY_FEATURE`, `expectedRecipients`, `authorCertificate`), overload di `GroupTextReceiver.receive` e relativi test comuni; `GroupTextTransferServiceTest` per copie dopo nuovi ingressi e inoltri.
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
