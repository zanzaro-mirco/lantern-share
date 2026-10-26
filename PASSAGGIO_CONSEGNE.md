# Passaggio di consegne — 25 ottobre 2026

## Ripartenza corrente

Repository pubblico: https://github.com/zanzaro-mirco/lantern-share. Cartella: `C:/Users/mzanz/codex_projects/lantern-share`, branch `main`, ultimo commit di codice pubblicato **`e8963d3`**. Non ripartire da uno scheletro: identità, SQLite, TLS, associazione e comunicazione PoC sono già implementati. La vecchia cartella `app_condivisione_kmp` non è più il progetto corrente.

Leggere `AGENTS.md`, [piano](PIANO_SVILUPPO.md), [architettura](ARCHITETTURA_E_QUALITA.md) e la sola [sintesi corrente](STATO_SVILUPPO.md). Per la funzionalità corrente servono ADR 014–021 e i sorgenti indicati sotto. [Indice aggiornato di tutti i documenti](docs/STATO_DOCUMENTAZIONE.md).

La guida dettagliata per il passaggio a Claude Code è **`../LANTERN_RIPARTENZA_CLAUDE_CODE.md`**, nella cartella superiore su questa macchina. È una fotografia di consegna, esterna a Git. `CLAUDE.md` nel repository richiama le regole comuni; piano/stato nel repository restano le fonti da aggiornare nei prossimi incrementi.

## Capacità disponibile e verifica

- B1–B7 integrati: ammissione durevole locale con politica A, inviti delegati, verifica di appartenenza, prima scelta di sessione, testo durevole e roster autenticato che conserva gli offline. Non hardware.
- B8 e B9: **Nuovo testo / Ricevi / Consegna copia** su Node/Android/desktop e Bonjour/iOS, copia dell'autore anche dopo nuovi ingressi con destinatari congelati. `1fabae6`: [completo Apple 40220901275](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40220901275) **success**, 201/201 XCTest, Native/framework/app/simulatore; iOS ordinario e PoC success. Non hardware.
- **B10, pubblicato in `6d1425f`, attestato in simulatore (completo 40241551612, 202/202 XCTest):** copia inoltrata da un destinatario originale non autore, [ADR 020](docs/ADR-020-COPIA-INOLTRATA-DA-DESTINATARIO.md). Feature `group-roster-text-relay`, LTC versione 3, firma verificata con il certificato della join dell'autore nel roster vivo; mai verso l'autore, membri successivi o non destinatari; nessuna rifirma, contatore o destinatario retroattivo. Implementato in core, Node/owner JVM, facciate iOS Kotlin e owner/sessione Swift. Evidenze in [STATO](STATO_SVILUPPO.md): JVM/TLS/SQLite e Native/Swift/simulatore verificati, **hardware non verificato**.
- **Stabilità avvio/chiusura Node, pubblicata nel commit successivo a `6d1425f`:** `AsyncResourceCloser.closeAll` prende l'istantanea al momento della chiamata; `Node` non usa più `toList()` sul set concorrente dei socket (causa della `NoSuchElementException` in `selectGroupConnection` e dello `stop()` interrotto che lasciava `accept` vivo in `close()`). Regressione deterministica con mutazione verificata, test Node su loopback, 5/5 esecuzioni di `GroupTextTransferServiceTest`, connettività 248. Solo JVM/Android; nessun effetto su wire/schema/iOS.

- **B11, pubblicato nel commit successivo a `e8963d3`, non ancora attestato su Apple:** ripresa nella stessa sessione dopo una consegna interrotta, [ADR 021](docs/ADR-021-RIPRESA-DOPO-CONSEGNA-INTERROTTA.md). `SessionSelector` unisce le osservazioni della stessa sessione come `used` invece di rifiutarle; nessun cambio wire/schema/HELLO né adattatori OS. JVM reale con interruzione deterministica (prima falliva), test comuni aggiornati, verifica integrata JVM/Android riuscita; nuovo XCTest scritto ma **non compilato né eseguito**; Native/Swift/simulatore e hardware non verificati.

Blocco di stabilità pubblicato con autorizzazione, senza checkpoint Apple completo (nessun file iOS/comune toccato). Un solo checkpoint Apple completo autorizzato per B11. Nessuna release o firma reale.

## Unico prossimo blocco

1. **Post-push locale, fatto:** commit `6d1425f`, [completo Apple 40241551612](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40241551612) letto una volta da concluso: **success**, 202/202 XCTest (incluso l'inoltro C → A), Native/framework/app/simulatore; [iOS ordinario 40241543316](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40241543316) e [PoC 40241543317](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40241543317) success. Hardware non verificato.
2. Stabilità di avvio/chiusura dei Node: **pubblicata**, verificata su JVM; PoC e iOS ordinario partono dal push e si leggono una volta da conclusi, senza polling (**post-push locale:** commit `e8963d3`, [iOS ordinario 40297802983](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40297802983) e [PoC 40297802933](https://github.com/zanzaro-mirco/lantern-share/actions/runs/40297802933) letti una volta da conclusi: **success**).
3. **B11 pubblicato** (nuovo tentativo dopo una consegna interrotta): leggere **una volta** da concluso il completo Apple avviato dopo il push (il selettore comune e un XCTest cambiano); se fallisce leggere i soli errori del job e correggere prima di ampliare.
4. Dopo un checkpoint riuscito, proposta da confermare con criteri prima del codice: **scelta operativa fra più sessioni usate** (`NeedsChoice` oggi senza ingresso), oppure i residui hardware di fase 1 quando l'utente li riattiva. Scelta dell'utente.

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
