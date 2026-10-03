# Stato sviluppo — 3 ottobre 2026

**Punto di ripartenza:** leggere `AGENTS.md` e `PASSAGGIO_CONSEGNE.md`. Fase 0 chiusa; fase 1 in corso. Collaudi fisici rinviati il 3 ottobre, registrati e non superati; nessun hardware Apple provato. `08dfb86`: percorso Apple in simulatore e Android/desktop verificati; crash Android corretto ma riprova fisica pendente. `56f0de3`: CI artefatti riuscita. `77f554b`: CI regole pure v1 riuscita. Implementati transcript, HELLO e verifica remota v1 isolati; correggono anche il rischio di stack overflow del codec su annidamento ostile. JVM/metadata comuni, unit test Android e APK verificati; nuova CI da verificare. Il servizio rimane v0. Prossimo incremento: payload APPROVE v1 rigoroso, senza attivazione nel trasporto. Le sezioni storiche non descrivono lo stato corrente.

## Fondamenta v1 — transcript, HELLO e verifica remota isolati

Sessione autonoma richiesta dall'utente il 3 ottobre. `ProtocolHandshakeParticipant` copia le capacità e valida identità/nonce. `ProtocolHandshakeTranscript` lega entrambe le offerte canoniche, identità e nonce con campi a lunghezza, ordine simmetrico e domini separati per transcript/conferma direzionale. `ProtocolHandshakeHelloCodec` riusa il serializer delle capacità, rifiuta duplicati anche annidati e input oltre 4608 byte. `ProtocolHandshakeVerification` rifiuta pin TLS discordante, incompatibilità e firma remota invalida; nessun trust o autorizzazione implicita, nessun chiamante di rete. Decisione, vettore SHA-256 e obblighi del futuro adattatore in `docs/ADR-005-TRANSCRIPT-HANDSHAKE-V1.md`.

Revisione avversaria: riprodotto `StackOverflowError` nel codec precedente con array profondamente annidati entro 4096 byte. Corretto con guardia condivisa sulla profondità prima del parser (2 per offerta, 3 per HELLO); regressione verificata con errore di input, non cattura generica degli errori di runtime. Nessuna modifica a wire v0, identità, SQLite, UI, versioni o lock.

Verifiche effettive: `.\gradlew.bat :protocol:jvmTest :protocol:compileCommonMainKotlinMetadata :connectivity:jvmTest --console=plain`, `BUILD SUCCESSFUL` in 6 s dopo la correzione: 48 test protocollo, 20 connettività superati e un multicast opt-in saltato. Tre test JVM usano firme ECDSA/SHA-256 reali, non TLS/keystore. `.\gradlew.bat -Pandroid=true :protocol:testDebugUnitTest :androidApp:assembleDebug --console=plain`, riuscito in 9 s dopo un primo avvio bloccato dalla sandbox con “Accesso negato”: 45 test Android e APK prodotto, non installato. Aggiunto successivamente test di rifiuto HELLO v1 da `Wire` v0: `.\gradlew.bat -Pandroid=true :protocol:jvmTest :protocol:testDebugUnitTest --console=plain` riuscito in 3 s, totale finale 49 test JVM e 46 della variante Android, zero fallimenti/saltati nelle due suite protocollo. Metadata comuni non equivalgono a compilazione Kotlin/Native o Swift. Nuova CI e simulatore Apple pendenti; hardware rinviato.

CI codec precedente `60609c7`, unico controllo iniziale: [iOS](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37125250974) e [Android/desktop](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37125250256) ancora `in_progress`, non chiamate superate e nessun polling. Prossimo passo circoscritto: payload APPROVE v1 con emittente/destinatario/firma e test di indirizzamento, limiti e round-trip; ancora separato dal trasporto. Fase 1 aperta, nessun gruppo/recupero/allegato introdotto. Le sezioni sotto conservano le evidenze precedenti.

## Fondamenta v1 — codec offerte isolato

`ProtocolCapabilitiesCodec` implementato in Kotlin comune con kotlinx.serialization esistente: campi obbligatori, tipi rigorosi, nessun campo sconosciuto o duplicato, insiemi senza duplicati, limiti del modello, UTF-8 rigoroso e limite 4096 byte prima del parsing. Codifica deterministica con funzionalità ordinate. Versioni future rappresentabili, non accettate dal negoziatore. Nessun chiamante di rete, migrazione o cambio al wire v0, DB, identità, versioni/lock. Contratto documentato in ADR 004.

Verifica locale effettiva: `.\gradlew.bat :protocol:jvmTest --console=plain`, `BUILD SUCCESSFUL` in 4 s; 25 test, zero fallimenti/saltati, inclusi cinque nuovi del codec. Primo tentativo: un test negativo fallito per la coercizione numerica `1e0`; aggiunta validazione lessicale, suite ripetuta con successo. CI del nuovo codec e compilazione Kotlin/Native ancora da verificare; nessun hardware testato. CI precedente `77f554b`: [iOS](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37123915990) e [Android/desktop](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37123915955) entrambe `success`, controllate una volta il 3 ottobre.

Prossimo incremento: transcript canonico v1 che vincoli offerte, identità e nonce, con vettori/test di alterazione; leggere `docs/PROTOCOLLO_POC.md` prima di estendere l'associazione. Nessuna attivazione nel trasporto, nessun fallback automatico v0. Collaudi fisici rinviati, fase 1 aperta. Le note sul codec ancora mancante nella sezione precedente conservata sotto sono storiche.

## Fondamenta v1 — contratto di negoziazione isolato

Implementati in Kotlin comune `ProtocolCapabilities`, risultato esplicito compatibile/incompatibile e `ProtocolNegotiation`. Solo versione 1 implementata; intersezione delle capacità, requisiti obbligatori verificati in entrambe le direzioni, nessun fallback v0. Offerte limitate e copia delle collezioni in ingresso; nessuna autorizzazione implicita. Non esistono ancora codec v1, handshake autenticato o chiamanti di produzione. Nessun cambiamento a formato wire v0, schema, identità o lock. Decisione e limiti: `docs/ADR-004-NEGOZIAZIONE-V1.md`.

Verifica effettiva: `.\gradlew.bat :protocol:jvmTest --console=plain`, `BUILD SUCCESSFUL` in 21 s; 20 test, zero fallimenti o saltati, inclusi sei nuovi (intersezione/ordine/simmetria, requisiti dei due peer, opzioni future, versioni non implementate, input/limiti, snapshot). La suite precedente v0 passa invariata. `git diff --check` riuscito. Kotlin/Native e CI del nuovo codice ancora pendenti; nessun hardware provato in questo incremento.

Collaudi rinviati, elencati in `docs/COLLAUDO.md`: residui Android ↔ Windows senza Internet e regressione del crash, iPhone, Mac Intel/ARM64. Non chiudere la fase 1 in loro assenza. Prossimo incremento concreto: codec rigoroso delle offerte v1 con vettori JSON e dimensioni limitate; mantenere il trasporto v0 e non attivare negoziazione non autenticata.

## Preparazione collaudo — artefatti di test

Esiti verificati con `gh run view`: [iOS 36775866536](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36775866536) e [Android/desktop 36775866597](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36775866597), entrambe `success` sullo stesso SHA `08dfb8667b30d330534895bc2221ccd3f87be392`. Riepilogo log XCTest: 19 test, zero fallimenti. Salvataggio prima della ricevuta e riapertura verificati in loopback simulatore, non su LAN fisica.

Il workflow Android/desktop ora carica APK debug e cartella Windows completa di runtime solo dopo build riuscita, con SHA nel nome, errore se manca l'output e conservazione 14 giorni. Non sono release né installer; nessuna credenziale reale aggiunta. La firma debug Android dei runner può variare: aggiornamento preservando i dati solo con firma compatibile; la guida non prescrive cancellazioni automatiche. README e `docs/COLLAUDO.md` aggiornati eliminando i vecchi limiti iOS ormai superati.

Verifica della nuova configurazione: revisione mirata dei percorsi rispetto agli output Gradle e controlli locali di presenza dei pacchetti e `git diff --check`; upload/download Actions ancora da verificare nella nuova run. Nessuna build dell'app ripetuta per questa modifica di soli workflow/documentazione. Prossimo incremento concreto: eseguire e registrare la prima prova Android ↔ Windows descritta in `docs/COLLAUDO.md`; i collaudi iPhone e Mac restano obbligatori in fase 1.

Le sezioni seguenti sono storiche: la verifica Apple pendente di `TEXT/ACK` è ora superata dalla CI `08dfb86`.

## Testo e ricevute iOS — implementati, verifica Apple pendente

Il canale iOS ora invia/riceve TEXT firmati e ACK compatibili con Android/JVM. Costruttori, validazione UTF-8/UUID e byte canonici in Kotlin; Crypto/Security e socket in Swift. Nessun cambio a wire-v0, schema, identità o lock. Autorizzazione e trust vengono ricontrollati per messaggi e ricevute; mittente/certificato/sessione/firma vincolati al canale. SQLite salva prima dell'invio ACK, deduplica gli stessi frame e rifiuta ID in conflitto. Ricevute ammesse solo per invii pendenti della connessione corrente. Il mittente salva prima dell'invio, mantiene il testo senza ricevuta se il canale si chiude; nessun recupero/ritrasmissione automatica.

UI: peer collegato, campo testo massimo 8192 byte, cronologia locale caricata anche all'avvio e indicatore ricevuta dopo commit remoto. Invio vincolato all'ID del destinatario mostrato, non a un eventuale nuovo canale. SQLite e firma sulla coda servizio, stato Compose sul main. Solo due peer; niente allegati, inoltro, protocollo v1 o gruppo.

Verifica Windows: `.\gradlew.bat :protocol:jvmTest :connectivity:jvmTest :ui:compileCommonMainKotlinMetadata :ui:compileKotlinJvm --console=plain`, `BUILD SUCCESSFUL` in 24 s; 35 casi JVM, 34 riusciti, un multicast opt-in saltato. Tre test nuovi TextWire verificano compatibilità, identificatori/limiti e rifiuto di unsigned TEXT. `git diff --check` riuscito. UI JVM/common task già aggiornati: non compilano iOS né Swift.

Aggiunti nove XCTest nativi di messaggistica e test SQLite Kotlin/Native di salvataggio/ricevuta/deduplica/conflitto/riapertura. TLS, Keychain e SQLite reali nei test; solo l'errore del repository è iniettato per verificare il mancato ACK. **Nuovi test scritti ma non compilati/eseguiti su Windows.** Baseline precedente verificata: [CI dba224a](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36770172809), tutta verde. Prossimo passo concreto: verificare la nuova CI iOS, poi collaudo fisico testo bidirezionale/riapertura su iPhone ↔ Android o desktop. Hardware Apple sempre pendente in fase 1.

## CI iOS selettiva — configurata, attivazione remota pendente

Il job iOS è trasferito invariato da `verify.yml` a `.github/workflows/ios.yml`. Android e desktop continuano a ogni push/PR. Il nuovo workflow parte per app Apple, sorgenti Kotlin condivisi/iOS e schema SQLDelight, build Gradle, wrapper/catalogo/lock pertinenti e setup CI iOS; esclude sorgenti Android/JVM e documentazione. Dispatch manuale disponibile per la sola verifica Apple. Nessuna nuova action, dipendenza o versione; nessun test disabilitato. Limiti dei filtri e procedura manuale nel README.

Verifica locale: controlli strutturali Node dei job invariati, filtri push/PR identici, dispatch presente e 26 vettori di percorsi riusciti; `git diff --check` riuscito. Non è validazione del motore Actions su GitHub. La modifica al nuovo workflow avvierà una verifica iOS; i successivi push non pertinenti non la avvieranno. La CI `dba224a` era ancora in corso all'unico controllo, con Android/desktop riusciti. Prossimo passo: verificare l'esito XCTest e il nuovo workflow alla prossima richiesta; collaudi fisici in fase 1 sempre obbligatori.

## Correzione aspettative XCTest — implementata, esecuzione Apple pendente

La [CI 36766891297](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36766891297), commit `c8027b2`, conferma il setup runtime e la compilazione Swift/Kotlin. Android e tutti i job desktop passano. In simulatore passano i cinque test Keychain, TLS con pin esatti e trasferimento byte, doppia conferma con una scrittura trust per peer, scadenza monotona. Falliscono cancellazione (`unwaited expectation 'server admitted'`) e pin errato (timeout aspettando `.failed`, mentre il log mostra rifiuto TLS e stato `.waiting`).

Il test cancellazione crea l'aspettativa server solo nel ramo che ne richiede l'ammissione; conserva l'aspettativa client invertita e il controllo zero scritture client. Il test negativo TLS accetta come segnale di rifiuto `.waiting` o `.failed` **solo con errore TLS non riuscito**; errori DNS/POSIX e `.ready` fanno fallire il test. La connessione viene cancellata al primo esito. Nessun test rimosso, timeout aumentato o codice produttivo modificato.

Controllo locale: revisione mirata e `git diff --check`; nessuna build Gradle pertinente a una modifica solo XCTest, nessun Xcode su Windows. I due test corretti non sono ancora compilati/eseguiti. Prossimo passo: verificarli nella nuova CI prima della messaggistica iOS. Fase 1 e collaudi fisici Apple restano aperti.

Le sezioni seguenti conservano le evidenze precedenti; i limiti di compilazione/setup indicati sotto sono superati dalla CI `c8027b2`.

## Setup CoreSimulator CI — implementato, verifica macOS pendente

La [CI 36765117114](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36765117114), commit `67efea1`, ha superato Android e tutti i job desktop, ma si è fermata su `xcodebuild -downloadPlatform iOS -buildVersion 18.4`: `Unable to connect to simulator`, exit 70. Non ha compilato né testato la revisione Swift.

Il setup ora inizializza i componenti Xcode, interroga CoreSimulator prima del download (workaround dei manutentori di [runner-images #12862](https://github.com/actions/runner-images/issues/12862)), scarica soltanto se il runtime esatto non è disponibile e ne verifica la disponibilità prima dei task Kotlin/XCTest. Errori del servizio, JSON non valido e download fallito restano bloccanti. Log in `build/ios-simulator-setup.log`, conservato nell'artefatto CI anche in caso di fallimento. Nessun aggiornamento di versioni, nessun test nativo rimosso.

Controlli locali Windows con Git Bash: `bash -n .github/scripts/prepare-ios-simulator.sh`, `bash -n .github/scripts/test-prepare-ios-simulator.sh` e `bash .github/scripts/test-prepare-ios-simulator.sh` riusciti; sette scenari verificati con sostituti dei comandi Apple confinati ai test. Non equivalgono alla verifica reale del runtime su macOS. Nessuna build Gradle rilanciata per questa modifica di infrastruttura. Prossimo passo: verificare una volta la nuova CI, poi compilazione Swift e XCTest se il setup passa. Collaudi fisici Apple ancora pendenti in fase 1.

## Associazione iOS sopra TLS — implementata, verifica nativa pendente

Controlli locali della revisione: ` .\gradlew.bat :protocol:jvmTest :connectivity:jvmTest :ui:compileCommonMainKotlinMetadata :ui:compileKotlinJvm --console=plain` riuscito (task già aggiornati), `git diff --check` riuscito. Questi task non compilano `iosMain` né Swift su Windows. Verifica nativa richiesta per il nuovo ponte al backoff Kotlin e i nuovi test.

Revisione del 30 settembre: corretti il vincolo tra certificato e connessione TLS (prima basato su una cache globale per ID), i callback dopo cancellazione, il doppio tap su Conferma, la scadenza monotona indipendente dal timer, il caricamento TXT Bonjour e i callback di precedenti attivazioni. Il tentativo di pairing ora conserva la selezione durante errori temporanei e riprova con backoff/jitter Kotlin entro la finestra originale. Corretto anche il `try` mancante nella lettura Swift del trust. Aggiunti test nativi per certificato della connessione, doppia conferma, cancellazione durante invio e scadenza. **Test nativi scritti ma non ancora compilati/eseguiti** su questo host Windows. La [CI 36635631396](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36635631396), commit `773282d`, si è fermata nuovamente nel download del runtime (`Unable to connect to simulator`), prima di verificare il codice Swift. Nessun cambiamento a wire, schema o identità persistenti.

L'app iOS pubblica ora un listener TLS 1.3 tramite Bonjour con gli stessi metadati `id`, `name` e `v=0` usati da Android e desktop, risolve i peer scoperti e applica l'iniziatore deterministico già definito dal dominio. La selezione locale apre una finestra di 120 secondi e consente al TLS soltanto pin già autorizzati o il singolo candidato selezionato.

Il flusso scambia `HELLO`, calcola il transcript canonico in Kotlin, mostra per intero il digest SHA-256, firma `APPROVE` con la chiave Keychain e verifica la conferma remota contro il certificato effettivamente accettato dal TLS. Il trust viene scritto nel repository SQLDelight soltanto dopo entrambe le conferme e dopo che Network.framework ha elaborato l'invio locale. Rifiuto, scadenza, arresto, frame imprevisti e identità TLS/HELLO discordanti chiudono il canale senza persistere il candidato. Alla riapertura vengono caricati i pin autorizzati e sono ammessi i reconnect TLS; testo e ricevute restano fuori da questo incremento.

Il formato wire v0 non cambia. I costruttori `HELLO/APPROVE`, transcript, codice visualizzato, framing, validazione JSON e byte canonici da firmare restano Kotlin; Swift gestisce Network.framework, CryptoKit, Security e ciclo di vita iOS. `PairingWire` rifiuta ora identità, nonce, sessioni e firme malformati prima che raggiungano il trasporto; i relativi casi negativi sono coperti nei test comuni. Aggiunto un controllo XCTest del certificato remoto associato al pin dopo l'handshake.

Verifica locale Windows riuscita: `:protocol:jvmTest`, `:connectivity:jvmTest`, `:ui:compileCommonMainKotlinMetadata`, `:ui:compileKotlinJvm`, `:androidApp:assembleDebug` e risoluzione bloccata di `iosArm64CompileKlibraries`, `iosSimulatorArm64CompileKlibraries`, `iosX64CompileKlibraries`. La [CI 36633931340](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36633931340) ha compilato il framework ed eseguito i test condivisi; la build app si è fermata sull'optional `SecKeyCopyAttributes`, ora gestito esplicitamente. La ricompilazione Swift, gli XCTest aggiornati e l'hardware iPhone restano **non verificati**. Prossimo passo concreto: verificare la correzione Swift su macOS; soltanto dopo estendere il canale iOS a `TEXT/ACK`.

## Chiusura TLS Android fuori dal thread UI — implementata, collaudo fisico pendente

Il log reale mostrava `NetworkOnMainThreadException` in `ConscryptEngineSocket.close`, chiamato da `PeerConnection.close()` attraverso `Node.block()` dopo il tap su “Blocca localmente”. La chiusura di una socket TLS può inviare `close_notify` e quindi eseguire I/O: non può avvenire nel callback Compose sul main thread.

`AsyncResourceCloser` confina ora le chiusure potenzialmente bloccanti nello scope `Dispatchers.IO` già posseduto dal nodo. Blocco e rifiuto aggiornano subito autorizzazione e UI, poi chiudono il canale in asincrono. Anche `stop()` stacca immediatamente il run e demanda socket/listener a I/O; `close()` attende il cleanup prima di terminare lo scope. Aggiunto un test che verifica l'esecuzione sul dispatcher proprietario; il test end-to-end esistente continua a coprire blocco e disconnessione TLS reali.

Verifica locale riuscita: `:connectivity:jvmTest`, `:androidApp:assembleDebug` e `:androidApp:lintDebug`; 21 casi nel report, zero fallimenti e un test nativo Mac saltato come previsto. `BUILD SUCCESSFUL` in 19 secondi. Da verificare sul telefono: collegarsi a Windows e usare “Blocca localmente”, “Rifiuta” e “Arresta” senza crash.

## Trasporto TLS iOS con pinning — implementato, verifica nativa pendente

Il package Swift contiene ora `AppleTLSTransport`, che crea listener e connessioni Network.framework esclusivamente TLS 1.3. Usa la `SecIdentity` persistente, richiede l'identità del peer e accetta soltanto certificati con pin esplicitamente fornito dal chiamante, chiave EC P-256, firma ECDSA/SHA-256, validità temporale e autofirma verificata. Un insieme vuoto, un pin malformato o diverso rifiuta l'handshake; Bonjour non conferisce trust.

Il nuovo `WireFrameDecoder` comune gestisce il prefisso uint32 big endian, frammentazione, frame consecutivi e limite di 65.536 byte, delegando ogni payload a `Wire`. `IosWireFraming` lo espone a Swift, quindi Network.framework non duplica JSON o regole Kotlin. L'associazione, la persistenza del trust, HELLO/APPROVE e il testo restano deliberatamente fuori dall'incremento.

Verifica locale Windows riuscita: `:protocol:jvmTest` e `:ui:compileCommonMainKotlinMetadata` in 8 secondi; anche `:ui:compileIosMainKotlinMetadata` termina senza errori ma il task iOS è saltato sull'host non Apple, quindi non costituisce compilazione nativa. Aggiunti XCTest con listener/connessione loopback reali per handshake reciproco, trasferimento di byte e rifiuto del pin errato. La compilazione Swift e l'esecuzione sul simulatore sono pendenti fino alla CI. Decisione in `docs/ADR-003-TRASPORTO-TLS-IOS.md`.

Prossimo passo: verificare una volta il job iOS del commit; se riesce, il prossimo incremento separato sarà l'associazione iOS sopra il trasporto autenticato.

## Correzione firma TLS Android — implementata e verificata su hardware

Nel primo collaudo reale Android ↔ Windows entrambi i dispositivi si sono scoperti sulla LAN, ma l'associazione si è fermata prima del codice di confronto con `SSLHandshakeException`. Il log reale Android ha identificato `KeyStoreException: Incompatible digest` durante `CryptoUpcalls.ecSignDigestWithPrivateKey`: la chiave non esportabile era autorizzata per `SHA-256`, mentre Conscrypt TLS 1.3 usa `NONEwithECDSA` su un digest già calcolato per `CertificateVerify`.

La generazione della chiave autorizza ora sia `SHA-256` sia `NONE`, senza modificare protocollo, pinning o formato dell'identità. All'apertura viene eseguita una firma di compatibilità senza contenuti; una vecchia chiave incompatibile produce un messaggio esplicito e non viene sostituita silenziosamente. Poiché le autorizzazioni Android Keystore sono immutabili, sul dispositivo di prova occorre cancellare una volta i dati dopo l'installazione del nuovo APK: l'ID cambia e qualsiasi associazione precedente deve essere ripetuta.

Verifica locale riuscita: `:androidApp:assembleDebug`, `:androidApp:lintDebug` e `:connectivity:jvmTest`; build completata in 56 secondi. Questi controlli non esercitano Android Keystore/Conscrypt reali. Dopo reinstallazione e rinnovo dell'identità, l'utente ha confermato sul telefono che il percorso prima bloccato completa il collegamento con Windows e che la comunicazione funziona. Non sono ancora documentati separatamente testo in entrambe le direzioni e riavvio dei due processi.

**Stato delle fasi:** fase 0 chiusa sulla prova fisica Android ↔ Windows riuscita. La fase 1 include il completamento del percorso Apple, i collaudi fisici obbligatori su iPhone, Mac Intel e Mac Apple Silicon e le verifiche residue Android ↔ Windows: WAN disattivata, testo esplicitamente bidirezionale e riavvio dei processi.

## Persistenza SQLDelight iOS — implementata e verificata in CI

Lo schema SQLDelight e i contratti `DeviceRepository` esistenti sono ora condivisi anche con iOS. Il nuovo adattatore usa `native-driver` 2.1.0, conserva `lantern.db` nella cartella Application Support dell'app, serializza l'accesso con un lock nativo e rende esplicita la chiusura del driver. La logica delle query è stata estratta in un componente comune senza cambiare schema, formato dei dati o comportamento degli adattatori JVM/Android.

La schermata Compose iOS legge il nome persistito all'avvio e permette di salvarne uno valido. Apertura, lettura e scrittura del database avvengono su una coda non UI; gli errori restano visibili. Il trasporto TLS, l'associazione e la messaggistica iOS rimangono esplicitamente non disponibili.

Aggiunto un test Kotlin/Native che crea un database reale in una directory temporanea del simulatore, salva il nome, chiude il driver, riapre lo stesso database e verifica il valore. Il workflow iOS esegue ora anche `:persistence:iosSimulatorArm64Test` e conserva il relativo report.

La [CI 36471901305](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36471901305), commit `28e7015`, ha compilato il repository iOS, il framework UI e i test di protocollo; Android e tutti i job desktop/Mac sono riusciti. Il nuovo test SQLite si è fermato in compilazione perché due chiamate Foundation richiedevano l'opt-in `ExperimentalForeignApi`. L'opt-in è stato aggiunto esclusivamente al test.

La [CI 36473189762](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36473189762), commit `86f90fb`, ha superato compilazione ed esecuzione del test SQLite: salvataggio, chiusura e riapertura sono quindi verificati sul simulatore. Si è poi fermata al link dell'app Xcode per simboli `_sqlite3_*` irrisolti in entrambe le architetture del simulatore; il framework Kotlin statico richiede che il target consumatore colleghi la libreria SQLite di sistema. Aggiunto `-lsqlite3` ai soli linker flags del target app.

La [CI 36474723744](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36474723744), commit `1efb3da`, è interamente riuscita: framework e test iOS condivisi, test SQLite di salvataggio/riapertura, link dell'app simulatore e cinque XCTest Keychain, oltre ad Android e desktop Windows/Linux/Mac Intel/ARM64.

Verificato su Windows: `:persistence:jvmMainClasses`, `:ui:jvmMainClasses`, `:connectivity:jvmTest` e la compilazione metadata comune sono riusciti; i lock del driver nativo sono stati risolti per iPhone arm64 e simulatori arm64/x64. In CI il framework iOS, il test salvataggio-riapertura e l'app Xcode con SQLite collegato sono riusciti. **Nessun dispositivo Apple fisico è stato provato:** tale verifica è ora un criterio della fase 1.

## CI remota e identità iOS — incremento verificato in simulatore

Prima CI reale, commit `e348fca`: **desktop Windows, Linux, Mac ARM64 e Mac Intel riusciti**, incluse build con runtime e test nativi Portachiavi Mac. Il framework Kotlin iOS e i test di protocollo sono arrivati a completamento; l'app Swift si è fermata per runtime iOS 18.4 assente. Android si è fermato nel setup dell'SDK per il pacchetto legacy `tools`. Questi risultati aggiornano i precedenti resoconti che dichiaravano la CI non ancora eseguita. Non sono prove su dispositivi fisici.

Correzione `af69849`: installazione esplicita di `platform-tools` per Android e runtime iOS 18.4 per Xcode 16.3. Versioni Kotlin/Gradle/Compose invariate.

Esito correzione: [CI 36392913603](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36392913603) **tutta riuscita**, inclusa app iOS unsigned su simulatore e Android. Verifica locale dopo rinomina in `lantern-share`: comando Gradle completo con multicast, test, distributable Windows, APK e lint riuscito in 1m08s; 26 test senza fallimenti/saltati. Non equivale a collaudo LAN tra dispositivi fisici.

Implementato l'adattatore Swift `LanternIdentity`: chiave P-256, certificato autofirmato tramite Swift Certificates Apple, pin persistente e SecIdentity nel Keychain, firma SHA-256/ECDSA; apertura fuori dal thread UI e ID mostrato nella schermata Compose. Dati parziali o incoerenti bloccano l'avvio senza rigenerazione automatica. Aggiunti cinque XCTest con Keychain reale del simulatore, dipendenze Swift esatte e integrazione XcodeGen/CI. Decisioni in `docs/ADR-002-IDENTITA-IOS.md`.

La prima compilazione nativa ha rilevato un difetto di Swift Certificates 1.6.0 (`kSecAttrKeyTypeECDSA` non disponibile su iOS). Selezionata la release ufficiale 1.7.0 che usa `kSecAttrKeyTypeECSECPrimeRandom`, con Swift tools 5.9; lock e fonti aggiornati. Rimossi DocC/SymbolKit, non richiesti dalla nuova versione. Nessuna patch locale alla libreria e nessun bypass di sicurezza.

La [CI 36394483320](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36394483320) ha compilato con successo l'app iOS con il nuovo adattatore e lock Swift; tutti i job desktop/Android sono passati. Il bundle XCTest si è fermato al link prima di eseguire i test, cercando un framework Crypto generato ma assente. Rimossa la dipendenza package duplicata dal target di test ospitato dall'app nel commit `98502d1`.

La [CI 36432550052](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36432550052), commit `5505384`, ha superato il link ed eseguito cinque XCTest, tutti falliti per `errSecMissingEntitlement` (-34018) sull'host unsigned. Aggiunti anche il requisito plist di avvio Compose e l'isolamento dei flag Kotlin al target app. Il commit `6aa051f` configura entitlement e firma locale ad hoc esclusivamente per il simulatore, senza credenziali Apple Developer. Nessun test viene saltato per mascherare il rifiuto del Keychain.

**Esito finale:** [CI 36433898550](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36433898550), commit `6aa051f`, interamente riuscita: Android, desktop Windows/Linux/Mac Intel/Mac ARM64 e iOS. **Cinque XCTest eseguiti, zero fallimenti**, sul simulatore iPhone 16 / iOS 18.4 con Xcode 16.3. Verificati riapertura con certificato/ID invariati, firme con chiave ordinaria e SecIdentity destinata a TLS, rifiuto del testo alterato, rifiuto di chiave/certificato mancanti e pin cambiato, attributi Keychain locali e legati allo sblocco. Il precedente errore di link e il rifiuto degli entitlement sono risolti. Il bundle `.xcresult` è conservato nell'artefatto `ios-verification` della CI.

Comando nativo effettivamente riuscito (ID del simulatore creato dal workflow):

```sh
xcodebuild -project iosApp/Lantern.xcodeproj -scheme Lantern -configuration Debug \
  -destination "platform=iOS Simulator,id=$device_id" \
  -resultBundlePath build/ios-identity-tests.xcresult \
  -onlyUsePackageVersionsFromResolvedFile CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- test
```

**Non verificato su dispositivi fisici:** iPhone reale, protezione con dispositivo bloccato, riavvio completo del dispositivo, aggiornamento/reinstallazione e prove LAN tra piattaforme. Il test degli attributi non è una prova hardware di blocco/sblocco. iOS non ha ancora listener/connessione TLS, associazione, messaggistica o repository SQLite. Il prossimo incremento è collegare Network.framework al protocollo condiviso e introdurre la persistenza iOS, mantenendo esplicito lo stato non autorizzato prima della doppia conferma. Fase 0 aperta; nessuna release pubblicata e nessuna credenziale di firma reale utilizzata.

## Storico — incremento Portachiavi macOS precedente all'identità iOS

Implementato l'adattatore desktop `MacKeychainIdentityStore` usando il provider Apple del JDK 17, senza cambiare versioni o lock. L'ingresso Mac lo seleziona automaticamente; Windows/Linux mantengono PKCS#12. La migrazione importa chiave e certificato originali, preservando ID e associazioni; mantiene il backup cifrato e azzera il buffer applicativo della passphrase. Dopo l'importazione riapre il provider e verifica pin e firma.

Il riferimento pubblico `mac-identity.ref` impedisce rotazioni silenziose in caso di chiave mancante, sostituita o importazione interrotta. Nessun ripiego su un keystore diverso. Un profilo Mac copiato su Windows/Linux senza backup della chiave viene rifiutato. L'adattatore, la procedura di migrazione e l'ingresso UI sono separati; il motore di rete e il protocollo rimangono invariati.

Limite esplicito: il provider JDK esporta la chiave in memoria; non è una chiave non esportabile/Secure Enclave. Una creazione nuova interrotta prima dell'importazione lascia un riferimento senza chiave e richiede recupero esplicito o nuovo profilo. Dettagli e motivazioni in `docs/ADR-001-IDENTITA-MAC.md`, richiamato dal documento di architettura.

Aggiunti otto test portabili: riapertura/spostamento, migrazione conservativa, password errata/annullamento, chiave mancante/sostituita, ripresa della migrazione interrotta, riferimento corrotto/database orfano, creazione interrotta e chiave privata incoerente. Crittografia e filesystem reali; solo il confine Portachiavi viene sostituito nei test. Aggiunto un test nativo opt-in e una procedura CI con Portachiavi usa e getta su Mac ARM64/Intel. Tale prova non è eseguita né conteggiata fra i test Windows.

**Fase 0 ancora aperta.** Questo incremento copre l'implementazione del Portachiavi desktop, non il percorso iOS inizialmente considerato insieme a esso. iOS resta una sonda Bonjour: identità Keychain, trasporto autenticato e messaggistica iPhone sono ancora da implementare. Prossimo incremento concreto: adattatore di identità iOS e ponte TLS Network.framework verso il protocollo condiviso, poi persistenza e UI del percorso completo. I collaudi Mac nativi vanno eseguiti sulle due architetture; nessun dispositivo fisico è stato usato e nessuna release è stata pubblicata.

Verifica finale Windows riuscita in **18 secondi**, senza aggiornare i lock:

```powershell
.\gradlew.bat -Pandroid=true -Pmulticast=true :protocol:jvmTest :connectivity:jvmTest :desktopApp:createDistributable :androidApp:assembleDebug :androidApp:lintDebug --console=plain
```

**26 test nei rapporti, zero fallimenti/errori e zero saltati**: 8 nuovi sul confine Portachiavi, 6 integrazione TLS/SQLite, 6 protocollo (task già aggiornato), 3 autorizzazione, 2 framing, 1 mDNS reale sullo stesso host. Il test Apple è escluso su Windows. Pacchetto Windows rigenerato; build APK e lint Android riusciti (0 errori, 18 warning). Nessuna build Apple/Linux né esecuzione della CI remota. I resoconti seguenti sono storici; le loro lacune Portachiavi sono superate quanto all'implementazione, non al collaudo nativo.

## Revisione architettura e mantenibilità — incremento precedente

Su richiesta dell'utente è stata aggiunta al piano la responsabilità di sviluppatore Kotlin/KMP e software architect senior. Il nuovo documento `ARCHITETTURA_E_QUALITA.md` definisce il metodo operativo e contiene il registro della revisione eseguita. I requisiti di prodotto e l'apertura della fase 0 rimangono invariati.

Refactoring applicato: source set JVM/Android espliciti; repository SQLite nel modulo persistence dietro contratti di dominio; canale, framing e autorizzazione estratti da Node; token di pairing e tempo monotono; risorse/callback isolati per attivazione; frame tipizzati con JSON v0 invariato; limiti condivisi; componenti UI separati; cleanup esplicito degli ingressi app. Nessun aggiornamento di libreria. `.editorconfig` aggiunto.

Verifica finale **riuscita senza riscrivere i lock**, 24 secondi:

```powershell
.\gradlew.bat -Pandroid=true -Pmulticast=true :protocol:jvmTest :connectivity:jvmTest :desktopApp:createDistributable :androidApp:assembleDebug :androidApp:lintDebug --console=plain
```

**18 test, zero fallimenti, zero test saltati:** protocollo 6, integrazione 6, autorizzazione 3, framing 2, mDNS reale sullo stesso host 1. Lint: **0 errori, 18 warning** (versioni/target API, trust manager personalizzato, configurazione backup/icona); nessun warning è stato soppresso per far passare la build. I rapporti aggiornati sono in `connectivity/build/reports/tests/jvmTest/`, `protocol/build/reports/tests/jvmTest/` e `androidApp/build/reports/`.

Verificata anche la risoluzione, senza aggiornamento, dei lock `macos-arm64`, `macos-x64` e `linux-x64` tramite `:desktopApp:lockDesktopDependencies`. Non equivale a compilazione Mac/Linux. CI aggiornata al task `:connectivity:jvmTest`, ma non eseguita sul servizio remoto. La UI non è stata collaudata graficamente e NSD Android non è stato provato su telefono.

Il resto del documento conserva il resoconto storico del primo incremento: i vecchi comandi `:connectivity:test` descrivono quella verifica e sono ora sostituiti da `:connectivity:jvmTest`. Nessuna fase di prodotto è stata chiusa mediante il refactoring.

## Esito del primo incremento

**Fase 0 aperta, non validata. Fase 1 soltanto avviata.** È stato implementato un percorso eseguibile desktop e compilabile Android; il traguardo Android–iPhone–Mac non è ancora raggiunto. iOS non ha ancora identità crittografica, associazione o trasporto: non si tratta soltanto di test hardware mancanti.

Il repository iniziale conteneva esclusivamente `PIANO_SVILUPPO.md`, nessun `.git` e nessun AGENTS.md trovato nella cartella o negli antenati controllati. Il primo incremento aveva lasciato la specifica invariata (SHA-256 originario: `E5A2B375384B0998B96CBBF1B1B1838311C8B3B3B65BEDCE9DE0E1D30A373530`). Su successiva richiesta esplicita dell'utente, il piano è stato integrato con ruolo e criteri di qualità; requisiti e criteri di accettazione del prodotto non sono stati cambiati.

## Implementato

- Nome provvisorio Lantern; Gradle Wrapper 8.9 ufficiale con verifica SHA-256; catalogo versioni, lock delle dipendenze JVM/Android e lock desktop distinti per Windows x64, Linux x64, Mac ARM64 e Mac x64. Fonti e compatibilità in `docs/VERSIONI.md`.
- Moduli KMP dominio, protocollo, persistenza e UI; ingressi Android, desktop JVM e iOS. Mac previsto da subito con runtime incluso e packaging DMG separato per architettura, metadati rete locale nel plist. Nessun sito/demo web.
- Desktop: identità P-256 persistente in PKCS#12 cifrato con passphrase utente; creazione atomica, blocco di istanza, nome e trust in SQLite tramite SQLDelight.
- LAN desktop: JmDNS sulla singola interfaccia IPv4 scelta; annunci `_lantern._tcp`, nome/ID/versione; nessuna scansione di sottorete.
- Selezione reciproca di un candidato per 120 secondi, TLS 1.3 con certificati esattamente vincolati al pin, codice SHA-256 legato ai nonce della connessione, conferma esplicita su entrambi, ammissione firmata persistente. Nessun certificato sconosciuto accettato automaticamente e nessun trust-all nel motore.
- Testo ECDSA firmato e cifrato nel trasporto; verifica mittente/canale/sessione, limiti frame/testo, SQLite idempotente, ricevuta dopo persistenza. Le firme usano dati canonici con lunghezze esplicite.
- Riconnessione con backoff/jitter e iniziatore deterministico, blocco locale del peer, arresto listener/socket/discovery.
- UI Compose: nome, attivazione, scoperti, associazione/confronto/rifiuto, destinatario, invio/ricezione e cronologia locale recente.
- Android: stessa UI e motore TLS, `NsdManager`, chiave non esportabile in Android Keystore, SQLite Android, backup disabilitato. Bouncy Castle escluso dall'APK. Servizio solo in primo piano in questo incremento.
- iOS: target arm64 dispositivo, simulatori arm64/x64, ingresso Compose, progetto generabile con XcodeGen 2.43.0, permessi Bonjour e sonda `NWBrowser` reale. **Solo scoperta, niente messaggistica iOS.**
- CI dichiarata per Windows, Linux, Mac Intel/ARM64, build/lint Android e compilazione iOS senza firma; README e collaudo fisico riproducibile.

## Verifiche eseguite su Windows 11 x64

Host: Java Temurin 17.0.20.1 per daemon/toolchain. Il launcher del Wrapper ha inizialmente rilevato il JBR 25 configurato in JAVA_HOME, mentre la configurazione Gradle host impone JDK 17. SDK Android preesistente in AppData, inizialmente non leggibile dalla sandbox e poi verificato con autorizzazione. Nessun SDK installato dall'agente e nessuna licenza accettata per conto dell'utente.

Comandi riusciti durante lo sviluppo:

```powershell
.\gradlew.bat --version
.\gradlew.bat :protocol:jvmTest :connectivity:test :desktopApp:classes --write-locks --console=plain
.\gradlew.bat -Pandroid=true :androidApp:assembleDebug :androidApp:lintDebug --write-locks --console=plain
.\gradlew.bat -Pmulticast=true :protocol:jvmTest :connectivity:test :desktopApp:createDistributable --write-locks --console=plain
.\gradlew.bat -PdesktopPlatform=macos-arm64 :desktopApp:lockDesktopDependencies --write-locks --console=plain
.\gradlew.bat -PdesktopPlatform=macos-x64 :desktopApp:lockDesktopDependencies --write-locks --console=plain
.\gradlew.bat -PdesktopPlatform=linux-x64 :desktopApp:lockDesktopDependencies --write-locks --console=plain
```

Verifica conclusiva sul codice consegnato, **senza** aggiornare i lock: `BUILD SUCCESSFUL`, 51 secondi:

```powershell
.\gradlew.bat -Pandroid=true -Pmulticast=true :protocol:jvmTest :connectivity:test :desktopApp:createDistributable :androidApp:assembleDebug :androidApp:lintDebug --console=plain
```

Suite: 4 test protocollo/backoff, 5 test identità/persistenza/TLS, 1 prova mDNS reale sullo stesso host. Copertura significativa:

- rifiuto versione sconosciuta, frame malformati/oversize e nonce invalidi;
- transcript simmetrico e legato ai nonce, serializzazione firmata non ambigua;
- persistenza identità, passphrase errata e firma alterata;
- pin inatteso rifiutato anche con handshake TLS reale;
- persistenza SQLite, deduplicazione e conflitto di ID;
- necessità della doppia conferma, testo Unicode, ricevuta, riconnessione e blocco;
- scoperta reciproca tramite multicast reale tra due JmDNS sullo stesso host.

Nel test end-to-end la discovery è sostituita da un elenco controllato; socket, crittografia, filesystem e SQLite sono reali. La prova mDNS separata non simula la rete. Non è una prova su due dispositivi.

Artefatti locali: `androidApp/build/outputs/apk/debug/androidApp-debug.apk` e `desktopApp/build/compose/binaries/main/app/Lantern/Lantern.exe` con cartelle `app`/`runtime`. Il pacchetto Windows è stato costruito, non installato né collaudato graficamente. Nessuna firma release, notarizzazione o pubblicazione. L'APK usa soltanto la firma debug standard del toolchain.

I warning lint sono mantenuti visibili: baseline target API/plugin non recente e controllo manuale richiesto dal trust manager a pin. Nessun errore lint. I warning non equivalgono a una revisione di sicurezza superata.

## Non verificato e lavoro mancante

- Nessuna compilazione iOS/macOS/Linux eseguita: la risoluzione dei loro artefatti Maven **non** è una build. Nessun Xcode su Windows. CI scritta ma mai eseguita su un remote.
- Nessuna installazione/esecuzione Android, nessun iPhone o Mac reale provato. UI compilata, non collaudata visivamente o con lettori schermo.
- iOS: mancano Keychain, certificati, NWListener/NWConnection TLS, pinning, associazione e driver SQLite. La sonda non sostituisce questi requisiti.
- Desktop: Portachiavi macOS, DPAPI/Secret Service non integrati; la passphrase PKCS#12 è una protezione provvisoria dichiarata. Metadati privacy Mac aggiunti ma comportamento dei prompt ancora da provare.
- Protocollo 0 di prova tra due peer, non v1 completo: assenti gruppo transitivo, credenziali delegate, sessioni LAN persistenti/convergenti, esclusione cronologia pre-ammissione, sincronizzazione e recupero. La sessione PoC è per connessione.
- Se il canale cade durante le conferme, può restare trust su un solo lato; ripristino manuale mediante blocco su entrambi e nuova associazione. Commit dell'ammissione da rendere recuperabile.
- IPv6 end-to-end, collegamento manuale UI, cambio rete automatico, rate limiting robusto, idle heartbeat e test di 10 peer non completati. I frame sono limitati ma manca una quota dello storico su disco.
- Android foreground service, notifiche, integrazioni desktop/tray, vita senza finestra, file, allegati, politiche di conservazione e packaging di rilascio restano fuori da questo incremento.
- I test non costituiscono audit crittografico; prima della beta serve revisione indipendente del pairing e del modello di gruppo.

## Prossimo incremento concreto

Portare il percorso autenticato su iOS con identità Keychain e Network.framework, mantenendo gli stessi vettori di protocollo e limiti; integrare il Portachiavi desktop Mac; compilare con Xcode su Mac ARM64 e Intel. Poi eseguire Android ↔ Mac, iPhone ↔ Mac e Android ↔ iPhone su LAN senza WAN secondo `docs/COLLAUDO.md`. Parallelamente rendere recuperabile l'ammissione interrotta prima di introdurre il modello di gruppo. Nessuna chiusura della fase 0 senza queste implementazioni e prove.
