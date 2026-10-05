# Lantern — condivisione locale KMP

**Prototipo sperimentale; fase 0 chiusa, fase 1 in corso.** Nome tecnico provvisorio, senza decisioni di branding. La specifica resta [PIANO_SVILUPPO.md](PIANO_SVILUPPO.md). Risultati verificati e lacune sono in [STATO_SVILUPPO.md](STATO_SVILUPPO.md).

Il desktop contiene un percorso reale: identità persistente, mDNS, associazione esplicita su entrambi gli schermi, TLS 1.3 reciproco, testo firmato, SQLite e ricevute dopo salvataggio. Android riusa protocollo e motore TLS con NSD e Keystore nativi. iOS implementa identità Keychain, SQLite, Bonjour, TLS, associazione e testo/ricevute, verificati in simulatore sul commit `08dfb86`; collaudi fisici Apple pendenti. Non è l'app completa prevista dal piano. Gli esiti delle build e dei test effettivi sono in STATO_SVILUPPO.md.

## Struttura

| Modulo | Responsabilità |
|---|---|
| `domain` | Contratti, stato UI, backoff e scelta dell'iniziatore |
| `protocol` | Frame JSON rigorosi, limiti, serializzazione canonica per firme |
| `persistence` | Schema e query SQLDelight condivisi |
| `connectivity` | Orchestrazione, autorizzazione e TLS JVM/Android; PKCS#12 e JmDNS desktop |
| `ui` | Compose condiviso, ingresso iOS |
| `desktopApp` | Ingresso JVM Windows, Linux e Mac Intel/Apple Silicon |
| `androidApp` | Activity, NSD, Android Keystore, driver SQLite Android |
| `iosApp` | Progetto Xcode generabile, identità Keychain, sonda Bonjour e trasporto TLS Network.framework |

`connectivity` è un modulo KMP con varianti JVM e Android e un source set `jvmAndAndroidMain` per il motore TLS. JmDNS e la creazione dei certificati desktop stanno in `jvmMain`; Android dipende dal modulo, senza importarne i sorgenti. `persistence` contiene `SqliteDeviceRepository` e l'apertura JDBC desktop, mentre il motore dipende dai contratti di dominio.

Il ruolo di sviluppo Kotlin e architettura senior e i criteri concreti di manutenzione sono definiti in [ARCHITETTURA_E_QUALITA.md](ARCHITETTURA_E_QUALITA.md), richiamato dal piano. Il documento include confini, convenzioni, gestione delle risorse, test e criteri di revisione.

## Toolchain

JDK **17** (impostare `JAVA_HOME`), Gradle Wrapper incluso. Internet necessario solo per la prima risoluzione delle dipendenze. L'app usa esclusivamente la LAN. Versioni e fonti ufficiali: [docs/VERSIONI.md](docs/VERSIONI.md).

Su Windows usare `.\gradlew.bat`; su macOS/Linux usare `bash ./gradlew` (non occorre il bit eseguibile). Se una configurazione globale Gradle impone un JDK diverso, correggere `org.gradle.java.home` o passare `-Dorg.gradle.java.home=...`.

```powershell
.\gradlew.bat :protocol:jvmTest :connectivity:jvmTest :desktopApp:classes
.\gradlew.bat :desktopApp:run
```

La prova multicast locale è esplicita: `.\gradlew.bat -Pmulticast=true :connectivity:jvmTest`. La CI esegue i test TLS loopback e salta questa sola prova dipendente dalla LAN del runner.

L'app chiede l'interfaccia IPv4 LAN. Windows/Linux richiedono una passphrase di almeno 12 caratteri per il PKCS#12, non salvata e non recuperabile. Su Mac l'identità viene salvata nel Portachiavi tramite il provider Apple del JDK; macOS può chiedere di autorizzare l'accesso. Se esiste un PKCS#12 precedente, l'app ne chiede la passphrase e importa la stessa identità, conservando il backup cifrato. Il provider nativo è ancora da collaudare sulle due architetture. Dettagli e recupero: [ADR identità Mac](docs/ADR-001-IDENTITA-MAC.md).

I dati desktop sono in `~/.lantern/`: `identity.p12` su Windows/Linux o riferimento pubblico `mac-identity.ref` su Mac, database `lantern.db` e lock dell'istanza. La chiave Mac rimane nel Portachiavi: copiare la cartella da sola non la trasferisce. Conservare identità e database insieme; una perdita dell'identità richiede nuova associazione. Il database contiene testo in chiaro a riposo. Non condividere la cartella tra processi.

Per testare due istanze nello stesso computer, creare due configurazioni di esecuzione JVM con `-Dlantern.home=<cartella-assoluta-distinta>` e `-Dlantern.bind=<IP-LAN>`. Queste proprietà sono della JVM **dell'app**, non del daemon Gradle. I test automatici creano direttamente due nodi distinti con socket loopback reali.

## Associare e inviare

1. Su due computer/Android nella stessa LAN, avviare l'app, assegnare i nomi e attivare il servizio.
2. Consentire al processo Java/app il traffico locale (mDNS UDP 5353 e TCP sulla porta mostrata). Non aprire porte sul router.
3. Selezionare **Associa su entrambi i dispositivi** entro 120 secondi.
4. Confrontare **tutti** i gruppi del codice sugli schermi fisici. Se diversi, rifiutare. Confermare su entrambi.
5. Selezionare **Scrivi**, inserire il testo e inviare. `✓ salvato` significa persistenza remota, non lettura.
6. Arrestare e riattivare: le identità già autorizzate si ricollegano senza nuova conferma. **Blocca localmente** rimuove il trust sul dispositivo corrente.

Se una conferma viene persa durante la prima associazione, un lato può aver salvato il trust e l'altro no: bloccare localmente su entrambi e ripetere. Il recupero transazionale dell'associazione è ancora aperto. Non si fondono sessioni e non si recuperano messaggi offline in questo incremento.

## Android

Prerequisiti: SDK Android con API 35 e build-tools 35.0.0, licenze accettate dal titolare. Impostare `ANDROID_HOME` o creare `local.properties` non versionato con `sdk.dir=<percorso SDK>`. Minimo Android 10/API 29.

```powershell
.\gradlew.bat -Pandroid=true :androidApp:assembleDebug :androidApp:lintDebug
```

APK: `androidApp/build/outputs/apk/debug/androidApp-debug.apk`. Installazione manuale su dispositivo di test autorizzato con `adb install -r ...`. Il build debug usa esclusivamente la chiave debug locale del toolchain, mai credenziali release. Non è stata eseguita un'installazione su dispositivi in questa sessione.

Le build precedenti alla correzione della firma TLS 1.3 potevano creare una chiave Android Keystore limitata a `SHA-256`; Conscrypt richiede anche `NONE` perché firma un digest TLS già calcolato. Dopo aver installato la build corretta, una chiave incompatibile viene rifiutata senza rotazione silenziosa: cancellare una volta i dati di Lantern e riaprire l'app per creare consapevolmente una nuova identità. L'ID cambia e le eventuali associazioni devono essere ripetute.

L'identità Android risiede in Android Keystore; backup dell'app disabilitato. In questa prova l'app **si arresta in background**. Tornare in primo piano e attivare nuovamente il servizio. Cambio rete: arrestare, chiudere e riaprire l'Activity. Foreground service e reazione automatica al cambio rete sono ancora aperti.

La chiusura di una socket TLS può eseguire I/O per inviare `close_notify`. Blocco locale, rifiuto dell'associazione e arresto demandano quindi la chiusura delle risorse al dispatcher I/O del nodo; i callback Compose non chiudono direttamente socket sul main thread.

## Mac obbligatorio, due architetture

Su macOS 13+ con JDK 17 nativo (arm64 su Apple Silicon; x86_64 su Intel):

```sh
bash ./gradlew :protocol:jvmTest :connectivity:jvmTest :desktopApp:run
bash ./gradlew :desktopApp:createDistributable
bash ./gradlew :desktopApp:packageDmg
```

Ripetere **nativamente su entrambe le architetture**, senza scambiare i runtime. Output in `desktopApp/build/compose/binaries/`. `createDistributable` prepara `.app` e runtime Java incluso; `packageDmg` crea il contenitore locale non firmato. Nessun comando pubblica release, firma Developer ID o notarizza. La versione packaging Mac `1.0.0` è solo un vincolo del formato DMG, non una release 1.0 del prodotto.

Mac richiede ancora: collaudo del Portachiavi implementato, permessi rete locale del bundle verificati, barra menu, sopravvivenza alla chiusura della finestra, avvio login, prove di sospensione. Attualmente chiudere la finestra arresta l'app. Non dichiarare Mac pronto alla distribuzione.

Windows/Linux usano rispettivamente `createDistributable`, `packageMsi` / `packageDeb` sul relativo host con i tool di packaging richiesti da Compose. La CI conserva per 14 giorni il distributable Windows con runtime e l'APK debug Android negli artefatti dei **checkpoint manuali** `Verify Lantern PoC`, con SHA nel nome; i push rapidi non producono pacchetti. Nessuna release. Download, installazione e cautela sulla firma debug Android: [procedura di collaudo](docs/COLLAUDO.md#build-di-test-e-prima-prova-android--windows).

## iPhone / Xcode

Serve un Mac con Xcode **16.3** per questa baseline, JDK 17 e XcodeGen 2.43.0. XcodeGen serve soltanto a generare il progetto, non è una dipendenza dell'app. Le versioni più recenti di Xcode richiedono verifica/aggiornamento della toolchain Kotlin.

```sh
bash ./gradlew :ui:linkDebugFrameworkIosSimulatorArm64 :protocol:iosSimulatorArm64Test
cd iosApp
xcodegen generate
mkdir -p Lantern.xcodeproj/project.xcworkspace/xcshareddata/swiftpm
cp Package.resolved Lantern.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved
xcodebuild -project Lantern.xcodeproj -scheme Lantern -sdk iphonesimulator -configuration Debug -destination 'generic/platform=iOS Simulator' -onlyUsePackageVersionsFromResolvedFile CODE_SIGNING_ALLOWED=NO build
```

Su Mac Intel usare `iosX64` per il simulatore. Aprire il progetto generato in Xcode per il dispositivo reale; **la firma per iPhone va configurata dall'utente**, non da questi script. Deployment target iOS 16. `Info.plist` contiene descrizione rete locale e `_lantern._tcp`. Nessun entitlement di background promette ricezione continua.

L'app apre l'identità nel Keychain, apre `lantern.db` nella propria Application Support e mostra ID e nome dispositivo persistenti; elenca servizi desktop/Android tramite `NWBrowser`. Il package Swift locale contiene l'adattatore `NWListener`/`NWConnection`: TLS 1.3 reciproco, identità Keychain e verifica esatta dei pin forniti dal chiamante. Associazione con doppia conferma integrata nella UI e verificata in loopback simulatore nella CI `dba224a`. Il framing, le validazioni wire e i byte canonici firmati restano Kotlin. Decisioni in [ADR identità iOS](docs/ADR-002-IDENTITA-IOS.md) e [ADR trasporto TLS iOS](docs/ADR-003-TRASPORTO-TLS-IOS.md).

Implementato anche `TEXT/ACK` iOS, **verificato in CI simulatore sul commit `08dfb86`**: dopo l'associazione il peer collegato appare sopra il campo messaggio (massimo 8192 byte UTF-8). L'invio salva il testo localmente; “Salvato sul destinatario” compare solo dopo la ricevuta. Il destinatario verifica mittente, sessione e firma e invia ACK soltanto dopo il commit SQLite idempotente. Cronologia locale e ricevute vengono caricate anche alla riapertura; un messaggio privo di ricevuta non viene ritrasmesso automaticamente. Solo testo tra due peer, senza inoltro o recupero. Collaudi Apple fisici ancora necessari.

Per i test dell'identità su un simulatore iOS 18.4 con Xcode 16.3: `xcodebuild -downloadPlatform iOS -buildVersion 18.4`, generare il progetto, poi dalla cartella principale `xcodebuild -project iosApp/Lantern.xcodeproj -scheme Lantern -destination 'platform=iOS Simulator,name=iPhone 16,OS=18.4' -onlyUsePackageVersionsFromResolvedFile CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- test`. La firma locale ad hoc include gli entitlement del simulatore necessari al Keychain; non usa certificati o credenziali Apple Developer. `Simulator.entitlements` è selezionato soltanto per SDK `iphonesimulator`, mai per dispositivo reale. La CI crea un simulatore dedicato e conserva il risultato XCTest.

## Verifiche e sicurezza

Il [contratto PoC](docs/PROTOCOLLO_POC.md) precede e descrive l'implementazione crittografica. Nessun trust manager accetta certificati indiscriminatamente. Il codice di confronto non è una password trasmessa in chiaro e deve essere confrontato fuori banda. Gli annunci LAN e i nomi non sono autenticati.

I test integrativi usano chiavi nuove, filesystem/SQLite reali, TLS reale e solo discovery simulata. Non equivalgono a prove multicast, hardware mobile o installazione Mac. Rapporti HTML: `protocol/build/reports/tests/jvmTest/` e `connectivity/build/reports/tests/jvmTest/`.

La CI è eseguita nel repository pubblico [lantern-share](https://github.com/zanzaro-mirco/lantern-share/actions), con due livelli:

- **Push/PR rapidi:** un piccolo job `plan` legge il diff Git completo e seleziona solo i target interessati. JVM: test protocollo/connettività e classi desktop su Windows. Android: compilazione dell'app e test protocollo Android. iOS: framework e compilazione app/entrambi i target XCTest, senza installazione runtime o esecuzione simulatore. Niente pacchetti/lint/matrice completa. Markdown non avvia job pesanti; `jvmAndAndroid` coinvolge entrambi i target, sorgenti condivisi/file di build/lock coinvolgono tutti, percorsi o diff sconosciuti allargano i controlli. Nessun limite di 300 file. Run automatiche obsolete dello stesso workflow/ref vengono cancellate; quelle manuali no.
- **Checkpoint manuali:** `gh workflow run verify.yml --ref main` esegue JVM su Windows/Linux/Mac ARM/Mac Intel, Keychain nativo Mac, test Android, APK/lint e pacchetti desktop. `gh workflow run ios.yml --ref main` esegue anche tutti i test Native e XCTest ordinari. Per interop: `gh workflow run ios.yml --ref main -f bootstrap_interop=true -f bootstrap_scenario=all`; una preparazione/compilazione interop, tre esecuzioni senza ricompilare (`success`, `mismatch`, `cancel`), controller/fixture/namespace nuovi e `.xcresult` separati. Si può scegliere un singolo scenario per diagnosi. La prima anomalia fallisce la run; nessun errore nascosto o test fallito escluso.

I checkpoint completi restano obbligatori prima di dichiarare un traguardo verificato o preparare build per collaudi fisici; verde della CI rapida **non equivale** a test Native/Keychain/interop o compatibilità su tutti i sistemi. Eseguire i due workflow manuali sullo stesso SHA, senza polling. Non sono release e non usano credenziali Apple reali. Dettagli del batching in [COLLAUDO_BOOTSTRAP_INTEROP](docs/COLLAUDO_BOOTSTRAP_INTEROP.md). Riferimenti ufficiali: [matrici dinamiche GitHub](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations), [Build For Testing / Test Without Building Apple](https://developer.apple.com/library/archive/technotes/tn2339/_index.html).

Il commit `6aa051f` ha superato la precedente matrice completa, inclusi build iOS e cinque XCTest dell'identità. Evidenze correnti e limiti sono in STATO_SVILUPPO.md. Sono conservati rapporti di test; nessuna release è pubblicata.

Procedura e scheda risultati: [docs/COLLAUDO.md](docs/COLLAUDO.md).

Il 3 ottobre l'utente ha rinviato i collaudi fisici: restano obbligatori e non superati in fase 1. Nel frattempo sono introdotte le regole Kotlin di negoziazione v1, codec capacità/HELLO/APPROVE rigorosi, transcript canonico, verifica remota, envelope e macchina di stato del bootstrap, **non attivati nel servizio**. Il proprietario JVM/Android isolato coordina HELLO unico, conferma con ticket, framing comune limitato, scadenza automatica con scheduler condiviso e chiusura socket anche su errori/cancellazione concorrenti. Test comuni, stream e TLS 1.3 reale con pin esatti; non sono collaudi fisici né implementazione del v1 completo o dell'adattatore Apple v1. Nessuna modifica al wire v0 o al database. Ambito e limiti: [ADR 004](docs/ADR-004-NEGOZIAZIONE-V1.md), [ADR 005](docs/ADR-005-TRANSCRIPT-HANDSHAKE-V1.md), [ADR 006](docs/ADR-006-STATO-HANDSHAKE-V1.md) e [ADR 007](docs/ADR-007-CONNESSIONE-BOOTSTRAP-V1.md). Il completamento locale del bootstrap non concede trust o autorizzazione ai messaggi.
