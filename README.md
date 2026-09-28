# Lantern — condivisione locale KMP

**Primo incremento sperimentale; fase 0 non completata.** Nome tecnico provvisorio, senza decisioni di branding. La specifica resta [PIANO_SVILUPPO.md](PIANO_SVILUPPO.md). Risultati verificati e lacune sono in [STATO_SVILUPPO.md](STATO_SVILUPPO.md).

Il desktop contiene un percorso reale: identità persistente, mDNS, associazione esplicita su entrambi gli schermi, TLS 1.3 reciproco, testo firmato, SQLite e ricevute dopo salvataggio. Android riusa protocollo e motore TLS con NSD e Keystore nativi. **iOS contiene identità Keychain, ingresso Compose e sonda Bonjour: non può ancora associarsi o scambiare messaggi.** Non è una implementazione completa della fase 0. Gli esiti delle build e dei test effettivi sono in STATO_SVILUPPO.md.

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
| `iosApp` | Progetto Xcode generabile e sonda Network.framework |

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

L'identità Android risiede in Android Keystore; backup dell'app disabilitato. In questa prova l'app **si arresta in background**. Tornare in primo piano e attivare nuovamente il servizio. Cambio rete: arrestare, chiudere e riaprire l'Activity. Foreground service e reazione automatica al cambio rete sono ancora aperti.

## Mac obbligatorio, due architetture

Su macOS 13+ con JDK 17 nativo (arm64 su Apple Silicon; x86_64 su Intel):

```sh
bash ./gradlew :protocol:jvmTest :connectivity:jvmTest :desktopApp:run
bash ./gradlew :desktopApp:createDistributable
bash ./gradlew :desktopApp:packageDmg
```

Ripetere **nativamente su entrambe le architetture**, senza scambiare i runtime. Output in `desktopApp/build/compose/binaries/`. `createDistributable` prepara `.app` e runtime Java incluso; `packageDmg` crea il contenitore locale non firmato. Nessun comando pubblica release, firma Developer ID o notarizza. La versione packaging Mac `1.0.0` è solo un vincolo del formato DMG, non una release 1.0 del prodotto.

Mac richiede ancora: collaudo del Portachiavi implementato, permessi rete locale del bundle verificati, barra menu, sopravvivenza alla chiusura della finestra, avvio login, prove di sospensione. Attualmente chiudere la finestra arresta l'app. Non dichiarare Mac pronto alla distribuzione.

Windows/Linux usano rispettivamente `createDistributable`, `packageMsi` / `packageDeb` sul relativo host con i tool di packaging richiesti da Compose. La CI costruisce distributable locali senza pubblicarli.

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

L'app apre l'identità nel Keychain e ne mostra l'ID persistente; poi la sonda elenca servizi desktop/Android tramite `NWBrowser`. Il package Swift locale e le versioni bloccate sono descritti nell'[ADR iOS](docs/ADR-002-IDENTITA-IOS.md). Il successivo incremento deve implementare NWListener/NWConnection TLS con verifica pin, associazione e driver SQLDelight iOS. Solo dopo tali implementazioni sarà possibile eseguire il collaudo completo iPhone.

Per i test dell'identità su un simulatore iOS 18.4 con Xcode 16.3: `xcodebuild -downloadPlatform iOS -buildVersion 18.4`, generare il progetto, poi `xcodebuild -project iosApp/Lantern.xcodeproj -scheme Lantern -destination 'platform=iOS Simulator,name=iPhone 16,OS=18.4' CODE_SIGNING_ALLOWED=NO test`. Nessuna credenziale di firma reale è richiesta per il simulatore. La CI crea un simulatore dedicato e conserva il risultato XCTest.

## Verifiche e sicurezza

Il [contratto PoC](docs/PROTOCOLLO_POC.md) precede e descrive l'implementazione crittografica. Nessun trust manager accetta certificati indiscriminatamente. Il codice di confronto non è una password trasmessa in chiaro e deve essere confrontato fuori banda. Gli annunci LAN e i nomi non sono autenticati.

I test integrativi usano chiavi nuove, filesystem/SQLite reali, TLS reale e solo discovery simulata. Non equivalgono a prove multicast, hardware mobile o installazione Mac. Rapporti HTML: `protocol/build/reports/tests/jvmTest/` e `connectivity/build/reports/tests/jvmTest/`.

La CI è eseguita nel repository privato [lantern-share](https://github.com/zanzaro-mirco/lantern-share/actions). Il commit `af69849` ha superato tutti i job: Android, desktop Windows/Linux/Mac Intel/ARM64 e build dell'app iOS precedente alla nuova identità. Gli esiti dell'incremento corrente sono in STATO_SVILUPPO.md. Sono conservati rapporti di test; nessuna release è pubblicata.

Procedura e scheda risultati: [docs/COLLAUDO.md](docs/COLLAUDO.md).
