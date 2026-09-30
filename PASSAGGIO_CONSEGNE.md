# Passaggio di consegne — 30 settembre 2026

## Ripartenza rapida

Progetto: `C:\Users\mzanz\codex_projects\lantern-share`. Repository pubblico: https://github.com/zanzaro-mirco/lantern-share, branch `main`. Nome tecnico dell'app: Lantern. La vecchia cartella `app_condivisione_kmp` non esiste più.

L'identità e la persistenza SQLDelight iOS sono chiuse e verificate in simulatore: **non ricominciare il debug già risolto**. Trasporto TLS e associazione iOS sono implementati e compilati nella CI `c8027b2`: passano TLS reciproco con pin esatti, trasferimento byte, doppia conferma e scadenza. Due test falliscono per aspettative XCTest, ora corrette ma da rieseguire; la suite completa non è ancora verde. Il collegamento Android ↔ Windows funziona; il successivo crash `NetworkOnMainThreadException` durante “Blocca localmente” è corretto e verificato localmente, ma attende riprova sul telefono. Confermare con `git status` e log prima di lavorare.

## Stato reale

- Desktop e Android: identità persistente, scoperta LAN, associazione reciproca, TLS 1.3 autenticato, testo firmato/cifrato nel trasporto, SQLite e riconnessione. `DIGEST_NONE` è verificato su hardware. Le chiusure TLS di blocco/rifiuto/arresto sono ora confinate a I/O; test/build/lint passano, riprova fisica del crash pendente.
- Mac: Portachiavi tramite provider Apple del JDK, migrazione del PKCS#12 senza cambiare ID; test nativi CI riusciti su Intel e ARM64. Nessun collaudo su Mac fisici dell'utente.
- iOS: identità P-256, certificato X.509, pin e SecIdentity nel Keychain; repository SQLDelight nativo e nome persistente. `AppleTLSTransport` configura TLS 1.3 reciproco e pin esatti. Pubblicazione/scoperta Bonjour, selezione a 120 secondi, `HELLO/APPROVE`, confronto completo, doppia conferma, verifica firma e trust persistente sono implementati riusando wire e contratti Kotlin. **Compilazione nativa riuscita; suite XCTest parzialmente verificata (8/10); messaggistica non implementata.**
- L'ultima CI completamente verde resta quella precedente all'aggiunta del trasporto iOS. La [CI 36766891297](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36766891297), commit `c8027b2`, ha superato setup CoreSimulator, framework e test Kotlin iOS, compilazione app e bundle XCTest. Android e tutti i job desktop sono riusciti. Gli XCTest hanno eseguito 10 casi: 8 riusciti, cancellazione fallita per aspettativa server non attesa e pin errato fallito perché attendeva soltanto `.failed` anziché anche `.waiting` con errore TLS. Il log documenta il rifiuto del certificato; la correzione dei due test richiede una nuova esecuzione Apple.
- Fase 0 chiusa sulla prova fisica Android ↔ Windows riuscita. La fase 1 comprende il completamento Apple, i collaudi fisici obbligatori su iPhone, Mac Intel e Mac Apple Silicon e le verifiche residue Android ↔ Windows con WAN disattivata, testo bidirezionale e riavvio. Nessuna release pubblicata.

## Incremento corrente e prossimo passo

CI iOS selettiva: il job è spostato senza modifiche a comandi/versioni/test in `.github/workflows/ios.yml` (`Verify Lantern iOS`). Filtri uguali su push e PR: app Apple, sorgenti di dominio/protocollo/persistenza/UI esclusi Android/JVM, build Gradle, wrapper/catalogo, lock pertinenti, workflow iOS e script di supporto. Android/desktop rimangono nel workflow originale a ogni push/PR. Forzatura della sola verifica iOS da Actions → Verify Lantern iOS → Run workflow, oppure `gh workflow run ios.yml --ref main`. Aggiornare i filtri se cambia il grafo dei moduli iOS; per grandi diff considerare il limite GitHub di 300 file e avviare manualmente. Non interpretare una run filtrata come collaudo nativo.

Controlli locali: confronto strutturale Node dei blocchi job prima/dopo (invariati), uguaglianza filtri push/PR, presenza dispatch manuale e 26 vettori di percorsi positivi/negativi riusciti; `git diff --check` riuscito. Non è esecuzione Actions né compilazione Swift. La CI dei test corretti `dba224a` ([36770172809](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36770172809)) era ancora in corso all'unico controllo; tutti gli altri job erano riusciti. Prossimo passo concreto: verificare il risultato XCTest pendente e la registrazione del nuovo workflow; niente polling ripetuto.

Correzione XCTest successiva alla CI `c8027b2`: l'aspettativa di ammissione server viene creata soltanto nel caso di pairing riuscito; nel caso cancellato restano il divieto di callback client e zero scritture client. Il test pin errato gestisce `.waiting` e `.failed`, richiede `NWError.tls` non riuscito e fallisce se riceve errori DNS/POSIX o raggiunge `.ready`; cancella al primo esito evitando doppio fulfillment. Timeout, pinning e codice di produzione invariati. Verifica locale limitata a revisione e `git diff --check`; Xcode non disponibile su Windows. Prossimo incremento concreto: verificare i due test corretti nella nuova CI prima di estendere iOS a `TEXT/ACK`.

Le note seguenti descrivono i passaggi precedenti; il setup è ora verificato su macOS dalla CI `c8027b2`, non più pendente.

Setup CI iOS del 30 settembre: la [run 36765117114](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36765117114), commit `67efea1`, è fallita prima della compilazione con `Unable to connect to simulator` (exit 70); Android e tutti i job desktop sono riusciti. Il workflow ora esegue `.github/scripts/prepare-ios-simulator.sh`: inizializzazione con `xcodebuild -runFirstLaunch`, lettura JSON dei runtime tramite `simctl` prima del download, riuso di iOS 18.4 solo se disponibile e verifica della disponibilità dopo l'installazione. Xcode 16.3, runtime, lock e test nativi restano invariati. Il log del setup viene conservato nell'artefatto `ios-verification` anche in caso di errore. Workaround documentato dai manutentori in [runner-images #12862](https://github.com/actions/runner-images/issues/12862).

Verifica locale del setup: sintassi Bash e sette test dell'orchestrazione riusciti (runtime presente, assente, indisponibile dopo installazione, errore download, errore inizializzazione, errore simctl, JSON non valido). I comandi Apple sono sostituiti **soltanto nei test**; non dimostra il funzionamento reale di CoreSimulator su macOS. Il workflow esegue anche questi test prima del setup reale. Prossimo incremento: controllare l'esito del nuovo setup e, se passa, la compilazione e gli XCTest della revisione iOS; nessuna estensione a `TEXT/ACK` prima di questa verifica.

Revisione del 30 settembre: eliminata la cache globale dei certificati, che non legava HELLO alla socket corrente. `PairingChannel` ignora callback dopo cancellazione, impedisce doppio invio APPROVE e ricontrolla il candidato prima della persistenza. Il browser usa `bonjourWithTXTRecord`; i callback di listener/browser precedenti sono ignorati. Il tentativo sopravvive a errori di collegamento fino ai 120 secondi, con backoff condiviso. Aggiunti XCTest per doppia conferma, cancellazione durante invio, scadenza prima del timer e certificato per connessione. Sono test scritti, non ancora eseguiti su Apple. La CI `36635631396` del commit `773282d` è fallita nel download runtime con `Unable to connect to simulator`, prima di compilare la correzione Swift.

La chiave Android nuova autorizza `SHA-256` e `NONE`, richiesti rispettivamente dalle firme applicative e da Conscrypt TLS 1.3. Una vecchia chiave incompatibile viene rifiutata con istruzione esplicita, senza rigenerazione silenziosa. Build APK, lint e test JVM sono riusciti; dopo cancellazione dati, anche il collegamento e la comunicazione Android ↔ Windows sono riusciti su hardware. Testo in entrambe le direzioni e riavvio non sono stati documentati separatamente.

Il prossimo passo è completare gli XCTest iOS corretti, quindi provare l'associazione contro Android o desktop e chiusura/riapertura del trust. L'utente ha nuovamente autorizzato push e verifica Actions: raggruppare le correzioni e controllare una sola volta la run; nessun polling ripetuto. Non anticipare `TEXT/ACK` finché la suite nativa non passa. In parallelo resta possibile installare il nuovo APK e riprovare blocco/rifiuto/arresto su Android ↔ Windows.

## Mappa minima dei sorgenti

| Area | Percorso |
|---|---|
| Contratti e stato | `domain/src/commonMain/kotlin/lantern/domain/Contracts.kt` |
| Protocollo v0 | `protocol/src/commonMain/kotlin/lantern/protocol/Wire.kt` |
| Motore JVM/Android | `connectivity/src/jvmAndAndroidMain/kotlin/lantern/connectivity/` |
| Schema e repository | `persistence/src/commonMain/sqldelight/lantern/persistence/Store.sq`, `persistence/src/commonMain/kotlin/`, `persistence/src/iosMain/`, `persistence/src/jvmAndAndroidMain/` |
| Identità Apple | `iosApp/AppleIdentity/Sources/LanternIdentity/` |
| App e test iOS | `iosApp/LanternApp.swift`, `iosApp/Tests/AppleIdentityTests.swift` |
| Ingresso Compose iOS | `ui/src/iosMain/kotlin/lantern/ui/IosEntry.kt` |
| Build Apple | `iosApp/project.yml`, `iosApp/Package.resolved`, `.github/workflows/verify.yml` |

Per la persistenza leggere anche `persistence/build.gradle.kts`, `IosRepository.kt` e il test iOS di riapertura; aprire gli altri sorgenti solo quando servono.

## Vincoli verificati: non annullare le correzioni

- Kotlin 2.1.21, Compose 1.8.2, Gradle 8.9, AGP 8.7.2, SQLDelight 2.1.0, JDK 17. Dettagli in `docs/VERSIONI.md`.
- Xcode 16.3 richiede il runtime simulatore iOS 18.4; CI lo installa esplicitamente. Android setup usa `platform-tools`, non il pacchetto legacy `tools`.
- Swift Certificates **1.7.0**, Crypto 3.9.0, ASN.1 1.3.0. La 1.6.0 non compila correttamente per iOS. Manifest e revisioni bloccati; copiare `iosApp/Package.resolved` nel progetto Xcode generato come da README.
- I test sono ospitati dall'app: non collegare nuovamente `LanternIdentity` al target XCTest. Flag di link Kotlin soltanto sul target app.
- `CADisableMinimumFrameDurationOnPhone=true` è necessario per l'avvio Compose.
- Test Keychain: firma **ad hoc solo simulatore**, `CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=-`, con `Simulator.entitlements`. L'esecuzione unsigned falliva con -34018. Non rimuovere i controlli Security e non applicare questi entitlement a `iphoneos`.
- Su Windows non sono disponibili Xcode o dispositivi Apple. Usare la CI per le verifiche native, senza dichiarare provato l'hardware.
- `gh` è installato/autenticato. Il nome attuale dell'account è `zanzaro-mirco`; la configurazione locale può mostrare ancora il vecchio nome.
- Nei comandi Git fuori sandbox può apparire “dubious ownership”: usare, se necessario, `git -c safe.directory=C:/Users/mzanz/codex_projects/lantern-share ...`, limitato a questo percorso. Non usare wildcard globali né cambiare proprietari indiscriminatamente.

## Comandi e gestione del lavoro

Impostare il working directory al percorso attuale, non a quello precedente. Comando locale completo già passato (non ripeterlo per la sola presa in carico):

```powershell
.\gradlew.bat -Pandroid=true -Pmulticast=true :protocol:jvmTest :connectivity:jvmTest :desktopApp:createDistributable :androidApp:assembleDebug :androidApp:lintDebug --console=plain
```

Per iOS usare i comandi esistenti nel README/workflow. Eseguire solo controlli pertinenti alle modifiche. Raggruppare le correzioni prima del push; una matrice completa CI richiede diversi minuti. Non restare in polling ripetuto: se non resta lavoro utile, consegnare lo stato pendente con URL e riprendere al turno successivo.

Alla fine dell'incremento aggiornare questi dati e la sezione corrente di STATO_SVILUPPO.md. I resoconti storici successivi conservano errori e limiti precedenti, non tutti ancora attuali.
