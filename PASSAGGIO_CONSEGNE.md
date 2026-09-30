# Passaggio di consegne — 30 settembre 2026

## Ripartenza rapida

Progetto: `C:\Users\mzanz\codex_projects\lantern-share`. Repository pubblico: https://github.com/zanzaro-mirco/lantern-share, branch `main`. Nome tecnico dell'app: Lantern. La vecchia cartella `app_condivisione_kmp` non esiste più.

L'identità e la persistenza SQLDelight iOS sono chiuse e verificate in simulatore: **non ricominciare il debug già risolto**. Trasporto TLS e associazione iOS sono implementati e sono stati rivisti il 30 settembre: certificato vincolato alla connessione corrente, cancellazione terminale, selezione con scadenza monotona, riprove con backoff Kotlin, isolamento dei callback e richiesta dei TXT Bonjour. Compilazione Swift e nuovi XCTest restano da verificare. Il collegamento Android ↔ Windows funziona; il successivo crash `NetworkOnMainThreadException` durante “Blocca localmente” è corretto e verificato localmente, ma attende riprova sul telefono. Confermare con `git status` e log prima di lavorare.

## Stato reale

- Desktop e Android: identità persistente, scoperta LAN, associazione reciproca, TLS 1.3 autenticato, testo firmato/cifrato nel trasporto, SQLite e riconnessione. `DIGEST_NONE` è verificato su hardware. Le chiusure TLS di blocco/rifiuto/arresto sono ora confinate a I/O; test/build/lint passano, riprova fisica del crash pendente.
- Mac: Portachiavi tramite provider Apple del JDK, migrazione del PKCS#12 senza cambiare ID; test nativi CI riusciti su Intel e ARM64. Nessun collaudo su Mac fisici dell'utente.
- iOS: identità P-256, certificato X.509, pin e SecIdentity nel Keychain; repository SQLDelight nativo e nome persistente. `AppleTLSTransport` configura TLS 1.3 reciproco e pin esatti. Pubblicazione/scoperta Bonjour, selezione a 120 secondi, `HELLO/APPROVE`, confronto completo, doppia conferma, verifica firma e trust persistente sono implementati riusando wire e contratti Kotlin. **Compilazione/test nativi di trasporto e associazione pendenti; messaggistica non implementata.**
- L'ultima CI completamente verde resta quella precedente all'aggiunta del trasporto iOS. La [CI 36633931340](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36633931340), commit `4714abf`, ha confermato il lock corretto: framework Kotlin e test iOS condivisi sono riusciti. La compilazione app ha poi rilevato in `AppleTLSTransport` l'assenza di unwrap su `SecKeyCopyAttributes`; corretto anche l'uso deprecato di `SecTrustGetCertificateAtIndex` con la catena restituita da `SecTrustCopyCertificateChain`. Ultima verifica locale pertinente: risoluzione delle tre configurazioni iOS, protocollo e connettività JVM riusciti; la ricompilazione Swift corretta richiede macOS.
- Fase 0 chiusa sulla prova fisica Android ↔ Windows riuscita. La fase 1 comprende il completamento Apple, i collaudi fisici obbligatori su iPhone, Mac Intel e Mac Apple Silicon e le verifiche residue Android ↔ Windows con WAN disattivata, testo bidirezionale e riavvio. Nessuna release pubblicata.

## Incremento corrente e prossimo passo

Revisione del 30 settembre: eliminata la cache globale dei certificati, che non legava HELLO alla socket corrente. `PairingChannel` ignora callback dopo cancellazione, impedisce doppio invio APPROVE e ricontrolla il candidato prima della persistenza. Il browser usa `bonjourWithTXTRecord`; i callback di listener/browser precedenti sono ignorati. Il tentativo sopravvive a errori di collegamento fino ai 120 secondi, con backoff condiviso. Aggiunti XCTest per doppia conferma, cancellazione durante invio, scadenza prima del timer e certificato per connessione. Sono test scritti, non ancora eseguiti su Apple. La CI `36635631396` del commit `773282d` è fallita nel download runtime con `Unable to connect to simulator`, prima di compilare la correzione Swift.

La chiave Android nuova autorizza `SHA-256` e `NONE`, richiesti rispettivamente dalle firme applicative e da Conscrypt TLS 1.3. Una vecchia chiave incompatibile viene rifiutata con istruzione esplicita, senza rigenerazione silenziosa. Build APK, lint e test JVM sono riusciti; dopo cancellazione dati, anche il collegamento e la comunicazione Android ↔ Windows sono riusciti su hardware. Testo in entrambe le direzioni e riavvio non sono stati documentati separatamente.

Il prossimo passo è compilare la revisione iOS ed eseguire gli XCTest su Apple, quindi provare l'associazione contro Android o desktop e chiusura/riapertura del trust. L'utente ha nuovamente autorizzato push e verifica Actions: raggruppare le correzioni e controllare una sola volta la run; nessun polling ripetuto. Non anticipare `TEXT/ACK` finché il confine Swift/Kotlin non compila. In parallelo resta possibile installare il nuovo APK e riprovare blocco/rifiuto/arresto su Android ↔ Windows.

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
