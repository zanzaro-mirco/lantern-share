# Passaggio di consegne — 3 ottobre 2026

## Ripartenza rapida

Progetto: `C:\Users\mzanz\codex_projects\lantern-share`. Repository pubblico: https://github.com/zanzaro-mirco/lantern-share, branch `main`. Nome tecnico dell'app: Lantern. La vecchia cartella `app_condivisione_kmp` non esiste più.

Identità, SQLDelight, TLS, associazione e testo/ricevute iOS sono compilati e verificati in simulatore dalla CI `08dfb86`: **non ricominciare il debug già risolto**. CI Android/desktop dello stesso commit riuscita. 19 XCTest, inclusi nove di messaggistica; salvataggio/riapertura verificati in simulatore, non su hardware Apple. Il collegamento Android ↔ Windows funziona; il crash `NetworkOnMainThreadException` durante “Blocca localmente” è corretto e verificato localmente, ma attende riprova sul telefono.

## Prossimo passo attuale

Terza sessione autonoma del 3 ottobre: implementata `ProtocolHandshakeAttempt`, macchina Kotlin comune del solo bootstrap v1. Offerte congelate, pin selezionato/TLS/HELLO concordanti, conferma esplicita con ticket di confronto, callback di firma e scrittura con ticket propri dell'istanza; nessun esito precedente può avanzare un tentativo nuovo. `Ready` richiede prova remota valida e conferma/invio locali, rimane scadibile/revocabile e NON concede trust o appartenenza al gruppo. Timeout monotono 120 secondi dalla selezione, ordine/duplicati e cancellazione/errori chiudono senza riuso. ADR `docs/ADR-006-STATO-HANDSHAKE-V1.md`. Tutte le chiamate/letture sul contesto seriale del proprietario; nessun chiamante nel servizio v0, nessuna persistenza.

Verifica attuale: `.\gradlew.bat -Pandroid=true :protocol:jvmTest :protocol:testDebugUnitTest :protocol:compileCommonMainKotlinMetadata :connectivity:jvmTest :androidApp:assembleDebug --console=plain`, riuscita in 9 s. 79 test protocollo JVM, 75 Android, 24 connettività superati e un multicast opt-in saltato; include 18 nuovi test comuni e quattro prove TLS 1.3 reali JVM attraverso la macchina. APK e metadata compilati, non hardware o Native/Swift locale. CI precedente `4203f42`, [iOS](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37136782616) e [Android/desktop](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37136782647), entrambe `success` al controllo iniziale. Nuova CI da verificare dopo push, senza polling ripetuto.

**Prossimo incremento:** proprietario isolato del bootstrap v1 con framing/instradamento codec/macchina e chiusura risorse su errori I/O/cancellazione, test TLS reali; ancora senza attivazione in `Node`/Swift, trust o modifiche al wire v0. L'invio iniziale HELLO una sola volta è attualmente una precondizione dell'adattatore, non un callback governato dalla macchina. Collaudi fisici ancora rinviati e obbligatori, fase 1 aperta. Le ricostruzioni delle sessioni precedenti sotto non sostituiscono queste evidenze o questo prossimo passo.

L'utente ha rinviato al 3 ottobre i collaudi fisici a un momento successivo: registrati in `docs/COLLAUDO.md`, non superati. Restano obbligatori in fase 1. Proseguire con le fondamenta v1, senza rifare iOS e senza attivare modifiche incompatibili sul canale v0. Implementati `ProtocolCapabilities` e `ProtocolNegotiation` in Kotlin comune: intersezione simmetrica, requisiti obbligatori su entrambi i lati, rifiuto versioni non implementate e limiti delle offerte. Non sono ancora frame di rete né autorizzazioni. ADR in `docs/ADR-004-NEGOZIAZIONE-V1.md`.

CI `77f554b` verificata il 3 ottobre: [iOS](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37123915990) e [Android/desktop](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37123915955) entrambe `success`. Superata la verifica remota delle regole pure, non i collaudi fisici.

Sessione autonoma del 3 ottobre: implementati transcript v1 simmetrico con entrambe le offerte/identità/nonce, byte di conferma direzionali, codec HELLO rigoroso e verifica della conferma remota legata al pin TLS. Nessun chiamante nel servizio: risultato verificato non significa trust, conferma utente o autorizzazione. Dettagli e vettore SHA-256 in `docs/ADR-005-TRANSCRIPT-HANDSHAKE-V1.md`; letto `docs/PROTOCOLLO_POC.md` prima del lavoro. Corretto inoltre un `StackOverflowError` riprodotto sul codec delle capacità con input ostile annidato: controllo della profondità prima del parsing, test di regressione. Schema SQLite, identità, wire v0, versioni e lock invariati.

Seconda sessione autonoma: aggiunti APPROVE rigoroso (mittente/destinatario/firma Base64 canonica), verifica dell'indirizzamento e envelope bootstrap versione 1 con HELLO/APPROVE coerenti, riusando i serializer. Tre test TLS 1.3 reali JVM verificano scambio bidirezionale, indirizzamento e rifiuto della firma su nuova connessione con nonce freschi. Fixture temporanee e pin esatti, nessun chiamante di produzione, nessun trust persistito. ADR 005 aggiornato; non è ancora l'envelope completo degli eventi/sessioni del prodotto.

Verifica finale: `.\gradlew.bat -Pandroid=true :protocol:jvmTest :protocol:testDebugUnitTest :protocol:compileCommonMainKotlinMetadata :connectivity:jvmTest :androidApp:assembleDebug --console=plain`, riuscita in 11 s; 61 test protocollo JVM, 57 della variante Android, 23 connettività superati e un multicast opt-in saltato. Metadata comuni e APK verificati, non hardware/iOS locale. `git diff --check` riuscito. CI `8729c63` controllata una volta: [iOS](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37126524221) e [Android/desktop](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37126524218) entrambe `success`. CI del nuovo codice da verificare dopo push. Prossimo incremento: macchina del solo handshake v1 con offerte congelate, conferma locale, ordine/scadenza/cancellazione e test di callback obsoleti, ancora senza trasporto o persistenza del trust; non salvare queste conferme come credenziali di gruppo e non aggiungere fallback automatico v0.

La [CI `56f0de3`](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36873108492) è riuscita: verificata presenza via API degli artefatti APK e Windows con runtime, non download/installazione. Durata 14 giorni: per collaudi successivi potrebbe servire una nuova build. Non sono release. Firma debug CI potenzialmente diversa: non disinstallare o cancellare dati senza decisione esplicita; build locale con stessa firma per preservare identità Android.

Evidenze: [CI iOS](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36775866536), [CI Android/desktop](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36775866597), entrambe `success` su `08dfb86`. Nessun hardware Apple disponibile su Windows; iPhone richiede Mac/Xcode e firma dispositivo configurata dall'utente, non l'artefatto dei risultati simulatore. Fase 0 chiusa, fase 1 aperta. Nessun allegato, gruppo o recupero implementato da questo incremento.

Le sezioni seguenti conservano il passaggio precedente: i riferimenti a verifica nativa pendente sono superati dagli esiti sopra.

## Stato reale

- Desktop e Android: identità persistente, scoperta LAN, associazione reciproca, TLS 1.3 autenticato, testo firmato/cifrato nel trasporto, SQLite e riconnessione. `DIGEST_NONE` è verificato su hardware. Le chiusure TLS di blocco/rifiuto/arresto sono ora confinate a I/O; test/build/lint passano, riprova fisica del crash pendente.
- Mac: Portachiavi tramite provider Apple del JDK, migrazione del PKCS#12 senza cambiare ID; test nativi CI riusciti su Intel e ARM64. Nessun collaudo su Mac fisici dell'utente.
- iOS: identità, SQLite/nome, TLS e `HELLO/APPROVE` verificati in CI simulatore; nessun hardware Apple. Implementato `TEXT/ACK`: firma, sessione e mittente verificati prima del salvataggio; ACK dopo commit, ID in attesa per connessione, cronologia/receipt persistenti e UI. **Nuova messaggistica e nuovi test Apple non ancora compilati/eseguiti.** Nessuno schema, wire, lock o ID cambiato.
- Ultima matrice completamente verde: [CI 36770172809](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36770172809), commit `dba224a`, inclusi i dieci XCTest Keychain/TLS/associazione corretti. Il workflow iOS separato `eca97ea` era ancora in corso all'unico controllo di questo incremento: non confonderlo con un nuovo collaudo passato.
- Fase 0 chiusa sulla prova fisica Android ↔ Windows riuscita. La fase 1 comprende il completamento Apple, i collaudi fisici obbligatori su iPhone, Mac Intel e Mac Apple Silicon e le verifiche residue Android ↔ Windows con WAN disattivata, testo bidirezionale e riavvio. Nessuna release pubblicata.

## Incremento corrente e prossimo passo

Messaggistica iOS wire-v0: `TextWire` condivide costruttori e validazioni con l'adattatore; `IosPairingProtocol` espone frame TEXT/ACK e byte firmati, `IosPersistence` delega a save/history/ack del repository esistente. `PairingChannel` richiede autorizzazione corrente, firma valida e sessione corrispondente; salva prima di ACK, rifiuta conflitti e ricevute non in attesa. Invio vincolato al peer scelto nella UI anche se il canale cambia mentre il callback è accodato. Tutto l'I/O/SQLite resta sulla coda del servizio; cronologia e stato del peer sono pubblicati sul main. Il protocollo resta v0 tra due peer: niente ritrasmissione, inoltro, recupero, file o immagini.

Controlli Windows: `.\gradlew.bat :protocol:jvmTest :connectivity:jvmTest :ui:compileCommonMainKotlinMetadata :ui:compileKotlinJvm --console=plain` riuscito in 24 s, `git diff --check` riuscito. 35 casi JVM: 34 riusciti e multicast opt-in saltato; inclusi tre nuovi test TextWire. Questi task non compilano iosMain né Swift. Aggiunti nove XCTest con TLS loopback/Keychain/SQLite reali per testo bidirezionale e riapertura, duplicato, firma/sessione errate, conflitto, testo non autorizzato, errore di persistenza senza ACK, ricevuta inattesa e limite UTF-8. Aggiunto test SQLite Kotlin/Native di messaggi/ricevuta/deduplica/conflitto/riapertura. Tutti i nuovi test Apple sono **scritti ma non eseguiti**.

Prossimo incremento: verificare una volta la nuova CI iOS di messaggistica, poi collaudo fisico iPhone ↔ Android/desktop con testo bidirezionale e riapertura. Non iniziare protocollo v1 o allegati in questo incremento. Le note seguenti sono storiche e i limiti della precedente suite sono superati dalla CI `dba224a`.

CI iOS selettiva: il job è spostato senza modifiche a comandi/versioni/test in `.github/workflows/ios.yml` (`Verify Lantern iOS`). Filtri uguali su push e PR: app Apple, sorgenti di dominio/protocollo/persistenza/UI esclusi Android/JVM, build Gradle, wrapper/catalogo, lock pertinenti, workflow iOS e script di supporto. Android/desktop rimangono nel workflow originale a ogni push/PR. Forzatura della sola verifica iOS da Actions → Verify Lantern iOS → Run workflow, oppure `gh workflow run ios.yml --ref main`. Aggiornare i filtri se cambia il grafo dei moduli iOS; per grandi diff considerare il limite GitHub di 300 file e avviare manualmente. Non interpretare una run filtrata come collaudo nativo.

Controlli locali: confronto strutturale Node dei blocchi job prima/dopo (invariati), uguaglianza filtri push/PR, presenza dispatch manuale e 26 vettori di percorsi positivi/negativi riusciti; `git diff --check` riuscito. Non è esecuzione Actions né compilazione Swift. La CI dei test corretti `dba224a` ([36770172809](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36770172809)) era ancora in corso all'unico controllo; tutti gli altri job erano riusciti. Prossimo passo concreto: verificare il risultato XCTest pendente e la registrazione del nuovo workflow; niente polling ripetuto.

Correzione XCTest successiva alla CI `c8027b2`: l'aspettativa di ammissione server viene creata soltanto nel caso di pairing riuscito; nel caso cancellato restano il divieto di callback client e zero scritture client. Il test pin errato gestisce `.waiting` e `.failed`, richiede `NWError.tls` non riuscito e fallisce se riceve errori DNS/POSIX o raggiunge `.ready`; cancella al primo esito evitando doppio fulfillment. Timeout, pinning e codice di produzione invariati. Verifica locale limitata a revisione e `git diff --check`; Xcode non disponibile su Windows. Prossimo incremento concreto: verificare i due test corretti nella nuova CI prima di estendere iOS a `TEXT/ACK`.

Le note seguenti descrivono i passaggi precedenti; il setup è ora verificato su macOS dalla CI `c8027b2`, non più pendente.

Setup CI iOS del 30 settembre: la [run 36765117114](https://github.com/zanzaro-mirco/lantern-share/actions/runs/36765117114), commit `67efea1`, è fallita prima della compilazione con `Unable to connect to simulator` (exit 70); Android e tutti i job desktop sono riusciti. Il workflow ora esegue `.github/scripts/prepare-ios-simulator.sh`: inizializzazione con `xcodebuild -runFirstLaunch`, lettura JSON dei runtime tramite `simctl` prima del download, riuso di iOS 18.4 solo se disponibile e verifica della disponibilità dopo l'installazione. Xcode 16.3, runtime, lock e test nativi restano invariati. Il log del setup viene conservato nell'artefatto `ios-verification` anche in caso di errore. Workaround documentato dai manutentori in [runner-images #12862](https://github.com/actions/runner-images/issues/12862).

Verifica locale del setup: sintassi Bash e sette test dell'orchestrazione riusciti (runtime presente, assente, indisponibile dopo installazione, errore download, errore inizializzazione, errore simctl, JSON non valido). I comandi Apple sono sostituiti **soltanto nei test**; non dimostra il funzionamento reale di CoreSimulator su macOS. Il workflow esegue anche questi test prima del setup reale. Prossimo incremento: controllare l'esito del nuovo setup e, se passa, la compilazione e gli XCTest della revisione iOS; nessuna estensione a `TEXT/ACK` prima di questa verifica.

Revisione del 30 settembre: eliminata la cache globale dei certificati, che non legava HELLO alla socket corrente. `PairingChannel` ignora callback dopo cancellazione, impedisce doppio invio APPROVE e ricontrolla il candidato prima della persistenza. Il browser usa `bonjourWithTXTRecord`; i callback di listener/browser precedenti sono ignorati. Il tentativo sopravvive a errori di collegamento fino ai 120 secondi, con backoff condiviso. Aggiunti XCTest per doppia conferma, cancellazione durante invio, scadenza prima del timer e certificato per connessione. Sono test scritti, non ancora eseguiti su Apple. La CI `36635631396` del commit `773282d` è fallita nel download runtime con `Unable to connect to simulator`, prima di compilare la correzione Swift.

La chiave Android nuova autorizza `SHA-256` e `NONE`, richiesti rispettivamente dalle firme applicative e da Conscrypt TLS 1.3. Una vecchia chiave incompatibile viene rifiutata con istruzione esplicita, senza rigenerazione silenziosa. Build APK, lint e test JVM sono riusciti; dopo cancellazione dati, anche il collegamento e la comunicazione Android ↔ Windows sono riusciti su hardware. Testo in entrambe le direzioni e riavvio non sono stati documentati separatamente.

Per la messaggistica verificare la nuova suite Apple prima del collaudo fisico. Raggruppare le correzioni e controllare una sola volta la run; nessun polling ripetuto. In parallelo resta possibile installare il nuovo APK e riprovare blocco/rifiuto/arresto su Android ↔ Windows.

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
