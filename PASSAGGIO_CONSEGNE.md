# Passaggio di consegne — 28 settembre 2026

## Ripartenza rapida

Progetto: `C:\Users\mzanz\codex_projects\lantern-share`. Repository privato: https://github.com/zanzaro-mirco/lantern-share, branch `main`. Nome tecnico dell'app: Lantern. La vecchia cartella `app_condivisione_kmp` non esiste più.

L'incremento identità iOS è chiuso e verificato: **non ricominciare il debug già risolto**. La persistenza SQLDelight iOS e il nome dispositivo nella UI sono implementati. La CI 36471901305 del commit `28e7015` ha compilato repository e framework iOS ma si è fermata sulla compilazione del nuovo test per l'opt-in Foundation mancante; la correzione è limitata al test e attende verifica. Baseline identità verificata: commit `6aa051f`, CI riuscita https://github.com/zanzaro-mirco/lantern-share/actions/runs/36433898550. Confermare con `git status` e log prima di lavorare.

## Stato reale

- Desktop e Android: identità persistente, scoperta LAN, associazione reciproca, TLS 1.3 autenticato, testo firmato/cifrato nel trasporto, SQLite e riconnessione. Limiti di prodotto e pairing interrotto descritti nel contratto PoC.
- Mac: Portachiavi tramite provider Apple del JDK, migrazione del PKCS#12 senza cambiare ID; test nativi CI riusciti su Intel e ARM64. Nessun collaudo su Mac fisici dell'utente.
- iOS: identità P-256, certificato X.509, pin e SecIdentity nel Keychain; ID mostrato in Compose; sonda Bonjour reale. Repository SQLDelight nativo e nome dispositivo persistente sono implementati; repository e framework compilano in CI, mentre il test corretto di riapertura attende il nuovo run. **Mancano trasporto TLS, associazione e messaggistica.**
- CI verde su Android, Windows, Linux, Mac Intel/ARM64 e iOS. Cinque XCTest passati sul Keychain reale del simulatore iPhone 16/iOS 18.4. Ultima suite locale Windows: 26 test passati con multicast, build desktop e Android; lint 0 errori/18 warning.
- Nessun collaudo fisico Android–iPhone–Mac. Fase 0 aperta; fase 1 solo avviata. Nessuna release pubblicata.

## Incremento corrente e prossimo passo

La persistenza SQLite iOS è stata implementata riutilizzando schema e contratti Kotlin, con driver nativo 2.1.0, ownership/chiusura esplicite, accesso fuori dal thread UI e test reale di salvataggio/riapertura. Prima di proseguire occorre registrare l'esito della CI nativa del commit corrente; non dichiararla verificata dal solo host Windows.

Il prossimo incremento concreto sarà **NWListener/NWConnection TLS con pinning**, limitato al trasporto e all'integrazione del protocollo Kotlin. L'associazione resta separata e successiva. Se l'utente sceglie un'altra priorità, seguire la sua istruzione.

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
