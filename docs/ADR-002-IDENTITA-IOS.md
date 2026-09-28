# ADR 002 — Identità iOS

## Contratto prima dell'uso nel trasporto

L'identità iOS usa lo stesso formato del protocollo 0: chiave EC P-256, certificato X.509 autofirmato, ID SHA-256 del DER e firme ECDSA/SHA-256 in DER/Base64. Il Keychain conserva chiave, certificato e pin atteso. Le firme passano a Security.framework tramite `SecKey`; l'app non serializza la chiave privata su file o UserDefaults. Non viene promessa protezione Secure Enclave o non esportabilità hardware.

La libreria ufficiale Apple Swift Certificates crea e verifica X.509: niente codificatore ASN.1 o primitive crittografiche scritti ad hoc. Il modulo Swift `LanternIdentity` è un adattatore di piattaforma; dominio, frame e regole di autorizzazione rimangono Kotlin. Espone una `SecIdentity` verificata, pronta per il futuro trasporto TLS, ma **questo incremento non implementa il trasporto iOS né autorizza alcun peer**.

Gli elementi sono locali, non sincronizzabili e `WhenUnlockedThisDeviceOnly`. Apertura e creazione sono serializzate nel processo. Al riavvio si verificano firma del certificato, scadenza, pin e corrispondenza della chiave tramite firma di prova. Elementi parziali o incoerenti fermano l'avvio; non si cancellano automaticamente e non si genera una nuova identità per mascherare un errore. Se una prima creazione si interrompe a metà serve un recupero esplicito ancora da progettare. Il certificato ha durata dieci anni; rotazione e recupero non sono implementati.

La chiave e il certificato vengono registrati separatamente nel Keychain; Security.framework li associa come `SecIdentity`. L'adattatore verifica che il certificato restituito per TLS sia quello atteso. Gli errori Keychain vengono mostrati nella UI e impediscono l'avvio della sonda. L'apertura avviene fuori dal thread UI; callback Bonjour obsolete vengono ignorate dopo l'arresto.

## Dipendenze e verifica

Versioni esatte in `iosApp/AppleIdentity/Package.swift`: Swift Certificates 1.7.0, Swift Crypto 3.9.0, Swift ASN.1 1.3.0. Il package richiede Swift tools 5.9 ed è integrato tramite XcodeGen; deployment iOS 16 invariato. Il manifest del progetto blocca anche le dipendenze transitive per non dipendere dalla data di risoluzione.

Fonti ufficiali consultate:

- [Manifest Swift Certificates 1.7.0](https://github.com/apple/swift-certificates/blob/1.7.0/Package.swift).
- [Supporto SecKey di Swift Certificates](https://github.com/apple/swift-certificates/blob/1.7.0/Sources/X509/CertificatePrivateKey.swift).
- [Conversione SecCertificate e costruzione X.509](https://github.com/apple/swift-certificates/blob/1.7.0/Sources/X509/Certificate.swift).
- [Apple: recuperare una chiave esistente](https://developer.apple.com/documentation/security/getting-an-existing-key).
- [Apple: installare il runtime del simulatore](https://developer.apple.com/documentation/xcode/downloading-and-installing-additional-xcode-components).

I test XCTest usano il Keychain reale del simulatore con namespace casuali e pulizia limitata ai propri elementi: riapertura, firma anche tramite chiave della SecIdentity, alterazione del testo, chiave/certificato mancanti, pin sostituito e attributi di protezione. Non sono mock di persistenza. Una prova in simulatore non valida protezione a dispositivo bloccato, hardware, prompt, reinstallazione o comunicazione LAN su iPhone fisico. Esiti effettivi e limiti aggiornati in STATO_SVILUPPO.md.

I test sono ospitati dall'app: dipendono dal target Lantern e importano il modulo già collegato all'host, senza aggiungere una seconda dipendenza link al package. Anche i flag del framework Kotlin appartengono soltanto al target app. La prima configurazione duplicava il package tra host e test; Xcode falliva durante la creazione dei framework prodotti da SwiftPM, prima di eseguire gli XCTest.

L'host mantiene i controlli standard di Compose: `CADisableMinimumFrameDurationOnPhone=true` nel plist soddisfa il requisito di avvio introdotto da Compose 1.7, invece di disabilitarne il controllo. Fonte: [note JetBrains Compose 1.7](https://github.com/JetBrains/compose-multiplatform/releases/tag/v1.7.0). La compilazione da sola non rileva questo errore di avvio.

L'esecuzione XCTest richiede gli entitlement Keychain anche nel simulatore: la prima esecuzione unsigned è stata rifiutata con `errSecMissingEntitlement` (-34018). Per i soli SDK `iphonesimulator`, il progetto usa `Simulator.entitlements` con identificatore dell'app e relativo gruppo Keychain; i test usano firma locale ad hoc (`CODE_SIGN_IDENTITY=-`), senza certificati o provisioning Apple Developer. Non si applicano questi entitlement a `iphoneos` e non si ignorano gli errori Security nei test. Fonte: [Apple: errSecMissingEntitlement](https://developer.apple.com/documentation/security/errsecmissingentitlement).
