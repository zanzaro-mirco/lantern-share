# Versioni scelte — 27 settembre 2026

Baseline conservativa riproducibile, non una dichiarazione di adozione delle ultime versioni. Il catalogo `gradle/libs.versions.toml` è la fonte delle versioni dirette. I lockfile Gradle fissano le dipendenze transitive delle configurazioni effettivamente risolte. I quattro lock `desktopApp/gradle-<piattaforma>.lockfile` sono stati generati risolvendo le dipendenze dei quattro runtime (senza compilare Mac/Linux). Le configurazioni Kotlin/Native iOS richiedono ancora il completamento dei lock su CI/macOS.

| Componente | Versione | Verifica ufficiale e motivazione |
|---|---|---|
| Kotlin e compiler Compose | 2.1.21 | [Matrice KMP](https://kotlinlang.org/docs/multiplatform/multiplatform-compatibility-guide.html): Gradle fino a 8.12.1, AGP fino a 8.7.2, Xcode 16.3 |
| Gradle | 8.9 | [Release](https://docs.gradle.org/8.9/release-notes.html), richiesto da AGP 8.7; Wrapper ufficiale con SHA-256 della distribuzione |
| AGP | 8.7.2 | [Compatibilità AGP 8.7](https://developer.android.com/build/releases/agp-8-7-0-release-notes): JDK 17, Gradle 8.9, API 35 |
| Compose Multiplatform | 1.8.2 | [Release JetBrains](https://github.com/JetBrains/compose-multiplatform/releases/tag/v1.8.2), coppia Kotlin 2.1.21 anche nel [template desktop ufficiale](https://github.com/JetBrains/compose-multiplatform-desktop-template) |
| Coroutines | 1.10.2 | [Release Kotlin](https://github.com/Kotlin/kotlinx.coroutines/releases/tag/1.10.2), linea Kotlin 2.1 |
| Serialization JSON | 1.8.1 | [Release Kotlin](https://github.com/Kotlin/kotlinx.serialization/releases/tag/v1.8.1), Kotlin 2.1; plugin compiler allineato a Kotlin |
| SQLDelight | 2.1.0 | [Documentazione e piattaforme](https://sqldelight.github.io/sqldelight/2.1.0/), generatori SQL e driver SQLite JVM/Android; compatibilità concretamente sottoposta a build |
| JmDNS | 3.6.1 | [Release ufficiale](https://github.com/jmdns/jmdns/releases/tag/3.6.1), libreria Java per DNS-SD desktop |
| Bouncy Castle PKIX | 1.83 | [Distribuzione ufficiale Java](https://www.bouncycastle.org/download/bouncy-castle-java/), generazione X.509 desktop; ECDSA/TLS usano JCA/JSSE |
| Activity Compose | 1.10.1 | Dipendenza Android per ComponentActivity; API minima del prodotto 29 |
| JDK runtime/toolchain | 17 | TLS 1.3 e packaging desktop; macOS richiede JDK nativo per ciascuna architettura |

La rete non usa Ktor: TCP/TLS nativo come nella specifica. [NSD Android](https://developer.android.com/develop/connectivity/wifi/use-nsd), [Android Keystore](https://developer.android.com/privacy-and-security/keystore), [Network.framework Apple](https://developer.apple.com/documentation/network/nwlistener).

Checksum Wrapper JAR 8.9 verificato contro il servizio Gradle: `498495120a03b9a6ab5d155f5de3c8f0d986a449153702fb80fc80e134484f17`.

Mac non è un target Kotlin/Native dell'app desktop: è JVM con runtime incluso, generato separatamente su Intel e Apple Silicon. I target `iosArm64`, `iosSimulatorArm64`, `iosX64` sono dichiarati nei moduli KMP. Nessun target web.

Non esiste una matrice ufficiale unica per tutti i componenti: la matrice Kotlin/AGP restringe la scelta, le release ufficiali documentano le singole librerie, build e test verificano la combinazione. Xcode successivi a 16.3 non sono attestati da questa baseline e richiedono un incremento della toolchain verificato.
# Dipendenze native iOS — 28 settembre 2026

Adattatore Swift locale `iosApp/AppleIdentity`: Swift Certificates 1.7.0, Swift Crypto 3.9.0, Swift ASN.1 1.3.0. Versioni esatte nel manifest, commit Git dei tag ufficiali in `iosApp/Package.resolved`. Swift tools 5.9, Xcode 16.3 e deployment iOS 16; nessuna variazione dello stack Kotlin. Il [manifest Apple 1.7.0](https://github.com/apple/swift-certificates/blob/1.7.0/Package.swift) supporta iOS 13+ e Swift 5.9, con Crypto 2.5..<4 e ASN.1 1.1+; le versioni scelte rispettano questi vincoli. La verifica effettiva Xcode è registrata separatamente in STATO_SVILUPPO.md.

La CI copia il lock nel progetto Xcode generato e usa `-onlyUsePackageVersionsFromResolvedFile`. Per rigenerazione manuale, dopo XcodeGen:

```sh
mkdir -p iosApp/Lantern.xcodeproj/project.xcworkspace/xcshareddata/swiftpm
cp iosApp/Package.resolved iosApp/Lantern.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved
```
