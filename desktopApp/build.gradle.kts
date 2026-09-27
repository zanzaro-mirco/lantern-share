import org.jetbrains.compose.desktop.application.dsl.TargetFormat
plugins { alias(libs.plugins.kotlinJvm); alias(libs.plugins.compose); alias(libs.plugins.composeCompiler) }
kotlin { jvmToolchain(17) }
val desktopPlatform = providers.gradleProperty("desktopPlatform").orElse(provider {
    val os = System.getProperty("os.name").lowercase()
    val arch = if (System.getProperty("os.arch") in listOf("aarch64", "arm64")) "arm64" else "x64"
    "${if (os.contains("mac")) "macos" else if (os.contains("windows")) "windows" else "linux"}-$arch"
}).get()
require(desktopPlatform in setOf("windows-x64", "linux-x64", "macos-x64", "macos-arm64"))
dependencyLocking { lockFile.set(file("gradle-$desktopPlatform.lockfile")) }
dependencies {
    implementation(project(":connectivity")); implementation(project(":ui"))
    implementation(project(":persistence"))
    implementation("org.jetbrains.compose.desktop:desktop-jvm-$desktopPlatform:${libs.versions.compose.get()}")
}
tasks.register("lockDesktopDependencies") {
    doLast { configurations.getByName("compileClasspath").resolve(); configurations.getByName("runtimeClasspath").resolve() }
}
compose.desktop {
    application {
        mainClass = "lantern.desktop.MainKt"
        nativeDistributions {
            targetFormats(TargetFormat.Dmg, TargetFormat.Msi, TargetFormat.Deb)
            packageName = "Lantern"; packageVersion = "0.1.0"
            modules("java.sql", "jdk.crypto.ec", "java.naming", "java.management")
            macOS {
                bundleID = "dev.lantern.poc"; minimumSystemVersion = "13.0"; packageVersion = "1.0.0"
                infoPlist {
                    extraKeysRawXml = """
                        <key>NSLocalNetworkUsageDescription</key>
                        <string>Lantern cerca dispositivi e scambia messaggi nella rete locale.</string>
                        <key>NSBonjourServices</key><array><string>_lantern._tcp</string></array>
                    """.trimIndent()
                }
            }
        }
    }
}
