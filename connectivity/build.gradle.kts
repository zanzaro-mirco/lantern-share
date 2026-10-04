plugins {
    alias(libs.plugins.multiplatform)
    alias(libs.plugins.androidLibrary) apply false
}

val withAndroid = providers.gradleProperty("android").orNull == "true"
if (withAndroid) apply(plugin = "com.android.library")

kotlin {
    jvm()
    if (withAndroid) androidTarget()
    jvmToolchain(17)
    applyDefaultHierarchyTemplate()
    sourceSets {
        commonMain.dependencies { api(project(":protocol")) }
        val jvmAndAndroidMain by creating { dependsOn(commonMain.get()) }
        jvmMain {
            dependsOn(jvmAndAndroidMain)
            dependencies {
                implementation(libs.bcpkix)
                implementation(libs.jmdns)
            }
        }
        if (withAndroid) getByName("androidMain").dependsOn(jvmAndAndroidMain)
        jvmTest.dependencies {
            implementation(kotlin("test"))
            implementation(project(":persistence"))
        }
    }
}

if (withAndroid) extensions.configure<com.android.build.gradle.LibraryExtension> {
    namespace = "lantern.connectivity"
    compileSdk = 35
    defaultConfig { minSdk = 29 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

tasks.withType<Test>().configureEach {
    systemProperty("lantern.multicast", providers.gradleProperty("multicast").orElse("false").get())
    if (providers.gradleProperty("macKeychain").orNull != "true") {
        exclude("**/MacKeychainNativeTest*")
    } else {
        reports.junitXml.outputLocation.set(layout.buildDirectory.dir("test-results/macKeychain"))
        reports.html.outputLocation.set(layout.buildDirectory.dir("reports/tests/macKeychain"))
    }
}

// Fixture entry point stays in jvmTest: no internal bootstrap API exposed to the application.
tasks.register<JavaExec>("runHandshakeV1InteropFixture") {
    group = "verification"
    description = "Run the disposable pinned-TLS bootstrap fixture (selected peer pin required)"
    dependsOn("jvmTestClasses")
    classpath = tasks.named<Test>("jvmTest").get().classpath
    mainClass.set("lantern.connectivity.HandshakeV1InteropFixture")
    javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(17)) })
    standardInput = System.`in`
    providers.gradleProperty("interopPeerPin").orNull?.let { args(it) }
}
