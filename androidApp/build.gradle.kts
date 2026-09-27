plugins {
    alias(libs.plugins.androidApplication)
    kotlin("android")
    alias(libs.plugins.composeCompiler)
    alias(libs.plugins.compose)
}
android {
    namespace = "lantern.android"
    compileSdk = 35
    defaultConfig { applicationId = "dev.lantern.poc"; minSdk = 29; targetSdk = 35; versionCode = 1; versionName = "0.1.0" }
    buildFeatures { compose = true }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    packaging { resources.excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF" }
}
kotlin { jvmToolchain(17) }
dependencies {
    implementation(project(":ui"))
    implementation(project(":connectivity"))
    implementation(project(":persistence"))
    implementation(libs.activity)
    implementation(compose.material3); implementation(compose.foundation)
    implementation(libs.sqliteAndroid)
}
