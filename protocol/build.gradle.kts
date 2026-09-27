plugins { alias(libs.plugins.multiplatform); alias(libs.plugins.serialization); alias(libs.plugins.androidLibrary) apply false }
val withAndroid = providers.gradleProperty("android").orNull == "true"
if (withAndroid) apply(plugin = "com.android.library")
kotlin {
    jvm(); iosArm64(); iosSimulatorArm64(); iosX64()
    if (withAndroid) androidTarget()
    jvmToolchain(17)
    sourceSets { commonMain.dependencies { api(project(":domain")); api(libs.serialization) }; commonTest.dependencies { implementation(kotlin("test")) } }
}
if (withAndroid) extensions.configure<com.android.build.gradle.LibraryExtension> { namespace = "lantern.protocol"; compileSdk = 35; defaultConfig { minSdk = 29 }; compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 } }
