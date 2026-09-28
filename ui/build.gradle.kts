plugins { alias(libs.plugins.multiplatform); alias(libs.plugins.compose); alias(libs.plugins.composeCompiler); alias(libs.plugins.androidLibrary) apply false }
val withAndroid = providers.gradleProperty("android").orNull == "true"
if (withAndroid) apply(plugin = "com.android.library")
kotlin {
    jvm(); iosArm64(); iosSimulatorArm64(); iosX64()
    if (withAndroid) androidTarget()
    jvmToolchain(17)
    targets.withType<org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget>().configureEach {
        binaries.framework { baseName = "LanternUI"; isStatic = true }
    }
    sourceSets {
        commonMain.dependencies {
            api(project(":domain"))
            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.material3)
        }
        iosMain.dependencies { implementation(project(":persistence")) }
    }
}
if (withAndroid) extensions.configure<com.android.build.gradle.LibraryExtension> { namespace = "lantern.ui"; compileSdk = 35; defaultConfig { minSdk = 29 }; compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 } }
