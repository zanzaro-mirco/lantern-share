plugins { alias(libs.plugins.multiplatform); alias(libs.plugins.sqldelight); alias(libs.plugins.androidLibrary) apply false }
val withAndroid = providers.gradleProperty("android").orNull == "true"
if (withAndroid) apply(plugin = "com.android.library")
kotlin {
    jvm(); iosArm64(); iosSimulatorArm64(); iosX64()
    if (withAndroid) androidTarget()
    jvmToolchain(17)
    applyDefaultHierarchyTemplate()
    sourceSets {
        commonMain.dependencies { api(project(":domain")) }
        val jvmAndAndroidMain by creating { dependsOn(commonMain.get()) }
        jvmMain {
            dependsOn(jvmAndAndroidMain)
            dependencies { api(libs.sqlite) }
        }
        if (withAndroid) getByName("androidMain").dependsOn(jvmAndAndroidMain)
    }
}
sqldelight { databases { create("LanternDatabase") { packageName.set("lantern.persistence") } } }
if (withAndroid) extensions.configure<com.android.build.gradle.LibraryExtension> { namespace = "lantern.persistence"; compileSdk = 35; defaultConfig { minSdk = 29 }; compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 } }
