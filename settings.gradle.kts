pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "Lantern"
include(":domain", ":protocol", ":persistence", ":connectivity", ":ui", ":desktopApp")
// Opt-in permits JVM work on hosts without an Android SDK; CI always enables this.
if (providers.gradleProperty("android").orNull == "true") include(":androidApp")
