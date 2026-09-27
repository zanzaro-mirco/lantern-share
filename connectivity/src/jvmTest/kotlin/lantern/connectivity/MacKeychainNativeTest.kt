package lantern.connectivity

import java.nio.file.Files
import kotlin.test.*

/** Opt-in: run only in a disposable account/keychain, never against a personal keychain. */
class MacKeychainNativeTest {
    @Test fun nativeImportReloadAndMigration() {
        check(System.getProperty("os.name").startsWith("Mac"))
        check(System.getenv("LANTERN_DISPOSABLE_KEYCHAIN") == "true") {
            "Prepare a disposable keychain and explicitly set LANTERN_DISPOSABLE_KEYCHAIN=true"
        }
        val directory = Files.createTempDirectory("lantern-native-keychain-")
        val old = Identity.open(directory.resolve("identity.p12"), "native-test-passphrase".toCharArray())
        val imported = MacKeychainIdentityStore().open(directory) { "native-test-passphrase".toCharArray() }!!
        assertEquals(old.id, imported.id)
        val reopened = MacKeychainIdentityStore().open(directory) { error("Unexpected password request") }!!
        val challenge = "native signing after reload".toByteArray()
        assertTrue(Identity.verify(old.certificate, challenge, reopened.sign(challenge)))
        val newProfile = Files.createTempDirectory("lantern-native-new-")
        val created = MacKeychainIdentityStore().open(newProfile) { error("Unexpected password request") }!!
        assertNotEquals(old.id, created.id)
        assertEquals(created.id, MacKeychainIdentityStore().open(newProfile) { null }!!.id)
        assertFalse(Files.exists(newProfile.resolve("identity.p12")))
    }
}
