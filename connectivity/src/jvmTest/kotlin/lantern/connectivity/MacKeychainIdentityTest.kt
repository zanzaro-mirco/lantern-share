package lantern.connectivity

import java.nio.file.Files
import kotlin.test.*

class MacKeychainIdentityTest {
    // Only the OS storage boundary is replaced. Files, certificates and signatures are real.
    private class TestKeychain : KeychainAccess {
        val entries = mutableMapOf<String, DesktopIdentityMaterial>()
        var rejectImport = false
        override fun find(alias: String) = entries[alias]
        override fun insert(alias: String, material: DesktopIdentityMaterial) {
            check(!rejectImport) { "Access denied" }
            check(entries.putIfAbsent(alias, material) == null)
        }
    }

    private fun directory() = Files.createTempDirectory("lantern-keychain-test-")
    private fun noPassword(): CharArray? = error("No passphrase should be requested")

    @Test fun restartAndMovedProfileKeepIdentity() {
        val keychain = TestKeychain()
        val directory = directory()
        val first = MacKeychainIdentityStore(keychain).open(directory, ::noPassword)!!
        assertFalse(Files.exists(directory.resolve("identity.p12")))
        val moved = directory.resolveSibling("${directory.fileName}-moved")
        Files.move(directory, moved)
        val second = MacKeychainIdentityStore(keychain).open(moved, ::noPassword)!!
        assertEquals(first.id, second.id)
        val message = "after restart".toByteArray()
        assertTrue(Identity.verify(first.certificate, message, second.sign(message)))
        assertEquals(1, keychain.entries.size)
    }

    @Test fun migrationPreservesCertificateAndBackupAndWipesPassword() {
        val directory = directory()
        val file = directory.resolve("identity.p12")
        val password = "test-migration-passphrase".toCharArray()
        val previous = Identity.open(file, password)
        val backup = Files.readAllBytes(file)
        val keychain = TestKeychain()
        val imported = MacKeychainIdentityStore(keychain).open(directory) { password }!!
        assertEquals(previous.id, imported.id)
        assertContentEquals(backup, Files.readAllBytes(file))
        assertTrue(password.all { it == '\u0000' })
        assertEquals(imported.id, MacKeychainIdentityStore(keychain).open(directory, ::noPassword)!!.id)
    }

    @Test fun cancellationAndWrongPassphraseDoNotModifyProfile() {
        val directory = directory()
        Identity.open(directory.resolve("identity.p12"), "original-passphrase".toCharArray())
        val keychain = TestKeychain()
        val store = MacKeychainIdentityStore(keychain)
        assertNull(store.open(directory) { null })
        val wrong = "incorrect-passphrase".toCharArray()
        assertFails { store.open(directory) { wrong } }
        assertTrue(wrong.all { it == '\u0000' })
        assertTrue(keychain.entries.isEmpty())
        assertFalse(Files.exists(directory.resolve("mac-identity.ref")))
    }

    @Test fun missingOrReplacedKeyFailsClosed() {
        val directory = directory()
        val keychain = TestKeychain()
        val store = MacKeychainIdentityStore(keychain)
        store.open(directory, ::noPassword)
        val alias = keychain.entries.keys.single()
        keychain.entries.clear()
        assertFails { store.open(directory, ::noPassword) }
        assertTrue(keychain.entries.isEmpty())
        keychain.entries[alias] = createDesktopIdentity()
        assertFails { store.open(directory, ::noPassword) }
    }

    @Test fun interruptedMigrationCanRetryOnlyWithSameIdentity() {
        val directory = directory()
        val original = Identity.open(directory.resolve("identity.p12"), "original-passphrase".toCharArray())
        val keychain = TestKeychain().apply { rejectImport = true }
        val store = MacKeychainIdentityStore(keychain)
        assertFails { store.open(directory) { "original-passphrase".toCharArray() } }
        assertTrue(Files.exists(directory.resolve("mac-identity.ref")))
        keychain.rejectImport = false
        assertEquals(original.id, store.open(directory) { "original-passphrase".toCharArray() }!!.id)
    }

    @Test fun existingDatabaseOrCorruptReferenceNeverCreatesIdentity() {
        val directory = directory()
        val keychain = TestKeychain()
        val store = MacKeychainIdentityStore(keychain)
        Files.writeString(directory.resolve("lantern.db"), "existing profile")
        assertFails { store.open(directory, ::noPassword) }
        Files.writeString(directory.resolve("mac-identity.ref"), "broken reference")
        assertFails { store.open(directory, ::noPassword) }
        assertTrue(keychain.entries.isEmpty())
    }

    @Test fun interruptedNewIdentityNeverSilentlyRegenerates() {
        val directory = directory()
        val keychain = TestKeychain().apply { rejectImport = true }
        val store = MacKeychainIdentityStore(keychain)
        assertFails { store.open(directory, ::noPassword) }
        val reference = Files.readAllBytes(directory.resolve("mac-identity.ref"))
        keychain.rejectImport = false
        assertFails { store.open(directory, ::noPassword) }
        assertContentEquals(reference, Files.readAllBytes(directory.resolve("mac-identity.ref")))
        assertTrue(keychain.entries.isEmpty())
    }

    @Test fun mismatchedPrivateKeyIsRejectedEvenWhenCertificatePinMatches() {
        val directory = directory()
        val keychain = TestKeychain()
        val store = MacKeychainIdentityStore(keychain)
        store.open(directory, ::noPassword)
        val alias = keychain.entries.keys.single()
        keychain.entries[alias] = keychain.entries.getValue(alias).copy(privateKey = createDesktopIdentity().privateKey)
        assertFails { store.open(directory, ::noPassword) }
    }
}
