package lantern.connectivity

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

/** Narrow OS boundary; replacements are used only by tests. */
internal interface KeychainAccess {
    fun find(alias: String): DesktopIdentityMaterial?
    fun insert(alias: String, material: DesktopIdentityMaterial)
}

internal class JdkMacKeychain : KeychainAccess {
    private fun load() = KeyStore.getInstance("KeychainStore", "Apple").apply { load(null, null) }

    override fun find(alias: String): DesktopIdentityMaterial? {
        val keys = load()
        if (!keys.containsAlias(alias)) return null
        check(keys.isKeyEntry(alias)) { "L'elemento Portachiavi non contiene una chiave privata" }
        return DesktopIdentityMaterial(
            keys.getKey(alias, null) as? PrivateKey ?: error("Accesso alla chiave Portachiavi negato"),
            keys.getCertificate(alias) as X509Certificate,
        )
    }

    override fun insert(alias: String, material: DesktopIdentityMaterial) {
        val keys = load()
        check(!keys.containsAlias(alias)) { "L'alias Portachiavi è già occupato" }
        // The provider uses this only for the in-memory import, not as a login password.
        val importPassword = randomNonce().toCharArray()
        try {
            keys.setKeyEntry(alias, material.privateKey, importPassword, arrayOf(material.certificate))
            keys.store(null, null)
        } finally {
            importPassword.fill('\u0000')
        }
    }
}

/** Call under the application's profile lock, before opening its database or networking. */
class MacKeychainIdentityStore internal constructor(private val keychain: KeychainAccess) {
    constructor() : this(JdkMacKeychain())

    fun open(directory: Path, legacyPassword: () -> CharArray?): Identity? {
        Files.createDirectories(directory)
        val referencePath = directory.resolve("mac-identity.ref")
        val legacyPath = directory.resolve("identity.p12")
        val reference = if (Files.exists(referencePath)) readReference(referencePath) else null
        val alias = reference?.alias ?: "lantern-${digest(directory.toRealPath().toString().toByteArray(Charsets.UTF_8))}"
        val stored = keychain.find(alias)
        if (stored != null) {
            val identity = stored.identity()
            if (reference != null) {
                check(identity.id == reference.id) { "Identità Portachiavi diversa da quella del profilo" }
            } else {
                // An existing profile must never silently adopt a different identity.
                if (Files.exists(legacyPath)) {
                    val legacy = readLegacy(legacyPath, legacyPassword) ?: return null
                    check(legacy.identity().id == identity.id) { "Identità PKCS#12 e Portachiavi diverse" }
                } else {
                    check(!Files.exists(directory.resolve("lantern.db"))) {
                        "Profilo esistente senza riferimento: ripristinare identità e riferimento originali"
                    }
                }
                writeReference(referencePath, Reference(alias, identity.id))
            }
            return identity
        }

        val material = if (Files.exists(legacyPath)) {
            readLegacy(legacyPath, legacyPassword) ?: return null
        } else {
            check(reference == null && !Files.exists(directory.resolve("lantern.db"))) {
                "Identità Portachiavi assente: ripristinare l'originale; nessuna nuova identità creata"
            }
            createDesktopIdentity()
        }
        val identity = material.identity()
        check(reference == null || reference.id == identity.id) { "Il backup non corrisponde al profilo" }
        // Persist the expected pin first: an interrupted import cannot silently rotate identity.
        if (reference == null) writeReference(referencePath, Reference(alias, identity.id))
        keychain.insert(alias, material)
        val reloaded = keychain.find(alias)?.identity() ?: error("Identità non riletta dal Portachiavi")
        check(reloaded.id == identity.id) { "Verifica importazione Portachiavi fallita" }
        return reloaded
    }

    private fun readLegacy(path: Path, password: () -> CharArray?): DesktopIdentityMaterial? {
        val secret = password() ?: return null
        return try { readDesktopIdentity(path, secret) } finally { secret.fill('\u0000') }
    }

    private data class Reference(val alias: String, val id: String)

    private fun readReference(path: Path): Reference {
        check(Files.size(path) <= 256) { "Riferimento Portachiavi non valido" }
        val lines = Files.readAllLines(path, Charsets.UTF_8)
        check(lines.size == 3 && lines[0] == "lantern-keychain-1" &&
            lines[1].matches(Regex("lantern-[0-9a-f]{64}")) &&
            lines[2].matches(Regex("[0-9a-f]{64}"))) { "Riferimento Portachiavi non valido" }
        return Reference(lines[1], lines[2])
    }

    private fun writeReference(path: Path, reference: Reference) {
        val temporary = Files.createTempFile(path.parent, "keychain-reference-", ".tmp")
        try {
            Files.writeString(temporary, "lantern-keychain-1\n${reference.alias}\n${reference.id}\n")
            Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }
}
