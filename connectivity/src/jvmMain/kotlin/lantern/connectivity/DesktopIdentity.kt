package lantern.connectivity

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.nio.file.*
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.cert.X509Certificate
import java.util.Date

fun Identity.Companion.open(path: Path, password: CharArray): Identity {
    require(password.size >= 12) { "Usare una passphrase di almeno 12 caratteri" }
    val ks = KeyStore.getInstance("PKCS12")
    if (Files.exists(path)) Files.newInputStream(path).use { ks.load(it, password) }
    else {
        ks.load(null, password)
        val material = createDesktopIdentity()
        ks.setKeyEntry("identity", material.privateKey, password, arrayOf(material.certificate))
        Files.createDirectories(path.toAbsolutePath().parent)
        val tmp = Files.createTempFile(path.toAbsolutePath().parent, "identity-", ".tmp")
        try {
            Files.newOutputStream(tmp).use { ks.store(it, password) }
            Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE)
        } finally { Files.deleteIfExists(tmp) }
    }
    return Identity(ks, password)
}

internal data class DesktopIdentityMaterial(val privateKey: PrivateKey, val certificate: X509Certificate) {
    fun identity(): Identity {
        certificate.checkValidity()
        certificate.verify(certificate.publicKey)
        val identity = Identity(certificate, privateKey)
        val challenge = SecureRandom().generateSeed(32)
        check(Identity.verify(certificate, challenge, identity.sign(challenge))) {
            "La chiave privata non corrisponde al certificato"
        }
        return identity
    }
}

internal fun readDesktopIdentity(path: Path, password: CharArray): DesktopIdentityMaterial {
    val keys = KeyStore.getInstance("PKCS12")
    Files.newInputStream(path).use { keys.load(it, password) }
    return DesktopIdentityMaterial(
        keys.getKey("identity", password) as PrivateKey,
        keys.getCertificate("identity") as X509Certificate,
    ).also { it.identity() }
}

internal fun createDesktopIdentity(): DesktopIdentityMaterial {
    val pair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    val subject = X500Name("CN=Lantern")
    val now = System.currentTimeMillis()
    val builder = JcaX509v3CertificateBuilder(
        subject, BigInteger(128, SecureRandom()), Date(now - 60_000),
        Date(now + 315_360_000_000L), subject, pair.public,
    )
    val certificate = JcaX509CertificateConverter().getCertificate(
        builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private)),
    )
    return DesktopIdentityMaterial(pair.private, certificate)
}
