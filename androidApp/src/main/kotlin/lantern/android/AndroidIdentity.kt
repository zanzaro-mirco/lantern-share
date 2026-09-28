package lantern.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import lantern.connectivity.Identity
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.math.BigInteger
import java.util.Date
import javax.security.auth.x500.X500Principal

private const val IDENTITY_ALIAS = "identity"

internal class IncompatibleAndroidIdentityException(cause: Exception) : IllegalStateException(
    "L'identità Android esistente non supporta TLS 1.3. Cancella i dati di Lantern e riapri l'app.",
    cause,
)

fun androidIdentity(): Identity {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    if (!store.containsAlias(IDENTITY_ALIAS)) {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(IDENTITY_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                // Conscrypt pre-hashes TLS 1.3 CertificateVerify and signs it with NONEwithECDSA.
                // SHA-256 remains authorized for Lantern's application-level signatures.
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
                .setCertificateSubject(X500Principal("CN=Lantern"))
                .setCertificateSerialNumber(BigInteger.ONE)
                .setCertificateNotBefore(Date(System.currentTimeMillis() - 60000))
                .setCertificateNotAfter(Date(System.currentTimeMillis() + 315360000000L)).build())
            generateKeyPair()
        }
    }
    requireTlsSigningSupport(store.getKey(IDENTITY_ALIAS, null) as PrivateKey)
    return Identity.fromPlatformKeyStore(store)
}

private fun requireTlsSigningSupport(privateKey: PrivateKey) {
    try {
        Signature.getInstance("NONEwithECDSA").run {
            initSign(privateKey)
            update(ByteArray(32))
            sign()
        }
    } catch (error: Exception) {
        throw IncompatibleAndroidIdentityException(error)
    }
}
