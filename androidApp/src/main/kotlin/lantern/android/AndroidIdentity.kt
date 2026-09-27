package lantern.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import lantern.connectivity.Identity
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.math.BigInteger
import java.util.Date
import javax.security.auth.x500.X500Principal

fun androidIdentity(): Identity {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    if (!store.containsAlias("identity")) {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder("identity", KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setCertificateSubject(X500Principal("CN=Lantern"))
                .setCertificateSerialNumber(BigInteger.ONE)
                .setCertificateNotBefore(Date(System.currentTimeMillis() - 60000))
                .setCertificateNotAfter(Date(System.currentTimeMillis() + 315360000000L)).build())
            generateKeyPair()
        }
    }
    return Identity.fromPlatformKeyStore(store)
}
