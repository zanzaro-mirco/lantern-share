package lantern.connectivity

import lantern.domain.IdentityStore
import java.security.*
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.*

fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
fun randomNonce(): String = ByteArray(32).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }

class Identity internal constructor(
    val certificate: X509Certificate,
    private val privateKey: PrivateKey,
) : IdentityStore {
    internal constructor(keys: KeyStore, password: CharArray?) : this(
        keys.getCertificate("identity") as X509Certificate,
        keys.getKey("identity", password) as PrivateKey,
    )
    override val id = digest(certificate.encoded)
    fun sign(bytes: ByteArray): String = Base64.getEncoder().encodeToString(Signature.getInstance("SHA256withECDSA").run { initSign(privateKey); update(bytes); sign() })
    fun context(allowed: (String) -> Boolean): SSLContext {
        // Explicit key manager also supports non-exportable Android Keystore keys.
        val km = object : X509ExtendedKeyManager() {
            override fun getPrivateKey(alias: String?) = if (alias == "identity") privateKey else null
            override fun getCertificateChain(alias: String?) = if (alias == "identity") arrayOf(certificate) else null
            override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = if (keyType?.startsWith("EC") == true) arrayOf("identity") else null
            override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = getClientAliases(keyType, issuers)
            override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: java.net.Socket?) = if (keyType?.any { it.startsWith("EC") } == true) "identity" else null
            override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: java.net.Socket?) = getServerAliases(keyType, issuers)?.firstOrNull()
            override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?) = chooseClientAlias(keyType, issuers, null)
            override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?) = chooseServerAlias(keyType, issuers, null)
        }
        return SSLContext.getInstance("TLSv1.3").apply { init(arrayOf(km), arrayOf(PinnedTrust(allowed)), SecureRandom()) }
    }
    companion object {
        fun fromPlatformKeyStore(keys: KeyStore): Identity = Identity(keys, null)
        fun verify(cert: X509Certificate, bytes: ByteArray, signature: String): Boolean = runCatching {
            Signature.getInstance("SHA256withECDSA").run { initVerify(cert); update(bytes); verify(Base64.getDecoder().decode(signature)) }
        }.getOrDefault(false)
    }
}
class PinnedTrust(private val allowed: (String) -> Boolean) : X509TrustManager {
    private fun check(chain: Array<out X509Certificate>?) {
        if (chain == null || chain.size != 1) throw java.security.cert.CertificateException("Un solo certificato richiesto")
        val cert = chain[0]
        cert.checkValidity()
        cert.verify(cert.publicKey)
        val key = cert.publicKey as? java.security.interfaces.ECPublicKey
        if (key == null || key.params.curve.field.fieldSize != 256 || !allowed(digest(cert.encoded))) throw java.security.cert.CertificateException("Identità non autorizzata")
    }
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = check(chain)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = check(chain)
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}
