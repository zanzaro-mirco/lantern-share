package lantern.connectivity

import lantern.protocol.Wire
import java.security.AlgorithmParameters
import java.security.InvalidKeyException
import java.security.Signature
import java.security.SignatureException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.util.Base64

/**
 * OS signature callback for the isolated group proof. Resolving a certificate is not
 * accepting a trust anchor: the caller still supplies an independently established root.
 * The resolver must return the certificate for the requested pin, never a key selected
 * by a peer-provided alias. Resolver failures propagate; missing/invalid evidence refuses.
 * No cache: each verification rechecks certificate validity and the current resolver.
 */
internal class GroupAdmissionCertificateVerifier(
    private val resolveCertificate: (String) -> X509Certificate?,
) {
    private val expectedCurve = AlgorithmParameters.getInstance("EC").run {
        init(ECGenParameterSpec("secp256r1"))
        getParameterSpec(ECParameterSpec::class.java)
    }

    fun verify(expectedIdentity: String, bytes: ByteArray, signature: String): Boolean {
        require(Wire.isFingerprint(expectedIdentity)) { "Invalid expected certificate pin" }
        if (signature.length !in 4..256) return false
        val decoded = try {
            Base64.getDecoder().decode(signature)
        } catch (_: IllegalArgumentException) {
            return false
        }
        if (Base64.getEncoder().encodeToString(decoded) != signature) return false
        val certificate = resolveCertificate(expectedIdentity) ?: return false
        // Do not use Identity.verify: its broad runCatching masks unexpected OS failures.
        return try {
            if (digest(certificate.encoded) != expectedIdentity) return false
            certificate.checkValidity()
            val key = certificate.publicKey as? ECPublicKey ?: return false
            if (!matchesCurve(key.params)) return false
            certificate.verify(key)
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(bytes)
                verify(decoded)
            }
        } catch (_: CertificateException) {
            false
        } catch (_: InvalidKeyException) {
            false
        } catch (_: SignatureException) {
            false
        }
    }

    private fun matchesCurve(actual: ECParameterSpec): Boolean =
        actual.curve == expectedCurve.curve && actual.generator == expectedCurve.generator &&
            actual.order == expectedCurve.order && actual.cofactor == expectedCurve.cofactor
}
