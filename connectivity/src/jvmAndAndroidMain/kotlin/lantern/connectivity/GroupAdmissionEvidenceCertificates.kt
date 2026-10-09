package lantern.connectivity

import lantern.protocol.GroupAdmissionEvidence
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/** Parses public evidence only. The independent root, chain, TLS roles and confirmations remain mandatory. */
internal object GroupAdmissionEvidenceCertificates {
    fun decode(evidence: GroupAdmissionEvidence): Map<String, X509Certificate> {
        val factory = CertificateFactory.getInstance("X.509")
        val certificates = linkedMapOf<String, X509Certificate>()
        for (supplied in evidence.certificates) {
            // The shared DTO already bounded and checked canonical Base64, before any OS parser.
            val der = Base64.getDecoder().decode(supplied.der)
            val input = ByteArrayInputStream(der)
            val certificate = try {
                factory.generateCertificate(input) as? X509Certificate ?: throw InvalidGroupAdmissionCertificateException()
            } catch (_: CertificateException) {
                throw InvalidGroupAdmissionCertificateException()
            }
            val encoded = try {
                certificate.encoded
            } catch (_: CertificateException) {
                throw InvalidGroupAdmissionCertificateException()
            }
            // Reject PEM/normalization, a second certificate and trailing bytes. Identity is exact DER, not just key.
            if (input.available() != 0 || !encoded.contentEquals(der) || digest(der) != supplied.identity) {
                throw InvalidGroupAdmissionCertificateException()
            }
            certificates[supplied.identity] = certificate
        }
        return certificates.toMap()
    }
}

/** No peer-controlled contents or parser cause in diagnostics. Unexpected provider failures still propagate. */
internal class InvalidGroupAdmissionCertificateException : IllegalArgumentException("Invalid group admission certificate")
