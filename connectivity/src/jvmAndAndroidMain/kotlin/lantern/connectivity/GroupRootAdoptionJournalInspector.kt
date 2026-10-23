package lantern.connectivity

import lantern.domain.PendingGroupAdoption
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupState
import lantern.protocol.GroupRootAdoptionJournalInspection
import lantern.protocol.GroupRootAdoptionJournalInspectionResult
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.localGroupPresentation
import java.security.cert.X509Certificate
import java.util.Base64

/** OS boundary for historical inspection; no repository writes, live selection or authorization. */
internal object GroupRootAdoptionJournalInspector {
    fun inspect(record: PendingGroupAdoption, currentIdentityId: String): GroupRootAdoptionJournalInspectionResult =
        withVerifier { GroupRootAdoptionJournalInspection.inspect(record, currentIdentityId, it) }

    fun presentation(anchor: GroupTrustAnchor?, currentIdentityId: String, committed: PendingGroupAdoption?): LocalGroupState =
        withVerifier { localGroupPresentation(anchor, currentIdentityId, committed, it) }

    internal fun <T> withVerifier(block: ((GroupAdmissionCertificate, ByteArray, String) -> Boolean) -> T): T {
        // Per-invocation only: no stale certificate/provider results survive a later inspection.
        val certificates = mutableMapOf<String, X509Certificate>()
        val verifier by lazy { GroupAdmissionCertificateVerifier(certificates::get) }
        return block { supplied, bytes, signature ->
            val certificate = certificates.getOrPut(supplied.identity) { GroupAdmissionEvidenceCertificates.decode(supplied) }
            // A roster combines multiple chains in this invocation. A cached ID must not
            // skip the exact-DER check when another entry supplies different public bytes.
            check(Base64.getEncoder().encodeToString(certificate.encoded) == supplied.der) { "Conflicting certificate encoding" }
            verifier.verify(supplied.identity, bytes, signature)
        }
    }
}
