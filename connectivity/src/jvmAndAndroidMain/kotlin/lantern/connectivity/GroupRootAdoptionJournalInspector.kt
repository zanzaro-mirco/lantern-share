package lantern.connectivity

import lantern.domain.PendingGroupAdoption
import lantern.protocol.GroupRootAdoptionJournalInspection
import lantern.protocol.GroupRootAdoptionJournalInspectionResult
import java.security.cert.X509Certificate

/** OS boundary for historical inspection; no repository writes, live selection or authorization. */
internal object GroupRootAdoptionJournalInspector {
    fun inspect(record: PendingGroupAdoption, currentIdentityId: String): GroupRootAdoptionJournalInspectionResult {
        // Per-invocation only: no stale certificate/provider results survive a later inspection.
        val certificates = mutableMapOf<String, X509Certificate>()
        val verifier by lazy { GroupAdmissionCertificateVerifier(certificates::get) }
        return GroupRootAdoptionJournalInspection.inspect(record, currentIdentityId) { supplied, bytes, signature ->
            certificates.getOrPut(supplied.identity) { GroupAdmissionEvidenceCertificates.decode(supplied) }
            verifier.verify(supplied.identity, bytes, signature)
        }
    }
}
