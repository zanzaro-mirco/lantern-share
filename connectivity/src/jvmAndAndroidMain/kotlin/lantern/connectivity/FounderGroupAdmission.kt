package lantern.connectivity

import lantern.domain.LocalGroupRepository
import lantern.protocol.FounderGroupAdmissionDraft
import lantern.protocol.GroupAdmissionProof

/**
 * Prepare evidence for a future explicit founder-issued admission, off the UI thread.
 * The caller serializes this operation with identity/group changes and cancellation. It must
 * discard the result if its live connection/request ends; this helper owns neither lifecycle
 * nor transport and cannot establish membership, persist trust or commit remote admission.
 * Consumed by the explicit founder path in GroupAdmissionService. Delegated members require
 * a different, verified local proof path; a durable anchor alone is not sufficient.
 */
internal fun prepareFounderGroupAdmission(
    identity: Identity,
    repository: LocalGroupRepository,
    memberId: String,
): GroupAdmissionProof {
    val verifier = GroupAdmissionCertificateVerifier { issuer ->
        identity.certificate.takeIf { issuer == identity.id }
    }
    return FounderGroupAdmissionDraft.prepareSigned(repository, identity.id, memberId, identity::sign) { bytes, signature ->
        verifier.verify(identity.id, bytes, signature)
    }
}
