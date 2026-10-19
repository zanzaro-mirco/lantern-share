package lantern.protocol

import lantern.domain.GroupAdoptionRepository
import lantern.domain.GroupTrustAnchor

/** Untrusted public membership material. Its member must be bound independently to mutual TLS. */
class GroupMembershipEvidence(
    val anchor: GroupTrustAnchor,
    val memberIdentity: String,
    val admission: GroupAdmissionEvidence?,
) {
    init {
        require(Wire.isFingerprint(anchor.groupId) && Wire.isFingerprint(anchor.founderId) &&
            Wire.isFingerprint(memberIdentity)) { "Invalid membership identifiers" }
        if (admission == null) require(memberIdentity == anchor.founderId) { "Missing membership path" }
        else {
            require(memberIdentity != anchor.founderId && admission.proof.anchor == anchor &&
                admission.proof.admissions.last().claim.memberId == memberIdentity) { "Membership path mismatch" }
        }
    }

    /** TLS already proves possession of the member's key. No received root becomes trusted here. */
    fun verify(
        expectedAnchor: GroupTrustAnchor,
        authenticatedPeerIdentity: String,
        verifySignature: (GroupAdmissionCertificate, ByteArray, String) -> Boolean,
    ): Boolean {
        require(Wire.isFingerprint(authenticatedPeerIdentity)) { "Invalid TLS identity" }
        if (anchor != expectedAnchor || memberIdentity != authenticatedPeerIdentity) return false
        val evidence = admission ?: return authenticatedPeerIdentity == expectedAnchor.founderId
        val certificates = evidence.certificates.associateBy { it.identity }
        return GroupAdmissionChainVerification.verify(evidence.proof, expectedAnchor, authenticatedPeerIdentity) { id, bytes, signature ->
            verifySignature(certificates.getValue(id), bytes, signature)
        } == GroupAdmissionChainResult.VerifiedChain
    }
}

/** Read-only producer consumed by the selected membership-check service, never a pending journal. */
object LocalGroupMembership {
    fun prepare(
        repository: GroupAdoptionRepository,
        identityId: String,
        certificate: GroupAdmissionCertificate,
        verifySignature: (GroupAdmissionCertificate, ByteArray, String) -> Boolean,
    ): GroupMembershipEvidence {
        require(certificate.identity == identityId) { "OS certificate identity mismatch" }
        val anchor = requireNotNull(repository.localGroup()) { "No local group" }
        val committed = repository.committedGroupAdoption()
        val admission = if (committed == null) {
            require(anchor.founderId == identityId) { "No committed local membership" }
            null
        } else {
            check(committed.anchor == anchor && committed.localIdentity == identityId) { "Local membership mismatch" }
            check(GroupRootAdoptionJournalInspection.inspect(committed, identityId, verifySignature) ==
                GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid) { "Invalid local membership proof" }
            val journal = GroupRootAdoptionJournalCodec.decode(committed.payload())
            check(journal.memberCertificate == certificate) { "Current OS certificate differs from membership" }
            journal.evidence
        }
        check(repository.localGroup() == anchor) { "Local group changed during verification" }
        val current = repository.committedGroupAdoption()
        check(if (committed == null) current == null else current != null && committed.sameRecord(current)) {
            "Local membership changed during verification"
        }
        return GroupMembershipEvidence(anchor, identityId, admission)
    }
}
