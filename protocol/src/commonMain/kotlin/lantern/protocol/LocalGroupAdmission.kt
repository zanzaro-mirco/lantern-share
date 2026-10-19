package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupAdoptionRepository

/**
 * Evidence from authoritative LOCAL membership, never from a pending journal or received root.
 * Does not grant live consent, write membership or own a connection. The caller serializes
 * identity/store changes and discards results after cancellation or the original deadline.
 */
object LocalGroupAdmission {
    fun prepareSigned(
        repository: GroupAdoptionRepository,
        identityId: String,
        memberId: String,
        certificate: GroupAdmissionCertificate,
        sign: (ByteArray) -> String,
        verifySignature: (GroupAdmissionCertificate, ByteArray, String) -> Boolean,
    ): GroupAdmissionEvidence {
        require(certificate.identity == identityId) { "Local certificate identity mismatch" }
        val anchor = requireNotNull(repository.localGroup()) { "No saved local group" }
        val committed = repository.committedGroupAdoption()
        val claim = GroupAdmissionClaim(anchor.groupId, identityId, memberId)
        // Validate identity syntax and self-admission before OS work, also for delegated issuers.
        GroupAdmissionCodec.signedBytes(claim)
        val previous: List<SignedGroupAdmission>
        val certificates: List<GroupAdmissionCertificate>
        if (committed == null) {
            FounderGroupAdmissionDraft.prepare(anchor, identityId, memberId)
            previous = emptyList()
            certificates = emptyList()
        } else {
            check(committed.anchor == anchor && committed.localIdentity == identityId) { "Local membership mismatch" }
            check(GroupRootAdoptionJournalInspection.inspect(committed, identityId, verifySignature) ==
                GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid) { "Invalid local membership proof" }
            val journal = GroupRootAdoptionJournalCodec.decode(committed.payload())
            check(journal.memberCertificate == certificate) { "Current OS certificate differs from local membership" }
            previous = journal.evidence.proof.admissions
            certificates = journal.evidence.certificates
            require(previous.size < GroupAdmissionChainVerification.MAX_ADMISSIONS) { "Delegation path limit reached" }
            require(memberId != anchor.founderId && previous.none { it.claim.memberId == memberId }) {
                "Delegation would repeat an identity"
            }
        }
        val signature = sign(GroupAdmissionCodec.signedBytes(claim))
        check(verifySignature(certificate, GroupAdmissionCodec.signedBytes(claim), signature)) {
            "OS admission signature verification failed"
        }
        val evidence = GroupAdmissionEvidence(
            GroupAdmissionProof(anchor, previous + SignedGroupAdmission(claim, signature)),
            certificates + certificate,
        )
        // Enforce existing wire bounds before handing evidence to an owner; never truncate a path.
        GroupAdmissionEvidenceCodec.encode(evidence)
        check(repository.localGroup() == anchor) { "Local group changed during signing" }
        val current = repository.committedGroupAdoption()
        check(if (committed == null) current == null else current != null && committed.sameRecord(current)) {
            "Local membership changed during signing"
        }
        return evidence
    }
}
