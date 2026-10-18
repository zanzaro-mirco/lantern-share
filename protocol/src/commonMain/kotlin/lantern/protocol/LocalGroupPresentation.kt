package lantern.protocol

import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupFailure
import lantern.domain.LocalGroupState
import lantern.domain.PendingGroupAdoption

/** Validate a LOCAL foundation loaded from storage; not remote admission or session authority. */
fun localGroupPresentation(anchor: GroupTrustAnchor?, identityId: String): LocalGroupState {
    if (!Wire.isFingerprint(identityId)) return LocalGroupState.Failed(LocalGroupFailure.IDENTITY_MISMATCH)
    if (anchor == null) return LocalGroupState.Empty
    if (!Wire.isFingerprint(anchor.groupId) || !Wire.isFingerprint(anchor.founderId)) {
        return LocalGroupState.Failed(LocalGroupFailure.INVALID_ROOT)
    }
    if (anchor.founderId != identityId) return LocalGroupState.Failed(LocalGroupFailure.IDENTITY_MISMATCH)
    return LocalGroupState.Founded(anchor)
}

/**
 * Presents only an already committed marker, read from GroupAdoptionRepository, never its pending
 * journal. The caller serializes OS identity/repository lifetime; verification runs outside SQLite.
 * A valid historical signature alone does not create membership, resume consent or authorize traffic.
 * Unexpected OS/provider failures propagate without publishing a partially checked state.
 */
fun localGroupPresentation(
    anchor: GroupTrustAnchor?,
    identityId: String,
    committedAdoption: PendingGroupAdoption?,
    verifySignature: (GroupAdmissionCertificate, ByteArray, String) -> Boolean,
): LocalGroupState {
    if (committedAdoption == null) return localGroupPresentation(anchor, identityId)
    if (!Wire.isFingerprint(identityId) || committedAdoption.localIdentity != identityId) {
        return LocalGroupState.Failed(LocalGroupFailure.IDENTITY_MISMATCH)
    }
    if (anchor != committedAdoption.anchor) return LocalGroupState.Failed(LocalGroupFailure.INVALID_ROOT)
    val result = try {
        GroupRootAdoptionJournalInspection.inspect(committedAdoption, identityId, verifySignature)
    } catch (_: InvalidGroupRootAdoptionJournalException) {
        return LocalGroupState.Failed(LocalGroupFailure.INVALID_ROOT)
    }
    return when (result) {
        GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid -> LocalGroupState.Adopted(committedAdoption.anchor)
        GroupRootAdoptionJournalInspectionResult.LocalIdentityMismatch -> LocalGroupState.Failed(LocalGroupFailure.IDENTITY_MISMATCH)
        else -> LocalGroupState.Failed(LocalGroupFailure.INVALID_ROOT)
    }
}
