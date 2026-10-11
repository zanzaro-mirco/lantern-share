package lantern.protocol

import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupFailure
import lantern.domain.LocalGroupState

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
