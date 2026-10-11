package lantern.protocol

import lantern.domain.GroupTrustAnchor

/**
 * Locally prepared origin, not a membership credential or permission to send messages.
 * No received evidence, network identifier or self-admission participates in founding.
 * The owner must serialize preparation/commit with membership changes and persist the anchor
 * before publishing a founded group. A null snapshot alone is not an atomic reservation.
 */
class GroupFoundationDraft private constructor(val anchor: GroupTrustAnchor) {
    companion object {
        /**
         * Call only following an explicit local create-group request, using the existing identity.
         * [generateGroupId] must generate a fresh OS-random 256-bit lowercase hexadecimal ID.
         * Validation checks spelling, not entropy. Failures propagate without retries or fallback.
         * [currentAnchor] is an authoritative local snapshot, never a discovery observation.
         */
        fun prepare(
            localIdentityId: String,
            currentAnchor: GroupTrustAnchor?,
            generateGroupId: () -> String,
        ): GroupFoundationDraft {
            require(Wire.isFingerprint(localIdentityId)) { "Invalid local foundation identity" }
            require(currentAnchor == null) { "An existing group must not be replaced by founding" }
            val groupId = generateGroupId()
            require(Wire.isFingerprint(groupId)) { "Invalid generated group identifier" }
            return GroupFoundationDraft(GroupTrustAnchor(groupId, localIdentityId))
        }
    }
}
