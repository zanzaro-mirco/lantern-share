package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository

/**
 * The first delegation from an independently saved local foundation. Not membership, consent,
 * or permission to adopt the anchor. The connection still needs evidence validation and both
 * context-bound confirmations before a future recoverable admission commit.
 */
class FounderGroupAdmissionDraft private constructor(
    val anchor: GroupTrustAnchor,
    val claim: GroupAdmissionClaim,
) {
    /** Fresh canonical bytes for the existing OS identity; never bytes supplied by a peer. */
    fun signedBytes(): ByteArray = GroupAdmissionCodec.signedBytes(claim)

    /** Signature encoding only; the caller must verify the actual OS signature and certificate. */
    fun withSignature(signature: String): GroupAdmissionProof =
        GroupAdmissionProof(anchor, listOf(SignedGroupAdmission(claim, signature)))

    companion object {
        /**
         * Synchronous preparation only. The owner serializes I/O and identity/group changes,
         * then checks its live request before using the returned untrusted proof. Errors propagate
         * without retries or writes. A final snapshot check is not distributed/OS atomicity.
         */
        fun prepareSigned(
            repository: LocalGroupRepository,
            localIdentityId: String,
            memberId: String,
            sign: (ByteArray) -> String,
            verifySignature: (ByteArray, String) -> Boolean,
        ): GroupAdmissionProof {
            val anchor = requireNotNull(repository.localGroup()) { "No saved local foundation" }
            val draft = prepare(anchor, localIdentityId, memberId)
            val signature = sign(draft.signedBytes())
            // Never let a signer mutate the verifier's canonical input or the resulting claim.
            check(verifySignature(draft.signedBytes(), signature)) { "OS admission signature verification failed" }
            check(repository.localGroup() == anchor) { "Local foundation changed during signing" }
            return draft.withSignature(signature)
        }

        /**
         * [anchor] must come from authoritative local storage, not received proof/discovery.
         * This founder-only path must not invent a self-admission or authorize delegated issuers.
         */
        fun prepare(
            anchor: GroupTrustAnchor,
            localIdentityId: String,
            memberId: String,
        ): FounderGroupAdmissionDraft {
            require(Wire.isFingerprint(anchor.groupId) && Wire.isFingerprint(anchor.founderId)) {
                "Invalid local foundation encoding"
            }
            require(Wire.isFingerprint(localIdentityId) && Wire.isFingerprint(memberId)) {
                "Invalid admission identity encoding"
            }
            require(localIdentityId == anchor.founderId) { "Local identity is not the saved founder" }
            return FounderGroupAdmissionDraft(
                anchor, GroupAdmissionClaim(anchor.groupId, localIdentityId, memberId),
            )
        }
    }
}
