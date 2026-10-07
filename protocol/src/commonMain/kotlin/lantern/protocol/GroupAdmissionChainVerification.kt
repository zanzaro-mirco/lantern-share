package lantern.protocol

import lantern.domain.GroupTrustAnchor

/** Proof validation only, not confirmation of a live attempt or permission to write trust. */
sealed interface GroupAdmissionChainResult {
    data object VerifiedChain : GroupAdmissionChainResult
    data object InvalidLength : GroupAdmissionChainResult
    data object GroupMismatch : GroupAdmissionChainResult
    data object BrokenChain : GroupAdmissionChainResult
    data object RepeatedIdentity : GroupAdmissionChainResult
    data object MemberMismatch : GroupAdmissionChainResult
    data class InvalidSignature(val admissionIndex: Int) : GroupAdmissionChainResult {
        init {
            require(admissionIndex >= 0) { "Admission index must not be negative" }
        }
    }
}

/** Validates one ordered delegation path, not a graph supplied by an untrusted peer. */
object GroupAdmissionChainVerification {
    // Bounds CPU/signature work, not the number of members in a group. No wire format yet.
    const val MAX_ADMISSIONS = 32

    /**
     * The anchor and expected member are independently established context, not received fields.
     * The OS callback must resolve a certificate whose verified fingerprint equals `issuerId`
     * and verify with that exact certificate's key; unknown/mismatched keys or invalid signatures
     * return false. Unexpected failures/cancellation propagate. No certificate is auto-pinned.
     *
     * Each successful signature establishes the next issuer's delegation within this proof only. The founder
     * need not be online and has no special administrative powers. The whole proof is checked
     * before returning; no partially verified membership or reusable signature token is exposed.
     * The supplied list must not be concurrently mutated while its snapshot is being copied.
     */
    fun verify(
        anchor: GroupTrustAnchor,
        expectedMemberId: String,
        admissions: List<SignedGroupAdmission>,
        verifySignature: (issuerId: String, bytes: ByteArray, signature: String) -> Boolean,
    ): GroupAdmissionChainResult {
        require(
            Wire.isFingerprint(anchor.groupId) && Wire.isFingerprint(anchor.founderId) &&
                Wire.isFingerprint(expectedMemberId),
        ) { "Invalid chain context identifier encoding" }
        if (admissions.isEmpty() || admissions.size > MAX_ADMISSIONS) {
            return GroupAdmissionChainResult.InvalidLength
        }
        // Own the bounded snapshot so callback changes to the caller's list cannot alter the proof.
        val path = admissions.toList()
        val seen = mutableSetOf(anchor.founderId)
        var issuer = anchor.founderId
        for (admission in path) {
            val claim = admission.claim
            if (claim.groupId != anchor.groupId) return GroupAdmissionChainResult.GroupMismatch
            if (claim.issuerId != issuer) return GroupAdmissionChainResult.BrokenChain
            if (!seen.add(claim.memberId)) return GroupAdmissionChainResult.RepeatedIdentity
            issuer = claim.memberId
        }
        if (issuer != expectedMemberId) return GroupAdmissionChainResult.MemberMismatch
        for ((index, admission) in path.withIndex()) {
            if (!verifySignature(
                    admission.claim.issuerId,
                    GroupAdmissionCodec.signedBytes(admission.claim),
                    admission.signature,
                )
            ) {
                return GroupAdmissionChainResult.InvalidSignature(index)
            }
        }
        return GroupAdmissionChainResult.VerifiedChain
    }
}
