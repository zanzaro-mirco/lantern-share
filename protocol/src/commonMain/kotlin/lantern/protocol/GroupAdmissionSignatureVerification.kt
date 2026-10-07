package lantern.protocol

import lantern.domain.GroupAdmissionBinding

sealed interface GroupAdmissionSignatureResult {
    /** Cryptographic binding only: not issuer membership, user approval or persisted trust. */
    data object VerifiedSignature : GroupAdmissionSignatureResult
    data class ContextMismatch(val binding: GroupAdmissionBinding) : GroupAdmissionSignatureResult {
        init {
            require(binding != GroupAdmissionBinding.MATCHED) { "A mismatch cannot represent a matched context" }
        }
    }
    data object SignerIdentityMismatch : GroupAdmissionSignatureResult
    data object InvalidSignature : GroupAdmissionSignatureResult
}

/** Does not authorize admission or write repositories. Unexpected OS verifier errors propagate. */
object GroupAdmissionSignatureVerification {
    /**
     * Expected IDs come from the admission context, not from the received statement.
     * `signerIdentity` must be the independently checked certificate fingerprint of the
     * very key used by `verifySignature`, never an unverified ID supplied by the sender.
     * Checking that this issuer is an authorized member of this group remains mandatory.
     * The OS adapter returns false for invalid DER/signatures; unexpected OS failures propagate.
     */
    fun verify(
        admission: SignedGroupAdmission,
        expectedGroupId: String,
        expectedIssuerId: String,
        expectedMemberId: String,
        signerIdentity: String,
        verifySignature: (bytes: ByteArray, signature: String) -> Boolean,
    ): GroupAdmissionSignatureResult {
        require(
            Wire.isFingerprint(expectedGroupId) && Wire.isFingerprint(expectedIssuerId) &&
                Wire.isFingerprint(expectedMemberId),
        ) { "Invalid admission context identifier encoding" }
        val binding = admission.claim.bindingTo(expectedGroupId, expectedIssuerId, expectedMemberId)
        if (binding != GroupAdmissionBinding.MATCHED) {
            return GroupAdmissionSignatureResult.ContextMismatch(binding)
        }
        if (signerIdentity != expectedIssuerId) return GroupAdmissionSignatureResult.SignerIdentityMismatch
        if (!verifySignature(GroupAdmissionCodec.signedBytes(admission.claim), admission.signature)) {
            return GroupAdmissionSignatureResult.InvalidSignature
        }
        return GroupAdmissionSignatureResult.VerifiedSignature
    }
}
