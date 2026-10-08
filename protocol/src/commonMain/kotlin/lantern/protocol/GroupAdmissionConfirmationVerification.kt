package lantern.protocol

sealed interface GroupAdmissionConfirmationResult {
    /** One remote signature only; not two confirmations, chain validity or durable trust. */
    data object VerifiedRemoteConfirmation : GroupAdmissionConfirmationResult
    data object AddressMismatch : GroupAdmissionConfirmationResult
    data object IdentityMismatch : GroupAdmissionConfirmationResult
    data object InvalidSignature : GroupAdmissionConfirmationResult
}

/** Isolated cryptographic binding; lifecycle/tickets/expiry/commit remain the owner's responsibility. */
object GroupAdmissionConfirmationVerification {
    /**
     * local/authenticated identities must come from this selected TLS connection, not received IDs.
     * The callback must use that exact peer certificate's key; invalid DER/signatures return false,
     * unexpected errors and cancellation propagate. The context must still belong to the current
     * live attempt when the owner processes the result. Never route this through bootstrap APPROVE.
     */
    fun verifyRemote(
        context: GroupAdmissionConfirmationContext,
        localIdentity: String,
        authenticatedPeerIdentity: String,
        senderIdentity: String,
        recipientIdentity: String,
        signature: String,
        verifySignature: (ByteArray, String) -> Boolean,
    ): GroupAdmissionConfirmationResult {
        require(localIdentity == context.issuerIdentity || localIdentity == context.memberIdentity) {
            "Local identity must participate in this confirmation"
        }
        val peerIdentity = if (localIdentity == context.issuerIdentity) context.memberIdentity else context.issuerIdentity
        if (senderIdentity != peerIdentity || recipientIdentity != localIdentity) {
            return GroupAdmissionConfirmationResult.AddressMismatch
        }
        if (authenticatedPeerIdentity != peerIdentity) return GroupAdmissionConfirmationResult.IdentityMismatch
        if (!ProtocolSignatureEncoding.isValid(signature) ||
            !verifySignature(context.approvalBytes(peerIdentity), signature)
        ) return GroupAdmissionConfirmationResult.InvalidSignature
        return GroupAdmissionConfirmationResult.VerifiedRemoteConfirmation
    }
}
