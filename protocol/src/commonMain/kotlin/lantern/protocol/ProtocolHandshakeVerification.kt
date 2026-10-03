package lantern.protocol

sealed interface ProtocolHandshakeVerificationResult {
    /** Remote attestation only: not local approval, persisted trust, or message authorization. */
    data class Verified(val capabilities: ProtocolNegotiationResult.Compatible) : ProtocolHandshakeVerificationResult
    data class Incompatible(val reason: ProtocolIncompatibility) : ProtocolHandshakeVerificationResult
    data object IdentityMismatch : ProtocolHandshakeVerificationResult
    data object AddressMismatch : ProtocolHandshakeVerificationResult
    data object InvalidSignature : ProtocolHandshakeVerificationResult
}

/** Stateless v1 verification, deliberately not wired into the v0 connection owner. */
object ProtocolHandshakeVerification {
    fun verifyRemoteApproval(
        local: ProtocolHandshakeParticipant,
        remote: ProtocolHandshakeParticipant,
        authenticatedPeerIdentity: String,
        approval: ProtocolHandshakeApproval,
        verifySignature: (ByteArray, String) -> Boolean,
    ): ProtocolHandshakeVerificationResult {
        if (approval.sender != remote.identity || approval.recipient != local.identity) {
            return ProtocolHandshakeVerificationResult.AddressMismatch
        }
        return verifyRemoteApproval(local, remote, authenticatedPeerIdentity, approval.signature, verifySignature)
    }

    /**
     * [authenticatedPeerIdentity] must come from the certificate accepted on this TLS connection,
     * never from discovery or the HELLO. [verifySignature] must use that same certificate's key.
     * The connection owner supplies its own frozen local offer and fresh nonce, and must still
     * enforce local confirmation, expiry/cancellation and trust before authorizing messages.
     */
    fun verifyRemoteApproval(
        local: ProtocolHandshakeParticipant,
        remote: ProtocolHandshakeParticipant,
        authenticatedPeerIdentity: String,
        signature: String,
        verifySignature: (ByteArray, String) -> Boolean,
    ): ProtocolHandshakeVerificationResult {
        if (remote.identity != authenticatedPeerIdentity || remote.identity == local.identity) {
            return ProtocolHandshakeVerificationResult.IdentityMismatch
        }
        val negotiation = when (val result = ProtocolNegotiation.negotiate(local.capabilities, remote.capabilities)) {
            is ProtocolNegotiationResult.Incompatible -> return ProtocolHandshakeVerificationResult.Incompatible(result.reason)
            is ProtocolNegotiationResult.Compatible -> result
        }
        if (!ProtocolHandshakeApproval.isValidSignature(signature)) {
            return ProtocolHandshakeVerificationResult.InvalidSignature
        }
        // Do not swallow adapter exceptions: a failed verifier must never become a success.
        if (!verifySignature(ProtocolHandshakeTranscript.approvalBytes(remote, local), signature)) {
            return ProtocolHandshakeVerificationResult.InvalidSignature
        }
        return ProtocolHandshakeVerificationResult.Verified(negotiation)
    }
}
