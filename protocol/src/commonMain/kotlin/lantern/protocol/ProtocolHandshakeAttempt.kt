package lantern.protocol

sealed interface ProtocolHandshakeState {
    data object AwaitingHello : ProtocolHandshakeState
    data class AwaitingConfirmation(val remoteApproved: Boolean) : ProtocolHandshakeState
    data class SigningApproval(val remoteApproved: Boolean) : ProtocolHandshakeState
    data class SendingApproval(val remoteApproved: Boolean) : ProtocolHandshakeState
    data object AwaitingRemoteApproval : ProtocolHandshakeState
    /** Both proofs and the local write succeeded; still not persisted trust or group membership. */
    data class Ready(val capabilities: ProtocolNegotiationResult.Compatible) : ProtocolHandshakeState
    data class Closed(val reason: ProtocolHandshakeFailure) : ProtocolHandshakeState
}

sealed interface ProtocolHandshakeFailure {
    data object IdentityMismatch : ProtocolHandshakeFailure
    data class Incompatible(val reason: ProtocolIncompatibility) : ProtocolHandshakeFailure
    data object UnexpectedMessage : ProtocolHandshakeFailure
    data object InvalidSignature : ProtocolHandshakeFailure
    data object AddressMismatch : ProtocolHandshakeFailure
    data object LocalOperationFailed : ProtocolHandshakeFailure
    data object Expired : ProtocolHandshakeFailure
    data object Cancelled : ProtocolHandshakeFailure
    data object ClockMovedBackwards : ProtocolHandshakeFailure
}

/** Opaque, attempt-owned callback tickets. Bytes/frames are defensive views, never mutable state. */
sealed interface ProtocolHandshakeOperation {
    class Sign internal constructor(bytes: ByteArray) : ProtocolHandshakeOperation {
        private val content = bytes.copyOf()
        val bytes: ByteArray get() = content.copyOf()
    }

    class Send internal constructor(val approval: ProtocolHandshakeApproval) : ProtocolHandshakeOperation
}

/** The UI must retain this exact comparison ticket when dispatching the user's confirmation. */
class ProtocolHandshakeComparison internal constructor(bytes: ByteArray) {
    private val content = bytes.copyOf()
    val bytes: ByteArray get() = content.copyOf()
}

/**
 * Isolated v1 bootstrap on one already authenticated TLS connection, not a service or trust store.
 * The owner must serialize ALL calls on its connection queue, send [localHello] before receiving
 * frames, and bind [verifyRemoteSignature] to that connection's accepted certificate.
 * [selectedPeerIdentity] is an explicit local selection, not a discovery-derived authorization.
 * [selectedAtMillis] and [nowMillis] use the same monotonic clock; selection precedes TLS.
 * Each reconnect needs a new instance and fresh OS-generated nonces, never a reset of this one.
 */
class ProtocolHandshakeAttempt(
    local: ProtocolHandshakeParticipant,
    selectedPeerIdentity: String,
    private val authenticatedPeerIdentity: String,
    private val selectedAtMillis: Long,
    private val nowMillis: () -> Long,
    private val verifyRemoteSignature: (ByteArray, String) -> Boolean,
) {
    private val local = snapshot(local)
    private var remote: ProtocolHandshakeParticipant? = null
    private var negotiation: ProtocolNegotiationResult.Compatible? = null
    private var remoteApproved = false
    private var localApprovalSent = false
    private var operation: ProtocolHandshakeOperation? = null
    private var comparison: ProtocolHandshakeComparison? = null
    private var verifying = false
    private var lastObservedMillis = selectedAtMillis
    private var current: ProtocolHandshakeState = ProtocolHandshakeState.AwaitingHello

    init {
        require(Wire.isFingerprint(selectedPeerIdentity)) { "Invalid selected peer identity" }
        require(selectedPeerIdentity != local.identity) { "Cannot select local identity" }
        if (authenticatedPeerIdentity != selectedPeerIdentity) close(ProtocolHandshakeFailure.IdentityMismatch)
    }

    val localHello: ProtocolHandshakeFrame.Hello?
        get() = if (isActive()) ProtocolHandshakeFrame.Hello(snapshot(local)) else null

    /** Remaining monotonic budget for an adapter's blocking read; null also invalidates the attempt. */
    val remainingMillis: Long?
        get() = if (isActive()) TIMEOUT_MILLIS - (lastObservedMillis - selectedAtMillis) else null

    /** Reading state also enforces expiration, so a delayed timer cannot leave a ready attempt live. */
    val state: ProtocolHandshakeState
        get() {
            isActive()
            return when (val value = current) {
                is ProtocolHandshakeState.Ready -> value.copy(
                    capabilities = value.capabilities.copy(features = value.capabilities.features.toSet()),
                )
                else -> value
            }
        }

    /** Full transcript for the comparison-code hash, only after a compatible, TLS-bound HELLO. */
    fun comparison(): ProtocolHandshakeComparison? {
        if (!isActive()) return null
        return comparison
    }

    fun receive(frame: ProtocolHandshakeFrame): Boolean {
        if (!isActive()) return false
        if (verifying || current is ProtocolHandshakeState.Ready) return close(ProtocolHandshakeFailure.UnexpectedMessage)
        return when (frame) {
            is ProtocolHandshakeFrame.Hello -> receiveHello(frame.participant)
            is ProtocolHandshakeFrame.Approve -> receiveApproval(frame.approval)
        }
    }

    /** Call only for explicit user confirmation of this attempt's full comparison code. */
    fun confirm(comparison: ProtocolHandshakeComparison): ProtocolHandshakeOperation.Sign? {
        if (!isActive() || this.comparison !== comparison ||
            current !is ProtocolHandshakeState.AwaitingConfirmation || verifying
        ) return null
        val peer = checkNotNull(remote)
        val request = ProtocolHandshakeOperation.Sign(ProtocolHandshakeTranscript.approvalBytes(local, peer))
        operation = request
        current = ProtocolHandshakeState.SigningApproval(remoteApproved)
        return request
    }

    /** The trusted OS signer returns the signature of exactly [request]'s bytes. */
    fun signed(request: ProtocolHandshakeOperation.Sign, signature: String): ProtocolHandshakeOperation.Send? {
        if (!isActive() || operation !== request || current !is ProtocolHandshakeState.SigningApproval) return null
        if (!ProtocolHandshakeApproval.isValidSignature(signature)) {
            close(ProtocolHandshakeFailure.LocalOperationFailed)
            return null
        }
        val send = ProtocolHandshakeOperation.Send(
            ProtocolHandshakeApproval(local.identity, checkNotNull(remote).identity, signature),
        )
        operation = send
        current = ProtocolHandshakeState.SendingApproval(remoteApproved)
        return send
    }

    /** A successful write callback, not preparation/queuing of the APPROVE, advances this state. */
    fun sent(request: ProtocolHandshakeOperation.Send): Boolean {
        if (!isActive() || operation !== request || current !is ProtocolHandshakeState.SendingApproval) return false
        operation = null
        localApprovalSent = true
        updateProgress()
        return true
    }

    fun operationFailed(request: ProtocolHandshakeOperation): Boolean {
        if (!isActive() || operation !== request) return false
        close(ProtocolHandshakeFailure.LocalOperationFailed)
        return true
    }

    /** Also invalidates Ready: completion cannot survive cancellation of the owning connection. */
    fun cancel() {
        if (current !is ProtocolHandshakeState.Closed) close(ProtocolHandshakeFailure.Cancelled)
    }

    private fun receiveHello(participant: ProtocolHandshakeParticipant): Boolean {
        if (current != ProtocolHandshakeState.AwaitingHello) return close(ProtocolHandshakeFailure.UnexpectedMessage)
        if (participant.identity != authenticatedPeerIdentity) return close(ProtocolHandshakeFailure.IdentityMismatch)
        val peer = snapshot(participant)
        val compatible = when (val result = ProtocolNegotiation.negotiate(local.capabilities, peer.capabilities)) {
            is ProtocolNegotiationResult.Incompatible -> return close(ProtocolHandshakeFailure.Incompatible(result.reason))
            is ProtocolNegotiationResult.Compatible -> result
        }
        remote = peer
        negotiation = compatible
        comparison = ProtocolHandshakeComparison(ProtocolHandshakeTranscript.bytes(local, peer))
        updateProgress()
        return true
    }

    private fun receiveApproval(approval: ProtocolHandshakeApproval): Boolean {
        val peer = remote ?: return close(ProtocolHandshakeFailure.UnexpectedMessage)
        if (remoteApproved) return close(ProtocolHandshakeFailure.UnexpectedMessage)
        verifying = true
        val result = try {
            ProtocolHandshakeVerification.verifyRemoteApproval(
                local, peer, authenticatedPeerIdentity, approval, verifyRemoteSignature,
            )
        } catch (failure: Throwable) {
            close(ProtocolHandshakeFailure.LocalOperationFailed)
            throw failure
        } finally {
            verifying = false
        }
        // A verifier callback may cancel the connection or finish after the monotonic deadline.
        if (!isActive()) return false
        when (result) {
            is ProtocolHandshakeVerificationResult.Verified -> remoteApproved = true
            is ProtocolHandshakeVerificationResult.Incompatible -> return close(ProtocolHandshakeFailure.Incompatible(result.reason))
            ProtocolHandshakeVerificationResult.IdentityMismatch -> return close(ProtocolHandshakeFailure.IdentityMismatch)
            ProtocolHandshakeVerificationResult.AddressMismatch -> return close(ProtocolHandshakeFailure.AddressMismatch)
            ProtocolHandshakeVerificationResult.InvalidSignature -> return close(ProtocolHandshakeFailure.InvalidSignature)
        }
        updateProgress()
        return true
    }

    private fun updateProgress() {
        current = when {
            localApprovalSent && remoteApproved -> ProtocolHandshakeState.Ready(checkNotNull(negotiation))
            localApprovalSent -> ProtocolHandshakeState.AwaitingRemoteApproval
            operation is ProtocolHandshakeOperation.Sign -> ProtocolHandshakeState.SigningApproval(remoteApproved)
            operation is ProtocolHandshakeOperation.Send -> ProtocolHandshakeState.SendingApproval(remoteApproved)
            else -> ProtocolHandshakeState.AwaitingConfirmation(remoteApproved)
        }
    }

    private fun isActive(): Boolean {
        if (current is ProtocolHandshakeState.Closed) return false
        val now = try {
            nowMillis()
        } catch (failure: Throwable) {
            close(ProtocolHandshakeFailure.LocalOperationFailed)
            throw failure
        }
        if (current is ProtocolHandshakeState.Closed) return false
        if (now < lastObservedMillis) return close(ProtocolHandshakeFailure.ClockMovedBackwards)
        lastObservedMillis = now
        // Subtraction can overflow only for an interval larger than Long.MAX_VALUE, which expires.
        val elapsed = now - selectedAtMillis
        if (elapsed < 0 || elapsed >= TIMEOUT_MILLIS) return close(ProtocolHandshakeFailure.Expired)
        return true
    }

    private fun close(reason: ProtocolHandshakeFailure): Boolean {
        if (current !is ProtocolHandshakeState.Closed) current = ProtocolHandshakeState.Closed(reason)
        operation = null
        comparison = null
        remote = null
        negotiation = null
        return false
    }

    private fun snapshot(participant: ProtocolHandshakeParticipant) = ProtocolHandshakeParticipant(
        participant.identity,
        participant.nonce,
        participant.capabilities,
    )

    companion object {
        const val TIMEOUT_MILLIS = 120_000L
    }
}
