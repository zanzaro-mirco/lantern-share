package lantern.protocol

sealed interface GroupAdmissionConfirmationState {
    data object AwaitingProof : GroupAdmissionConfirmationState
    data object VerifyingProof : GroupAdmissionConfirmationState
    data class AwaitingConfirmation(val remoteConfirmed: Boolean) : GroupAdmissionConfirmationState
    data class Signing(val remoteConfirmed: Boolean) : GroupAdmissionConfirmationState
    data class Sending(val remoteConfirmed: Boolean) : GroupAdmissionConfirmationState
    data object AwaitingRemoteConfirmation : GroupAdmissionConfirmationState
    /** Proof, remote signature and local write verified; revocable, NOT durable trust or commit. */
    data object Confirmed : GroupAdmissionConfirmationState
    data class Closed(val reason: GroupAdmissionConfirmationFailure) : GroupAdmissionConfirmationState
}

sealed interface GroupAdmissionConfirmationFailure {
    data class InvalidProof(val result: GroupAdmissionChainResult) : GroupAdmissionConfirmationFailure {
        init { require(result != GroupAdmissionChainResult.VerifiedChain) }
    }
    data class InvalidRemoteConfirmation(val result: GroupAdmissionConfirmationResult) : GroupAdmissionConfirmationFailure {
        init { require(result != GroupAdmissionConfirmationResult.VerifiedRemoteConfirmation) }
    }
    data object IdentityMismatch : GroupAdmissionConfirmationFailure
    data object UnexpectedConfirmation : GroupAdmissionConfirmationFailure
    data object LocalOperationFailed : GroupAdmissionConfirmationFailure
    data object AdapterFailed : GroupAdmissionConfirmationFailure
    data object Cancelled : GroupAdmissionConfirmationFailure
    data object Blocked : GroupAdmissionConfirmationFailure
    data object LeftGroup : GroupAdmissionConfirmationFailure
    data object TransportClosed : GroupAdmissionConfirmationFailure
    data object Expired : GroupAdmissionConfirmationFailure
    data object ClockMovedBackwards : GroupAdmissionConfirmationFailure
}

/** The UI must retain this exact attempt-owned ticket, not reconstruct it from the displayed hash. */
class GroupAdmissionComparison internal constructor(bytes: ByteArray) {
    private val content = bytes.copyOf()
    val bytes: ByteArray get() = content.copyOf()
}

sealed interface GroupAdmissionConfirmationOperation {
    class Sign internal constructor(bytes: ByteArray) : GroupAdmissionConfirmationOperation {
        private val content = bytes.copyOf()
        val bytes: ByteArray get() = content.copyOf()
    }

    /** Data for a future transport adapter; NOT a bootstrap APPROVE or an active wire frame. */
    class Send internal constructor(val sender: String, val recipient: String, val signature: String) :
        GroupAdmissionConfirmationOperation
}

/**
 * One isolated group-confirmation attempt. No socket, repository or OS crypto implementation.
 * The connection owner serializes ALL calls and forwards block/leave/EOF/cancel events on the
 * same queue, schedules the remaining deadline even while idle, and uses a new instance per
 * reconnect with fresh OS nonces. Context/offers and local/selected/peer pins must belong to
 * that very TLS connection. Root adoption and durable commit remain outside this component.
 */
class GroupAdmissionConfirmationAttempt(
    private val context: GroupAdmissionConfirmationContext,
    private val localIdentity: String,
    selectedPeerIdentity: String,
    private val authenticatedPeerIdentity: String,
    private val selectedAtMillis: Long,
    private val nowMillis: () -> Long,
    private val verifyAdmissionSignature: (String, ByteArray, String) -> Boolean,
    private val verifyRemoteSignature: (ByteArray, String) -> Boolean,
) {
    private var current: GroupAdmissionConfirmationState = GroupAdmissionConfirmationState.AwaitingProof
    private var comparison: GroupAdmissionComparison? = null
    private var operation: GroupAdmissionConfirmationOperation? = null
    private var remoteConfirmed = false
    private var localSent = false
    private var verifyingRemote = false
    private var lastObservedMillis = selectedAtMillis
    private val peerIdentity: String

    init {
        require(localIdentity == context.issuerIdentity || localIdentity == context.memberIdentity) {
            "Local TLS identity must participate in the admission"
        }
        require(Wire.isFingerprint(selectedPeerIdentity) && selectedPeerIdentity != localIdentity) {
            "Invalid selected admission peer"
        }
        peerIdentity = if (localIdentity == context.issuerIdentity) context.memberIdentity else context.issuerIdentity
        if (selectedPeerIdentity != peerIdentity || authenticatedPeerIdentity != peerIdentity) {
            close(GroupAdmissionConfirmationFailure.IdentityMismatch)
        }
    }

    val state: GroupAdmissionConfirmationState get() {
        isActive()
        return current
    }

    val remainingMillis: Long? get() =
        if (isActive()) TIMEOUT_MILLIS - (lastObservedMillis - selectedAtMillis) else null

    /** Resolves every issuer certificate against its expected pin before exposing the UI ticket. */
    fun prepare(): Boolean {
        if (!isActive() || current != GroupAdmissionConfirmationState.AwaitingProof) return false
        current = GroupAdmissionConfirmationState.VerifyingProof
        val result = try {
            GroupAdmissionChainVerification.verify(context.admissionProof, context.anchor, context.memberIdentity) { issuer, bytes, signature ->
                isActive() && verifyAdmissionSignature(issuer, bytes, signature)
            }
        } catch (failure: Throwable) {
            close(GroupAdmissionConfirmationFailure.AdapterFailed)
            throw failure
        }
        if (!isActive()) return false
        if (result != GroupAdmissionChainResult.VerifiedChain) {
            return close(GroupAdmissionConfirmationFailure.InvalidProof(result))
        }
        comparison = GroupAdmissionComparison(context.comparisonBytes())
        updateProgress()
        return true
    }

    fun comparison(): GroupAdmissionComparison? = if (isActive()) comparison else null

    /** Explicit user confirmation of this exact context; stale or foreign tickets do nothing. */
    fun confirm(ticket: GroupAdmissionComparison): GroupAdmissionConfirmationOperation.Sign? {
        if (!isActive() || comparison !== ticket || verifyingRemote ||
            current !is GroupAdmissionConfirmationState.AwaitingConfirmation
        ) return null
        return GroupAdmissionConfirmationOperation.Sign(context.approvalBytes(localIdentity)).also {
            operation = it
            updateProgress()
        }
    }

    /** Callback from the trusted local OS signer, signing exactly request.bytes with the TLS key. */
    fun signed(request: GroupAdmissionConfirmationOperation.Sign, signature: String): GroupAdmissionConfirmationOperation.Send? {
        if (!isActive() || operation !== request || current !is GroupAdmissionConfirmationState.Signing) return null
        if (!ProtocolSignatureEncoding.isValid(signature)) {
            close(GroupAdmissionConfirmationFailure.LocalOperationFailed)
            return null
        }
        return GroupAdmissionConfirmationOperation.Send(localIdentity, peerIdentity, signature).also {
            operation = it
            updateProgress()
        }
    }

    /** Only an actual successful transport write callback, never queueing, advances local progress. */
    fun sent(request: GroupAdmissionConfirmationOperation.Send): Boolean {
        if (!isActive() || operation !== request || current !is GroupAdmissionConfirmationState.Sending) return false
        operation = null
        localSent = true
        updateProgress()
        return true
    }

    fun operationFailed(request: GroupAdmissionConfirmationOperation): Boolean {
        if (!isActive() || operation !== request) return false
        close(GroupAdmissionConfirmationFailure.LocalOperationFailed)
        return true
    }

    fun receive(sender: String, recipient: String, signature: String): Boolean {
        if (!isActive()) return false
        if (comparison == null || remoteConfirmed || verifyingRemote) {
            return close(GroupAdmissionConfirmationFailure.UnexpectedConfirmation)
        }
        verifyingRemote = true
        val result = try {
            GroupAdmissionConfirmationVerification.verifyRemote(
                context, localIdentity, authenticatedPeerIdentity, sender, recipient, signature, verifyRemoteSignature,
            )
        } catch (failure: Throwable) {
            close(GroupAdmissionConfirmationFailure.AdapterFailed)
            throw failure
        } finally {
            verifyingRemote = false
        }
        // A callback may cancel/block/leave/close the attempt or complete after the deadline.
        if (!isActive()) return false
        if (result != GroupAdmissionConfirmationResult.VerifiedRemoteConfirmation) {
            return close(GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation(result))
        }
        remoteConfirmed = true
        updateProgress()
        return true
    }

    fun cancel() { close(GroupAdmissionConfirmationFailure.Cancelled) }
    fun block() { close(GroupAdmissionConfirmationFailure.Blocked) }
    fun leaveGroup() { close(GroupAdmissionConfirmationFailure.LeftGroup) }
    fun transportClosed() { close(GroupAdmissionConfirmationFailure.TransportClosed) }

    private fun updateProgress() {
        current = when {
            localSent && remoteConfirmed -> GroupAdmissionConfirmationState.Confirmed
            localSent -> GroupAdmissionConfirmationState.AwaitingRemoteConfirmation
            operation is GroupAdmissionConfirmationOperation.Sign -> GroupAdmissionConfirmationState.Signing(remoteConfirmed)
            operation is GroupAdmissionConfirmationOperation.Send -> GroupAdmissionConfirmationState.Sending(remoteConfirmed)
            else -> GroupAdmissionConfirmationState.AwaitingConfirmation(remoteConfirmed)
        }
    }

    private fun isActive(): Boolean {
        if (current is GroupAdmissionConfirmationState.Closed) return false
        val now = try {
            nowMillis()
        } catch (failure: Throwable) {
            close(GroupAdmissionConfirmationFailure.AdapterFailed)
            throw failure
        }
        if (current is GroupAdmissionConfirmationState.Closed) return false
        if (now < lastObservedMillis) return close(GroupAdmissionConfirmationFailure.ClockMovedBackwards)
        lastObservedMillis = now
        val elapsed = now - selectedAtMillis
        if (elapsed < 0 || elapsed >= TIMEOUT_MILLIS) return close(GroupAdmissionConfirmationFailure.Expired)
        return true
    }

    private fun close(reason: GroupAdmissionConfirmationFailure): Boolean {
        if (current !is GroupAdmissionConfirmationState.Closed) current = GroupAdmissionConfirmationState.Closed(reason)
        comparison = null
        operation = null
        return false
    }

    companion object {
        const val TIMEOUT_MILLIS = ProtocolHandshakeAttempt.TIMEOUT_MILLIS
    }
}
