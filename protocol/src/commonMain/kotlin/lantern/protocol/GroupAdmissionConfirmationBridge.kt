package lantern.protocol

sealed interface GroupAdmissionBridgeState {
    data object AwaitingStart : GroupAdmissionBridgeState
    data class Active(val confirmation: GroupAdmissionConfirmationState) : GroupAdmissionBridgeState
    data class Closed(val reason: GroupAdmissionBridgeFailure) : GroupAdmissionBridgeState
}

sealed interface GroupAdmissionBridgeFailure {
    data class Attempt(val reason: GroupAdmissionConfirmationFailure) : GroupAdmissionBridgeFailure
    data object InvalidFrame : GroupAdmissionBridgeFailure
    data object Transport : GroupAdmissionBridgeFailure
    data object Adapter : GroupAdmissionBridgeFailure
}

/** Exact callback ticket, not a reusable permission to sign another context. */
class GroupAdmissionBridgeSign internal constructor(internal val request: GroupAdmissionConfirmationOperation.Sign) {
    val bytes: ByteArray get() = request.bytes
}

/** Encoding/queueing this buffer does not acknowledge the attempt's write. */
class GroupAdmissionBridgeWrite internal constructor(bytes: ByteArray, internal val request: GroupAdmissionConfirmationOperation.Send) {
    private val content = bytes.copyOf()
    val bytes: ByteArray get() = content.copyOf()
}

/**
 * Isolated callback boundary; no OS transport/timer/crypto implementation or trust repository.
 * The owner serializes ALL calls, binds the context and crypto callbacks to the selected TLS
 * connection, forwards lifecycle events, closes transport on Closed, and schedules the remaining
 * monotonic deadline even while idle. Fresh OS nonces/new instance required for every reconnect.
 */
class GroupAdmissionConfirmationBridge(
    context: GroupAdmissionConfirmationContext,
    localIdentity: String,
    authenticatedLocalIdentity: String,
    selectedPeerIdentity: String,
    authenticatedPeerIdentity: String,
    selectedAtMillis: Long,
    nowMillis: () -> Long,
    verifyAdmissionSignature: (String, ByteArray, String) -> Boolean,
    verifyRemoteSignature: (ByteArray, String) -> Boolean,
) {
    private val attempt: GroupAdmissionConfirmationAttempt
    private val decoder = GroupAdmissionConfirmationFrameDecoder()
    private var phase: GroupAdmissionBridgeState = GroupAdmissionBridgeState.AwaitingStart
    private var failure: GroupAdmissionBridgeFailure? = null
    private var sign: GroupAdmissionBridgeSign? = null
    private var write: GroupAdmissionBridgeWrite? = null

    init {
        require(localIdentity == authenticatedLocalIdentity) { "Local admission TLS identity mismatch" }
        attempt = GroupAdmissionConfirmationAttempt(context, localIdentity, selectedPeerIdentity,
            authenticatedPeerIdentity, selectedAtMillis, nowMillis, verifyAdmissionSignature, verifyRemoteSignature)
    }

    @Throws(Exception::class)
    fun state(): GroupAdmissionBridgeState = guarded { snapshot() }

    @Throws(Exception::class)
    fun remainingMillis(): Long? = guarded {
        if (snapshot() is GroupAdmissionBridgeState.Closed) return@guarded null
        val remaining = attempt.remainingMillis
        if (snapshot() is GroupAdmissionBridgeState.Closed) null else remaining
    }

    /** Verify the full frozen proof before accepting network bytes or exposing a comparison. */
    @Throws(Exception::class)
    fun prepare(): Boolean = guarded {
        if (snapshot() != GroupAdmissionBridgeState.AwaitingStart) return@guarded false
        val prepared = attempt.prepare()
        if (snapshot() is GroupAdmissionBridgeState.Closed || !prepared) return@guarded false
        phase = GroupAdmissionBridgeState.Active(attempt.state)
        snapshot() !is GroupAdmissionBridgeState.Closed
    }

    @Throws(Exception::class)
    fun comparison(): GroupAdmissionComparison? = guarded {
        if (snapshot() is GroupAdmissionBridgeState.Active) attempt.comparison() else null
    }

    @Throws(Exception::class)
    fun confirm(ticket: GroupAdmissionComparison): GroupAdmissionBridgeSign? = guarded {
        if (snapshot() !is GroupAdmissionBridgeState.Active) return@guarded null
        val request = attempt.confirm(ticket) ?: return@guarded null
        if (snapshot() is GroupAdmissionBridgeState.Closed) return@guarded null
        GroupAdmissionBridgeSign(request).also { sign = it }
    }

    @Throws(Exception::class)
    fun signed(ticket: GroupAdmissionBridgeSign, signature: String): GroupAdmissionBridgeWrite? = guarded {
        if (snapshot() is GroupAdmissionBridgeState.Closed || sign !== ticket) return@guarded null
        val request = attempt.signed(ticket.request, signature)
        sign = null
        if (snapshot() is GroupAdmissionBridgeState.Closed || request == null) return@guarded null
        val bytes = GroupAdmissionConfirmationFrameDecoder.encode(request)
        if (snapshot() is GroupAdmissionBridgeState.Closed) return@guarded null
        GroupAdmissionBridgeWrite(bytes, request).also { write = it }
    }

    /** Only the successful OS transport completion callback may acknowledge this exact ticket. */
    @Throws(Exception::class)
    fun sent(ticket: GroupAdmissionBridgeWrite): Boolean = guarded {
        if (snapshot() is GroupAdmissionBridgeState.Closed || write !== ticket) return@guarded false
        write = null
        val accepted = attempt.sent(ticket.request)
        val current = snapshot()
        accepted && current !is GroupAdmissionBridgeState.Closed
    }

    @Throws(Exception::class)
    fun signingFailed(ticket: GroupAdmissionBridgeSign): Boolean = guarded {
        if (snapshot() is GroupAdmissionBridgeState.Closed || sign !== ticket) return@guarded false
        val accepted = attempt.operationFailed(ticket.request)
        snapshot()
        accepted
    }

    @Throws(Exception::class)
    fun writeFailed(ticket: GroupAdmissionBridgeWrite): Boolean = guarded {
        if (snapshot() is GroupAdmissionBridgeState.Closed || write !== ticket) return@guarded false
        terminate(GroupAdmissionBridgeFailure.Transport)
        true
    }

    @Throws(Exception::class)
    fun accept(chunk: ByteArray): Boolean = guarded {
        if (snapshot() is GroupAdmissionBridgeState.Closed) return@guarded false
        check(phase is GroupAdmissionBridgeState.Active) { "Admission proof has not been verified" }
        val confirmations = try {
            decoder.accept(chunk)
        } catch (invalid: IllegalArgumentException) {
            terminate(GroupAdmissionBridgeFailure.InvalidFrame)
            throw invalid
        }
        for (confirmation in confirmations) {
            if (!attempt.receive(confirmation.sender, confirmation.recipient, confirmation.signature)) {
                snapshot()
                return@guarded false
            }
        }
        snapshot() !is GroupAdmissionBridgeState.Closed
    }

    /** Clean EOF also revokes Confirmed; incomplete framing is closed and rethrown. */
    @Throws(Exception::class)
    fun finish(): Unit = guarded {
        if (snapshot() is GroupAdmissionBridgeState.Closed) return@guarded
        try {
            decoder.finish()
        } catch (invalid: IllegalArgumentException) {
            terminate(GroupAdmissionBridgeFailure.InvalidFrame)
            throw invalid
        } finally {
            if (failure == null) {
                attempt.transportClosed()
                snapshot()
            }
        }
    }

    fun cancel() {
        attempt.cancel()
        snapshot()
    }
    fun block() {
        attempt.block()
        snapshot()
    }
    fun leaveGroup() {
        attempt.leaveGroup()
        snapshot()
    }
    fun transportFailed() { terminate(GroupAdmissionBridgeFailure.Transport) }

    private fun snapshot(): GroupAdmissionBridgeState {
        failure?.let { return GroupAdmissionBridgeState.Closed(it) }
        val state = attempt.state
        if (state is GroupAdmissionConfirmationState.Closed) {
            terminate(GroupAdmissionBridgeFailure.Attempt(state.reason))
            return GroupAdmissionBridgeState.Closed(checkNotNull(failure))
        }
        return if (phase is GroupAdmissionBridgeState.Active) GroupAdmissionBridgeState.Active(state) else phase
    }

    private fun terminate(reason: GroupAdmissionBridgeFailure) {
        if (failure == null) failure = reason
        attempt.cancel()
        decoder.close()
        sign = null
        write = null
    }

    private inline fun <T> guarded(block: () -> T): T = try {
        block()
    } catch (failure: Throwable) {
        terminate(GroupAdmissionBridgeFailure.Adapter)
        throw failure
    }
}
