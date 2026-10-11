package lantern.protocol

sealed interface ProtocolHandshakeBridgeState {
    data object AwaitingStart : ProtocolHandshakeBridgeState
    data object SendingHello : ProtocolHandshakeBridgeState
    /** Core released, not socket ownership, successful adoption, membership or trust. */
    data object ReleasedToGroup : ProtocolHandshakeBridgeState
    data class Active(val handshake: ProtocolHandshakeState) : ProtocolHandshakeBridgeState
    data class Closed(val reason: ProtocolHandshakeBridgeFailure) : ProtocolHandshakeBridgeState
}

sealed interface ProtocolHandshakeBridgeFailure {
    data class Protocol(val reason: ProtocolHandshakeFailure) : ProtocolHandshakeBridgeFailure
    data object InvalidFrame : ProtocolHandshakeBridgeFailure
    data object Transport : ProtocolHandshakeBridgeFailure
    data object Adapter : ProtocolHandshakeBridgeFailure
}

/** Opaque callback tickets; views are copied and callbacks must retain the exact object. */
class ProtocolHandshakeBridgeWrite internal constructor(bytes: ByteArray, internal val approval: ProtocolHandshakeOperation.Send?) {
    private val content = bytes.copyOf()
    val bytes: ByteArray get() = content.copyOf()
}

class ProtocolHandshakeBridgeSign internal constructor(internal val request: ProtocolHandshakeOperation.Sign) {
    val bytes: ByteArray get() = request.bytes
}

/**
 * Callback-transport boundary, isolated from active v0 services. No socket, OS crypto or trust store.
 * The owner serializes ALL calls, closes transport on Closed, and schedules the remaining deadline
 * even while idle. Supply freshly generated OS nonces and pins from the selected mutual TLS socket.
 * A write is successful only in its transport completion callback, not when queued.
 */
class ProtocolHandshakeBridge(
    local: ProtocolHandshakeParticipant,
    authenticatedLocalIdentity: String,
    selectedPeerIdentity: String,
    authenticatedPeerIdentity: String,
    selectedAtMillis: Long,
    nowMillis: () -> Long,
    verifyRemoteSignature: (ByteArray, String) -> Boolean,
) {
    private val attempt: ProtocolHandshakeAttempt
    private val decoder = ProtocolHandshakeFrameDecoder()
    private var phase: ProtocolHandshakeBridgeState = ProtocolHandshakeBridgeState.AwaitingStart
    private var failure: ProtocolHandshakeBridgeFailure? = null
    private var write: ProtocolHandshakeBridgeWrite? = null
    private var sign: ProtocolHandshakeBridgeSign? = null

    init {
        require(local.identity == authenticatedLocalIdentity) { "Local TLS identity mismatch" }
        attempt = ProtocolHandshakeAttempt(local, selectedPeerIdentity, authenticatedPeerIdentity, selectedAtMillis, nowMillis, verifyRemoteSignature)
    }

    fun state(): ProtocolHandshakeBridgeState = guarded { snapshot() }

    fun remainingMillis(): Long? = guarded {
        if (phase == ProtocolHandshakeBridgeState.ReleasedToGroup) return@guarded null
        if (snapshot() is ProtocolHandshakeBridgeState.Closed) return@guarded null
        val remaining = attempt.remainingMillis
        if (snapshot() is ProtocolHandshakeBridgeState.Closed) null else remaining
    }

    /** No read before HELLO write completion or after invalidation; observes the original deadline. */
    fun nextReadBytes(): Int? = guarded {
        if (snapshot() !is ProtocolHandshakeBridgeState.Active) null else decoder.nextReadBytes
    }

    /** Snapshot only. The native owner must still exclude outstanding reads/writes/signatures. */
    fun offersForGroupAdmission(): ProtocolHandshakeOffers? = guarded {
        if (snapshot() !is ProtocolHandshakeBridgeState.Active || write != null || sign != null ||
            !decoder.isAtFrameBoundary
        ) null else attempt.offersForGroupAdmission()
    }

    /**
     * One-shot core release on the serial owner's queue, before either APPROVE.
     * The OS owner must atomically transfer its transport/timer/cleanup with this operation.
     * Returned offers preserve the final monotonic watermark, never authorize received roots.
     */
    fun releaseForGroupAdmission(): ProtocolHandshakeOffers? = guarded {
        val offers = offersForGroupAdmission() ?: return@guarded null
        phase = ProtocolHandshakeBridgeState.ReleasedToGroup
        attempt.cancel()
        release()
        offers
    }

    fun start(): ProtocolHandshakeBridgeWrite? = guarded {
        if (snapshot() != ProtocolHandshakeBridgeState.AwaitingStart) return@guarded null
        val hello = attempt.localHello ?: return@guarded null
        ProtocolHandshakeBridgeWrite(ProtocolHandshakeFrameDecoder.encode(hello), null).also {
            write = it
            phase = ProtocolHandshakeBridgeState.SendingHello
        }
    }

    fun sent(ticket: ProtocolHandshakeBridgeWrite): Boolean = guarded {
        if (snapshot() is ProtocolHandshakeBridgeState.Closed || write !== ticket) return@guarded false
        write = null
        if (ticket.approval == null) {
            phase = ProtocolHandshakeBridgeState.Active(attempt.state)
            snapshot() !is ProtocolHandshakeBridgeState.Closed
        } else {
            val accepted = attempt.sent(ticket.approval)
            val current = snapshot()
            accepted && current !is ProtocolHandshakeBridgeState.Closed
        }
    }

    /** No input may be routed before the initial HELLO completion callback. */
    fun accept(chunk: ByteArray): Boolean = guarded {
        if (phase == ProtocolHandshakeBridgeState.ReleasedToGroup) return@guarded false
        if (snapshot() is ProtocolHandshakeBridgeState.Closed) return@guarded false
        check(phase is ProtocolHandshakeBridgeState.Active) { "V1 bootstrap HELLO has not been sent" }
        val frames = try {
            decoder.accept(chunk)
        } catch (error: IllegalArgumentException) {
            terminate(ProtocolHandshakeBridgeFailure.InvalidFrame)
            throw error
        }
        for (frame in frames) {
            if (!attempt.receive(frame)) {
                snapshot()
                return@guarded false
            }
        }
        snapshot() !is ProtocolHandshakeBridgeState.Closed
    }

    fun comparison(): ProtocolHandshakeComparison? = guarded {
        if (snapshot() is ProtocolHandshakeBridgeState.Active) attempt.comparison() else null
    }

    /** Only the explicit UI confirmation of the retained comparison may request an OS signature. */
    fun confirm(ticket: ProtocolHandshakeComparison): ProtocolHandshakeBridgeSign? = guarded {
        if (snapshot() !is ProtocolHandshakeBridgeState.Active) return@guarded null
        attempt.confirm(ticket)?.let { ProtocolHandshakeBridgeSign(it).also { request -> sign = request } }
    }

    fun signed(ticket: ProtocolHandshakeBridgeSign, signature: String): ProtocolHandshakeBridgeWrite? = guarded {
        if (snapshot() is ProtocolHandshakeBridgeState.Closed || sign !== ticket) return@guarded null
        val approval = attempt.signed(ticket.request, signature)
        sign = null
        if (snapshot() is ProtocolHandshakeBridgeState.Closed) return@guarded null
        approval?.let {
            ProtocolHandshakeBridgeWrite(ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Approve(it.approval)), it)
                .also { sending -> write = sending }
        }
    }

    fun writeFailed(ticket: ProtocolHandshakeBridgeWrite): Boolean = guarded {
        if (snapshot() is ProtocolHandshakeBridgeState.Closed || write !== ticket) return@guarded false
        terminate(ProtocolHandshakeBridgeFailure.Transport)
        true
    }

    fun signingFailed(ticket: ProtocolHandshakeBridgeSign): Boolean = guarded {
        if (snapshot() is ProtocolHandshakeBridgeState.Closed || sign !== ticket) return@guarded false
        val accepted = attempt.operationFailed(ticket.request)
        snapshot()
        accepted
    }

    /** EOF always invalidates bootstrap progress, including Ready. Truncation is also rethrown. */
    fun finish(): Unit = guarded {
        if (phase == ProtocolHandshakeBridgeState.ReleasedToGroup) return@guarded
        if (snapshot() is ProtocolHandshakeBridgeState.Closed) return@guarded
        try {
            decoder.finish()
        } finally {
            terminate(ProtocolHandshakeBridgeFailure.Transport)
        }
    }

    fun cancel() {
        if (phase == ProtocolHandshakeBridgeState.ReleasedToGroup) return
        attempt.cancel()
        if (failure == null) failure = ProtocolHandshakeBridgeFailure.Protocol(ProtocolHandshakeFailure.Cancelled)
        release()
    }

    private fun snapshot(): ProtocolHandshakeBridgeState {
        // Do not consult the invalidated attempt/clock or resurrect cleanup after core release.
        if (phase == ProtocolHandshakeBridgeState.ReleasedToGroup) return phase
        failure?.let { return ProtocolHandshakeBridgeState.Closed(it) }
        val state = attempt.state
        if (state is ProtocolHandshakeState.Closed) {
            terminate(ProtocolHandshakeBridgeFailure.Protocol(state.reason))
            return ProtocolHandshakeBridgeState.Closed(checkNotNull(failure))
        }
        return if (phase is ProtocolHandshakeBridgeState.Active) ProtocolHandshakeBridgeState.Active(state) else phase
    }

    private fun terminate(reason: ProtocolHandshakeBridgeFailure) {
        if (phase == ProtocolHandshakeBridgeState.ReleasedToGroup) return
        if (failure == null) failure = reason
        attempt.cancel()
        release()
    }

    private fun release() {
        decoder.close()
        sign = null
        write = null
    }

    private inline fun <T> guarded(block: () -> T): T = try {
        block()
    } catch (error: Throwable) {
        terminate(ProtocolHandshakeBridgeFailure.Adapter)
        throw error
    }
}
