package lantern.ui

import lantern.protocol.GroupAdmissionConfirmationFailure
import lantern.protocol.GroupAdmissionConfirmationFrameDecoder
import lantern.protocol.GroupAdmissionConfirmationOperation
import lantern.protocol.GroupAdmissionConfirmationState
import lantern.protocol.GroupRootAdoptionAttempt
import lantern.protocol.GroupRootAdoptionFailure
import lantern.protocol.GroupRootAdoptionState

enum class IosGroupRootFailure {
    NONE, IDENTITY_CHANGED, ALREADY_IN_GROUP, STORAGE_FAILED,
    INVALID_PROOF, INVALID_REMOTE_CONFIRMATION, IDENTITY_MISMATCH, UNEXPECTED_CONFIRMATION,
    LOCAL_OPERATION_FAILED, ADAPTER, CANCELLED, BLOCKED, LEFT_GROUP, TRANSPORT,
    EXPIRED, CLOCK_MOVED_BACKWARDS, INVALID_FRAME,
}

/** CONFIRMED remains revocable: no root, trust or application authorization is persisted. */
data class IosGroupRootSnapshot(
    val phase: IosGroupAdmissionPhase,
    val failure: IosGroupRootFailure,
    val remoteConfirmed: Boolean,
)

class IosGroupRootSign internal constructor(internal val request: GroupAdmissionConfirmationOperation.Sign) {
    val bytes: ByteArray get() = request.bytes
}

class IosGroupRootWrite internal constructor(
    bytes: ByteArray,
    internal val request: GroupAdmissionConfirmationOperation.Send,
) {
    private val content = bytes.copyOf()
    val bytes: ByteArray get() = content.copyOf()
}

/**
 * Serial callback boundary for the selected TLS member, not an NWConnection owner.
 * The native owner binds OS crypto/offers to that connection, schedules the ORIGINAL deadline,
 * closes transport on CLOSED and keeps persistence alive until all pending callbacks finish.
 * All calls, identity/group changes and lifecycle events must use its same non-UI serial queue.
 * SQLite preflight is synchronous; this facade neither closes the driver nor exposes commit.
 */
class IosGroupRootAdoption private constructor(private val attempt: GroupRootAdoptionAttempt) {
    private val decoder = GroupAdmissionConfirmationFrameDecoder()
    private var prepared = false
    private var terminal: IosGroupRootSnapshot? = null
    private var signing: IosGroupRootSign? = null
    private var writing: IosGroupRootWrite? = null

    val maximumChunkBytes: Int get() = GroupAdmissionConfirmationFrameDecoder.MAX_CHUNK_BYTES

    @Throws(Exception::class)
    fun snapshot(): IosGroupRootSnapshot = guarded { observe() }

    @Throws(Exception::class)
    fun remainingMillis(): Long? = guarded {
        if (!active()) return@guarded null
        val remaining = attempt.remainingMillis()
        if (active()) remaining else null
    }

    @Throws(Exception::class)
    fun prepare(currentIdentityId: String, persistence: IosPersistence): Boolean = guarded {
        if (!active() || prepared) return@guarded false
        val accepted = attempt.prepare(currentIdentityId, persistence.localGroups)
        val alive = active() // A false result may have closed the core.
        prepared = accepted && alive
        prepared
    }

    @Throws(Exception::class)
    fun comparison(): IosGroupAdmissionComparison? = guarded {
        if (prepared && active()) attempt.comparison()?.let(::IosGroupAdmissionComparison) else null
    }

    @Throws(Exception::class)
    fun confirm(ticket: IosGroupAdmissionComparison): IosGroupRootSign? = guarded {
        if (!prepared || !active()) return@guarded null
        val request = attempt.confirm(ticket.ticket)
        if (!active() || request == null) return@guarded null
        IosGroupRootSign(request).also { signing = it }
    }

    @Throws(Exception::class)
    fun signed(ticket: IosGroupRootSign, signature: String): IosGroupRootWrite? = guarded {
        if (!active() || signing !== ticket) return@guarded null
        val request = attempt.signed(ticket.request, signature)
        signing = null
        if (!active() || request == null) return@guarded null
        val bytes = GroupAdmissionConfirmationFrameDecoder.encode(request)
        if (!active()) return@guarded null
        IosGroupRootWrite(bytes, request).also { writing = it }
    }

    /** Call only for successful OS contentProcessed, never merely after queueing the bytes. */
    @Throws(Exception::class)
    fun sent(ticket: IosGroupRootWrite): Boolean = guarded {
        if (!active() || writing !== ticket) return@guarded false
        writing = null
        val accepted = attempt.sent(ticket.request)
        val alive = active()
        accepted && alive
    }

    @Throws(Exception::class)
    fun signingFailed(ticket: IosGroupRootSign): Boolean = guarded {
        if (!active() || signing !== ticket) return@guarded false
        val accepted = attempt.operationFailed(ticket.request)
        observe()
        accepted
    }

    @Throws(Exception::class)
    fun writeFailed(ticket: IosGroupRootWrite): Boolean = guarded {
        if (!active() || writing !== ticket) return@guarded false
        close(IosGroupRootFailure.TRANSPORT)
        true
    }

    @Throws(Exception::class)
    fun accept(chunk: ByteArray): Boolean = guarded {
        if (!active()) return@guarded false
        check(prepared) { "Candidate root has not passed local preflight and proof verification" }
        val confirmations = try {
            decoder.accept(chunk)
        } catch (invalid: IllegalArgumentException) {
            close(IosGroupRootFailure.INVALID_FRAME)
            throw invalid
        }
        for (confirmation in confirmations) {
            val accepted = attempt.receive(confirmation.sender, confirmation.recipient, confirmation.signature)
            val alive = active()
            if (!accepted || !alive) return@guarded false
        }
        active()
    }

    @Throws(Exception::class)
    fun finish(): Unit = guarded {
        if (!active()) return@guarded
        try {
            decoder.finish()
        } catch (invalid: IllegalArgumentException) {
            close(IosGroupRootFailure.INVALID_FRAME)
            throw invalid
        } finally {
            if (terminal == null) {
                attempt.transportClosed()
                observe()
            }
        }
    }

    @Throws(Exception::class)
    fun cancel(): Unit = guarded {
        attempt.cancel()
        observe()
    }
    @Throws(Exception::class)
    fun block(): Unit = guarded {
        attempt.block()
        observe()
    }
    @Throws(Exception::class)
    fun leaveGroup(): Unit = guarded {
        attempt.leaveGroup()
        observe()
    }
    @Throws(Exception::class)
    fun transportFailed(): Unit = guarded {
        if (active()) close(IosGroupRootFailure.TRANSPORT)
    }

    private fun active() = observe().phase != IosGroupAdmissionPhase.CLOSED

    private fun observe(): IosGroupRootSnapshot {
        terminal?.let { return it }
        return when (val state = attempt.state()) {
            is GroupRootAdoptionState.Closed -> close(when (val reason = state.reason) {
                GroupRootAdoptionFailure.IdentityChanged -> IosGroupRootFailure.IDENTITY_CHANGED
                GroupRootAdoptionFailure.AlreadyInGroup -> IosGroupRootFailure.ALREADY_IN_GROUP
                GroupRootAdoptionFailure.StorageFailed -> IosGroupRootFailure.STORAGE_FAILED
                is GroupRootAdoptionFailure.Confirmation -> failure(reason.reason)
            })
            GroupRootAdoptionState.ReleasedForCommit -> error("This boundary never releases commit ownership")
            is GroupRootAdoptionState.Active -> when (val confirmation = state.confirmation) {
                GroupAdmissionConfirmationState.AwaitingProof, GroupAdmissionConfirmationState.VerifyingProof ->
                    view(IosGroupAdmissionPhase.AWAITING_START)
                is GroupAdmissionConfirmationState.AwaitingConfirmation ->
                    view(IosGroupAdmissionPhase.AWAITING_CONFIRMATION, confirmation.remoteConfirmed)
                is GroupAdmissionConfirmationState.Signing -> view(IosGroupAdmissionPhase.SIGNING, confirmation.remoteConfirmed)
                is GroupAdmissionConfirmationState.Sending -> view(IosGroupAdmissionPhase.SENDING, confirmation.remoteConfirmed)
                GroupAdmissionConfirmationState.AwaitingRemoteConfirmation -> view(IosGroupAdmissionPhase.AWAITING_REMOTE_CONFIRMATION)
                GroupAdmissionConfirmationState.Confirmed -> view(IosGroupAdmissionPhase.CONFIRMED, true)
                is GroupAdmissionConfirmationState.Closed -> error("Closed confirmation must be mapped by the root attempt")
            }
        }
    }

    private fun view(phase: IosGroupAdmissionPhase, remote: Boolean = false) =
        IosGroupRootSnapshot(phase, IosGroupRootFailure.NONE, remote)

    private fun close(reason: IosGroupRootFailure): IosGroupRootSnapshot {
        if (terminal == null) {
            terminal = IosGroupRootSnapshot(IosGroupAdmissionPhase.CLOSED, reason, false)
            attempt.cancel()
            decoder.close()
            signing = null
            writing = null
        }
        return checkNotNull(terminal)
    }

    private inline fun <T> guarded(action: () -> T): T = try {
        action()
    } catch (original: Throwable) {
        // Preserve a storage/cancellation/core failure before the generic adapter fallback.
        try { observe() } catch (secondary: Throwable) {
            if (secondary !== original) original.addSuppressed(secondary)
        }
        close(IosGroupRootFailure.ADAPTER)
        throw original
    }

    private fun failure(reason: GroupAdmissionConfirmationFailure): IosGroupRootFailure = when (reason) {
        is GroupAdmissionConfirmationFailure.InvalidProof -> IosGroupRootFailure.INVALID_PROOF
        is GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation -> IosGroupRootFailure.INVALID_REMOTE_CONFIRMATION
        GroupAdmissionConfirmationFailure.IdentityMismatch -> IosGroupRootFailure.IDENTITY_MISMATCH
        GroupAdmissionConfirmationFailure.UnexpectedConfirmation -> IosGroupRootFailure.UNEXPECTED_CONFIRMATION
        GroupAdmissionConfirmationFailure.LocalOperationFailed -> IosGroupRootFailure.LOCAL_OPERATION_FAILED
        GroupAdmissionConfirmationFailure.AdapterFailed -> IosGroupRootFailure.ADAPTER
        GroupAdmissionConfirmationFailure.Cancelled -> IosGroupRootFailure.CANCELLED
        GroupAdmissionConfirmationFailure.Blocked -> IosGroupRootFailure.BLOCKED
        GroupAdmissionConfirmationFailure.LeftGroup -> IosGroupRootFailure.LEFT_GROUP
        GroupAdmissionConfirmationFailure.TransportClosed -> IosGroupRootFailure.TRANSPORT
        GroupAdmissionConfirmationFailure.Expired -> IosGroupRootFailure.EXPIRED
        GroupAdmissionConfirmationFailure.ClockMovedBackwards -> IosGroupRootFailure.CLOCK_MOVED_BACKWARDS
    }

    companion object {
        @Throws(Exception::class)
        fun create(
            offers: IosHandshakeV1Offers,
            evidence: IosGroupAdmissionEvidence,
            authenticatedLocalIdentity: String,
            selectedPeerIdentity: String,
            authenticatedPeerIdentity: String,
            selectedAtMillis: Long,
            nowMillis: () -> Long,
            verifyAdmissionSignature: (String, ByteArray, String) -> Boolean,
            verifyRemoteSignature: (ByteArray, String) -> Boolean,
        ): IosGroupRootAdoption {
            require(offers.localIdentity == authenticatedLocalIdentity) { "Candidate root local TLS identity mismatch" }
            return IosGroupRootAdoption(GroupRootAdoptionAttempt(
                offers.offers, offers.localIdentity, selectedPeerIdentity, authenticatedPeerIdentity,
                evidence.evidence.proof, selectedAtMillis, nowMillis, verifyAdmissionSignature, verifyRemoteSignature,
            ))
        }
    }
}
