package lantern.ui

import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupAdmissionBridgeFailure
import lantern.protocol.GroupAdmissionBridgeSign
import lantern.protocol.GroupAdmissionBridgeState
import lantern.protocol.GroupAdmissionBridgeWrite
import lantern.protocol.GroupAdmissionComparison
import lantern.protocol.GroupAdmissionConfirmationBridge
import lantern.protocol.GroupAdmissionConfirmationContext
import lantern.protocol.GroupAdmissionConfirmationFailure
import lantern.protocol.GroupAdmissionConfirmationFrameDecoder
import lantern.protocol.GroupAdmissionConfirmationState

enum class IosGroupAdmissionRole { ISSUER, MEMBER }

/** Frozen Kotlin context, not a verified proof, socket grant or durable membership. */
class IosGroupAdmissionContext private constructor(
    internal val context: GroupAdmissionConfirmationContext,
    internal val offers: IosHandshakeV1Offers,
) {
    val issuerIdentity: String get() = context.issuerIdentity
    val memberIdentity: String get() = context.memberIdentity

    companion object {
        @Throws(Exception::class)
        fun create(
            offers: IosHandshakeV1Offers,
            expectedGroup: String,
            expectedFounder: String,
            evidence: IosGroupAdmissionEvidence,
            role: IosGroupAdmissionRole,
        ): IosGroupAdmissionContext {
            val context = GroupAdmissionConfirmationContext.fromBootstrapOffers(
                offers.offers, GroupTrustAnchor(expectedGroup, expectedFounder), evidence.evidence.proof,
            )
            require((context.issuerIdentity == offers.localIdentity) == (role == IosGroupAdmissionRole.ISSUER)) {
                "Group evidence role mismatch"
            }
            return IosGroupAdmissionContext(context, offers)
        }
    }
}

enum class IosGroupAdmissionPhase {
    AWAITING_START, AWAITING_CONFIRMATION, SIGNING, SENDING, AWAITING_REMOTE_CONFIRMATION, CONFIRMED, CLOSED,
    COMMITTED, COMMIT_OUTCOME_UNKNOWN,
}

enum class IosGroupAdmissionFailure {
    NONE, INVALID_PROOF, INVALID_REMOTE_CONFIRMATION, IDENTITY_MISMATCH, UNEXPECTED_CONFIRMATION,
    LOCAL_OPERATION_FAILED, ADAPTER, CANCELLED, BLOCKED, LEFT_GROUP, TRANSPORT, EXPIRED,
    CLOCK_MOVED_BACKWARDS, INVALID_FRAME,
}

/** CONFIRMED is revocable progress; it does not persist trust or authorize application traffic. */
data class IosGroupAdmissionSnapshot(
    val phase: IosGroupAdmissionPhase,
    val failure: IosGroupAdmissionFailure,
    val remoteConfirmed: Boolean,
)

class IosGroupAdmissionComparison internal constructor(internal val ticket: GroupAdmissionComparison) {
    val bytes: ByteArray get() = ticket.bytes
}

class IosGroupAdmissionSign internal constructor(internal val ticket: GroupAdmissionBridgeSign) {
    val bytes: ByteArray get() = ticket.bytes
}

class IosGroupAdmissionWrite internal constructor(internal val ticket: GroupAdmissionBridgeWrite) {
    val bytes: ByteArray get() = ticket.bytes
}

/** Serial-owner facade. Swift supplies only pinned OS crypto, I/O callbacks and lifecycle. */
class IosGroupAdmissionConfirmation private constructor(private val bridge: GroupAdmissionConfirmationBridge) {
    val maximumChunkBytes: Int get() = GroupAdmissionConfirmationFrameDecoder.MAX_CHUNK_BYTES

    @Throws(Exception::class)
    fun snapshot(): IosGroupAdmissionSnapshot = when (val state = bridge.state()) {
        GroupAdmissionBridgeState.AwaitingStart -> view(IosGroupAdmissionPhase.AWAITING_START)
        is GroupAdmissionBridgeState.Closed -> IosGroupAdmissionSnapshot(
            IosGroupAdmissionPhase.CLOSED, failure(state.reason), false,
        )
        is GroupAdmissionBridgeState.Active -> when (val confirmation = state.confirmation) {
            is GroupAdmissionConfirmationState.AwaitingConfirmation -> view(
                IosGroupAdmissionPhase.AWAITING_CONFIRMATION, confirmation.remoteConfirmed,
            )
            is GroupAdmissionConfirmationState.Signing -> view(IosGroupAdmissionPhase.SIGNING, confirmation.remoteConfirmed)
            is GroupAdmissionConfirmationState.Sending -> view(IosGroupAdmissionPhase.SENDING, confirmation.remoteConfirmed)
            GroupAdmissionConfirmationState.AwaitingRemoteConfirmation -> view(IosGroupAdmissionPhase.AWAITING_REMOTE_CONFIRMATION)
            GroupAdmissionConfirmationState.Confirmed -> view(IosGroupAdmissionPhase.CONFIRMED, true)
            GroupAdmissionConfirmationState.AwaitingProof, GroupAdmissionConfirmationState.VerifyingProof,
            is GroupAdmissionConfirmationState.Closed -> error("Inactive confirmation must be mapped by the bridge")
        }
    }

    @Throws(Exception::class)
    fun remainingMillis(): Long? = bridge.remainingMillis()
    @Throws(Exception::class)
    fun prepare(): Boolean = bridge.prepare()
    @Throws(Exception::class)
    fun comparison(): IosGroupAdmissionComparison? = bridge.comparison()?.let(::IosGroupAdmissionComparison)
    @Throws(Exception::class)
    fun confirm(ticket: IosGroupAdmissionComparison): IosGroupAdmissionSign? = bridge.confirm(ticket.ticket)?.let(::IosGroupAdmissionSign)
    @Throws(Exception::class)
    fun signed(ticket: IosGroupAdmissionSign, signature: String): IosGroupAdmissionWrite? =
        bridge.signed(ticket.ticket, signature)?.let(::IosGroupAdmissionWrite)
    @Throws(Exception::class)
    fun sent(ticket: IosGroupAdmissionWrite): Boolean = bridge.sent(ticket.ticket)
    @Throws(Exception::class)
    fun signingFailed(ticket: IosGroupAdmissionSign): Boolean = bridge.signingFailed(ticket.ticket)
    @Throws(Exception::class)
    fun writeFailed(ticket: IosGroupAdmissionWrite): Boolean = bridge.writeFailed(ticket.ticket)
    @Throws(Exception::class)
    fun accept(chunk: ByteArray): Boolean = bridge.accept(chunk)
    @Throws(Exception::class)
    fun finish() = bridge.finish()
    fun cancel() = bridge.cancel()
    fun block() = bridge.block()
    fun leaveGroup() = bridge.leaveGroup()
    fun transportFailed() = bridge.transportFailed()

    private fun view(phase: IosGroupAdmissionPhase, remoteConfirmed: Boolean = false) =
        IosGroupAdmissionSnapshot(phase, IosGroupAdmissionFailure.NONE, remoteConfirmed)

    private fun failure(reason: GroupAdmissionBridgeFailure): IosGroupAdmissionFailure = when (reason) {
        GroupAdmissionBridgeFailure.InvalidFrame -> IosGroupAdmissionFailure.INVALID_FRAME
        GroupAdmissionBridgeFailure.Transport -> IosGroupAdmissionFailure.TRANSPORT
        GroupAdmissionBridgeFailure.Adapter -> IosGroupAdmissionFailure.ADAPTER
        is GroupAdmissionBridgeFailure.Attempt -> when (reason.reason) {
            is GroupAdmissionConfirmationFailure.InvalidProof -> IosGroupAdmissionFailure.INVALID_PROOF
            is GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation -> IosGroupAdmissionFailure.INVALID_REMOTE_CONFIRMATION
            GroupAdmissionConfirmationFailure.IdentityMismatch -> IosGroupAdmissionFailure.IDENTITY_MISMATCH
            GroupAdmissionConfirmationFailure.UnexpectedConfirmation -> IosGroupAdmissionFailure.UNEXPECTED_CONFIRMATION
            GroupAdmissionConfirmationFailure.LocalOperationFailed -> IosGroupAdmissionFailure.LOCAL_OPERATION_FAILED
            GroupAdmissionConfirmationFailure.AdapterFailed -> IosGroupAdmissionFailure.ADAPTER
            GroupAdmissionConfirmationFailure.Cancelled -> IosGroupAdmissionFailure.CANCELLED
            GroupAdmissionConfirmationFailure.Blocked -> IosGroupAdmissionFailure.BLOCKED
            GroupAdmissionConfirmationFailure.LeftGroup -> IosGroupAdmissionFailure.LEFT_GROUP
            GroupAdmissionConfirmationFailure.TransportClosed -> IosGroupAdmissionFailure.TRANSPORT
            GroupAdmissionConfirmationFailure.Expired -> IosGroupAdmissionFailure.EXPIRED
            GroupAdmissionConfirmationFailure.ClockMovedBackwards -> IosGroupAdmissionFailure.CLOCK_MOVED_BACKWARDS
        }
    }

    companion object {
        @Throws(Exception::class)
        fun create(
            context: IosGroupAdmissionContext,
            selectedAtMillis: Long,
            nowMillis: () -> Long,
            verifyAdmissionSignature: (String, ByteArray, String) -> Boolean,
            verifyRemoteSignature: (ByteArray, String) -> Boolean,
        ): IosGroupAdmissionConfirmation {
            val offers = context.offers
            require(selectedAtMillis <= offers.observedAtMillis) { "Invalid original selection clock" }
            return IosGroupAdmissionConfirmation(GroupAdmissionConfirmationBridge(
                context.context, offers.localIdentity, offers.localIdentity, offers.remoteIdentity, offers.remoteIdentity,
                selectedAtMillis,
                { nowMillis().also { require(it >= offers.observedAtMillis) { "Handover clock moved backwards" } } },
                verifyAdmissionSignature, verifyRemoteSignature,
            ))
        }
    }
}
