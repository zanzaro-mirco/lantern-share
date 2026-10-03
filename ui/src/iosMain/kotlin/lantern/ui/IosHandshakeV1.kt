package lantern.ui

import lantern.protocol.ProtocolCapabilitiesCodec
import lantern.protocol.ProtocolHandshakeBridge
import lantern.protocol.ProtocolHandshakeBridgeFailure
import lantern.protocol.ProtocolHandshakeBridgeSign
import lantern.protocol.ProtocolHandshakeBridgeState
import lantern.protocol.ProtocolHandshakeBridgeWrite
import lantern.protocol.ProtocolHandshakeComparison
import lantern.protocol.ProtocolHandshakeFailure
import lantern.protocol.ProtocolHandshakeFrameDecoder
import lantern.protocol.ProtocolHandshakeParticipant
import lantern.protocol.ProtocolHandshakeState

enum class IosHandshakeV1Phase {
    AWAITING_START, SENDING_HELLO, AWAITING_HELLO, AWAITING_CONFIRMATION,
    SIGNING_APPROVAL, SENDING_APPROVAL, AWAITING_REMOTE_APPROVAL, READY, CLOSED,
}

enum class IosHandshakeV1Failure {
    NONE, INVALID_FRAME, TRANSPORT, ADAPTER, IDENTITY_MISMATCH, INCOMPATIBLE,
    UNEXPECTED_MESSAGE, INVALID_SIGNATURE, ADDRESS_MISMATCH, LOCAL_OPERATION_FAILED,
    EXPIRED, CANCELLED, CLOCK_MOVED_BACKWARDS,
}

/** READY is revocable bootstrap progress, never permission to persist trust or send chat. */
data class IosHandshakeV1Snapshot(
    val phase: IosHandshakeV1Phase,
    val failure: IosHandshakeV1Failure,
    val remoteApproved: Boolean,
    val negotiatedFeatures: List<String>,
)

class IosHandshakeV1Comparison internal constructor(internal val ticket: ProtocolHandshakeComparison) {
    val bytes: ByteArray get() = ticket.bytes
}

class IosHandshakeV1Sign internal constructor(internal val ticket: ProtocolHandshakeBridgeSign) {
    val bytes: ByteArray get() = ticket.bytes
}

class IosHandshakeV1Write internal constructor(internal val ticket: ProtocolHandshakeBridgeWrite) {
    val bytes: ByteArray get() = ticket.bytes
}

/**
 * Swift-facing facade only. Kotlin owns all bootstrap rules; not wired into PairingChannel.
 * The future native owner supplies OS nonce, verified mutual-TLS pins, selection clock and a
 * verifier bound to that connection's certificate. All calls run on its serial service queue.
 * It must close NWConnection on CLOSED, schedule deadline checks while idle, and close transport
 * if construction throws. Pass sent ONLY from the successful contentProcessed callback.
 */
class IosHandshakeV1 private constructor(private val bridge: ProtocolHandshakeBridge) {
    val maximumChunkBytes: Int get() = ProtocolHandshakeFrameDecoder.MAX_CHUNK_BYTES

    @Throws(Exception::class)
    fun snapshot(): IosHandshakeV1Snapshot = when (val state = bridge.state()) {
        ProtocolHandshakeBridgeState.AwaitingStart -> view(IosHandshakeV1Phase.AWAITING_START)
        ProtocolHandshakeBridgeState.SendingHello -> view(IosHandshakeV1Phase.SENDING_HELLO)
        is ProtocolHandshakeBridgeState.Closed -> IosHandshakeV1Snapshot(
            IosHandshakeV1Phase.CLOSED, failure(state.reason), false, emptyList(),
        )
        is ProtocolHandshakeBridgeState.Active -> when (val handshake = state.handshake) {
            ProtocolHandshakeState.AwaitingHello -> view(IosHandshakeV1Phase.AWAITING_HELLO)
            is ProtocolHandshakeState.AwaitingConfirmation -> view(IosHandshakeV1Phase.AWAITING_CONFIRMATION, handshake.remoteApproved)
            is ProtocolHandshakeState.SigningApproval -> view(IosHandshakeV1Phase.SIGNING_APPROVAL, handshake.remoteApproved)
            is ProtocolHandshakeState.SendingApproval -> view(IosHandshakeV1Phase.SENDING_APPROVAL, handshake.remoteApproved)
            ProtocolHandshakeState.AwaitingRemoteApproval -> view(IosHandshakeV1Phase.AWAITING_REMOTE_APPROVAL)
            is ProtocolHandshakeState.Ready -> IosHandshakeV1Snapshot(
                IosHandshakeV1Phase.READY, IosHandshakeV1Failure.NONE, true, handshake.capabilities.features.sorted(),
            )
            is ProtocolHandshakeState.Closed -> error("Closed handshake must be mapped by the bridge")
        }
    }

    @Throws(Exception::class)
    fun remainingMillis(): Long? = bridge.remainingMillis()
    @Throws(Exception::class)
    fun start(): IosHandshakeV1Write? = bridge.start()?.let(::IosHandshakeV1Write)
    @Throws(Exception::class)
    fun sent(ticket: IosHandshakeV1Write): Boolean = bridge.sent(ticket.ticket)
    @Throws(Exception::class)
    fun accept(chunk: ByteArray): Boolean = bridge.accept(chunk)
    @Throws(Exception::class)
    fun comparison(): IosHandshakeV1Comparison? = bridge.comparison()?.let(::IosHandshakeV1Comparison)
    @Throws(Exception::class)
    fun confirm(ticket: IosHandshakeV1Comparison): IosHandshakeV1Sign? = bridge.confirm(ticket.ticket)?.let(::IosHandshakeV1Sign)
    @Throws(Exception::class)
    fun signed(ticket: IosHandshakeV1Sign, signature: String): IosHandshakeV1Write? = bridge.signed(ticket.ticket, signature)?.let(::IosHandshakeV1Write)
    @Throws(Exception::class)
    fun writeFailed(ticket: IosHandshakeV1Write): Boolean = bridge.writeFailed(ticket.ticket)
    @Throws(Exception::class)
    fun signingFailed(ticket: IosHandshakeV1Sign): Boolean = bridge.signingFailed(ticket.ticket)
    @Throws(Exception::class)
    fun finish() = bridge.finish()
    fun cancel() = bridge.cancel()

    private fun view(phase: IosHandshakeV1Phase, remoteApproved: Boolean = false) =
        IosHandshakeV1Snapshot(phase, IosHandshakeV1Failure.NONE, remoteApproved, emptyList())

    private fun failure(reason: ProtocolHandshakeBridgeFailure): IosHandshakeV1Failure = when (reason) {
        ProtocolHandshakeBridgeFailure.InvalidFrame -> IosHandshakeV1Failure.INVALID_FRAME
        ProtocolHandshakeBridgeFailure.Transport -> IosHandshakeV1Failure.TRANSPORT
        ProtocolHandshakeBridgeFailure.Adapter -> IosHandshakeV1Failure.ADAPTER
        is ProtocolHandshakeBridgeFailure.Protocol -> when (reason.reason) {
            ProtocolHandshakeFailure.IdentityMismatch -> IosHandshakeV1Failure.IDENTITY_MISMATCH
            is ProtocolHandshakeFailure.Incompatible -> IosHandshakeV1Failure.INCOMPATIBLE
            ProtocolHandshakeFailure.UnexpectedMessage -> IosHandshakeV1Failure.UNEXPECTED_MESSAGE
            ProtocolHandshakeFailure.InvalidSignature -> IosHandshakeV1Failure.INVALID_SIGNATURE
            ProtocolHandshakeFailure.AddressMismatch -> IosHandshakeV1Failure.ADDRESS_MISMATCH
            ProtocolHandshakeFailure.LocalOperationFailed -> IosHandshakeV1Failure.LOCAL_OPERATION_FAILED
            ProtocolHandshakeFailure.Expired -> IosHandshakeV1Failure.EXPIRED
            ProtocolHandshakeFailure.Cancelled -> IosHandshakeV1Failure.CANCELLED
            ProtocolHandshakeFailure.ClockMovedBackwards -> IosHandshakeV1Failure.CLOCK_MOVED_BACKWARDS
        }
    }

    companion object {
        @Throws(Exception::class)
        fun create(
            localIdentity: String,
            localNonce: String,
            capabilitiesJson: String,
            authenticatedLocalIdentity: String,
            selectedPeerIdentity: String,
            authenticatedPeerIdentity: String,
            selectedAtMillis: Long,
            nowMillis: () -> Long,
            verifyRemoteSignature: (ByteArray, String) -> Boolean,
        ): IosHandshakeV1 = IosHandshakeV1(ProtocolHandshakeBridge(
            ProtocolHandshakeParticipant(localIdentity, localNonce, ProtocolCapabilitiesCodec.decode(capabilitiesJson.encodeToByteArray())),
            authenticatedLocalIdentity, selectedPeerIdentity, authenticatedPeerIdentity, selectedAtMillis, nowMillis, verifyRemoteSignature,
        ))
    }
}
