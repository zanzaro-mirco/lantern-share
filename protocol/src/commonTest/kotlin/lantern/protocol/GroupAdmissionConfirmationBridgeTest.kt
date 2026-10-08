package lantern.protocol

import kotlinx.coroutines.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor

/** Callback lifecycle/framing doubles only. No OS transport or automatic trust in these tests. */
class GroupAdmissionConfirmationBridgeTest {
    private val issuer = "a".repeat(64)
    private val member = "b".repeat(64)
    private val other = "c".repeat(64)
    private val caps = ProtocolCapabilities(1, setOf("text", "receipts"))
    private val anchor = GroupTrustAnchor(other, issuer)
    private val admission = SignedGroupAdmission(GroupAdmissionClaim(other, issuer, member), "cHJvb2Y=")
    private val context = GroupAdmissionConfirmationContext(
        ProtocolHandshakeParticipant(issuer, "d".repeat(64), caps),
        ProtocolHandshakeParticipant(member, "e".repeat(64), caps), anchor, GroupAdmissionProof(anchor, listOf(admission)))
    private val remoteBytes = GroupAdmissionConfirmationFrameDecoder.encode(GroupAdmissionConfirmation(issuer, member, "cHJvb2Y="))
    private var now = 10L

    @Test
    fun cancellationDuringProofVerificationCannotExposeTicketsOrAcceptBytes() {
        lateinit var bridge: GroupAdmissionConfirmationBridge
        bridge = bridge(proofVerifier = { _, _, _ -> bridge.cancel(); true })
        assertFalse(bridge.prepare())
        assertNull(bridge.comparison())
        assertFalse(bridge.accept(remoteBytes))
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.Cancelled)), bridge.state())
    }

    @Test
    fun remainingBudgetAndStateRevokeConfirmedAtTheOriginalDeadline() {
        val bridge = prepared()
        val write = pendingWrite(bridge)
        assertTrue(bridge.accept(remoteBytes))
        assertTrue(bridge.sent(write))
        now = 10 + GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS - 1
        assertEquals(1L, bridge.remainingMillis())
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Confirmed), bridge.state())
        now++
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.Expired)), bridge.state())
        assertNull(bridge.remainingMillis())
        assertFalse(bridge.accept(remoteBytes))
        assertFalse(bridge.sent(write))
    }

    @Test
    fun proofAndExplicitConfirmationAreRequiredAndEncodingNeverAcknowledgesWrite() {
        val bridge = bridge()
        assertEquals(GroupAdmissionBridgeState.AwaitingStart, bridge.state())
        assertNull(bridge.comparison())
        assertTrue(bridge.prepare())
        assertFalse(bridge.prepare())
        val comparison = assertNotNull(bridge.comparison())
        val sign = assertNotNull(bridge.confirm(comparison))
        assertContentEquals(context.approvalBytes(member), sign.bytes)
        val write = assertNotNull(bridge.signed(sign, "cHJvb2Y="))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Sending(false)), bridge.state())
        assertTrue(bridge.accept(remoteBytes))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Sending(true)), bridge.state())
        assertTrue(bridge.sent(write))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Confirmed), bridge.state())
        assertFalse(bridge.sent(write))
        assertNull(bridge.confirm(comparison))
    }

    @Test
    fun remoteChunksAndEitherOrderDoNotAcknowledgeLocalWrite() {
        for (remoteFirst in listOf(false, true)) {
            val bridge = prepared()
            if (remoteFirst) assertTrue(bridge.accept(remoteBytes))
            val write = pendingWrite(bridge)
            if (!remoteFirst) {
                for (byte in remoteBytes) assertTrue(bridge.accept(byteArrayOf(byte)))
            }
            assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Sending(true)), bridge.state())
            assertTrue(bridge.sent(write))
            assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Confirmed), bridge.state())
        }
    }

    @Test
    fun foreignTicketsAndMutatedBufferViewsCannotAdvanceAnotherBridge() {
        val first = prepared()
        val second = prepared()
        val comparison = assertNotNull(first.comparison())
        assertNull(second.confirm(comparison))
        val sign = assertNotNull(first.confirm(comparison))
        val expectedSign = sign.bytes
        sign.bytes.fill(0)
        assertContentEquals(expectedSign, sign.bytes)
        assertNull(second.signed(sign, "cHJvb2Y="))
        assertFalse(second.signingFailed(sign))
        val write = assertNotNull(first.signed(sign, "cHJvb2Y="))
        val expectedWrite = write.bytes
        write.bytes.fill(0)
        assertContentEquals(expectedWrite, write.bytes)
        assertFalse(second.sent(write))
        assertFalse(second.writeFailed(write))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.AwaitingConfirmation(false)), second.state())
    }

    @Test
    fun earlyInputOrInvalidProofNeverExposesAComparison() {
        val early = bridge()
        assertFailsWith<IllegalStateException> { early.accept(byteArrayOf()) }
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Adapter), early.state())
        assertNull(early.comparison())
        val invalid = bridge(proofVerifier = { _, _, _ -> false })
        assertFalse(invalid.prepare())
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.InvalidProof(GroupAdmissionChainResult.InvalidSignature(0)))), invalid.state())
        assertNull(invalid.comparison())
        val wrongPeer = bridge(selected = other)
        assertFalse(wrongPeer.prepare())
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.IdentityMismatch)), wrongPeer.state())
        assertFailsWith<IllegalArgumentException> { bridge(localPin = issuer) }
    }

    @Test
    fun eofRevokesConfirmedAndTruncationPermanentlyClosesWithDistinctFailure() {
        val completed = prepared()
        val write = pendingWrite(completed)
        assertTrue(completed.accept(remoteBytes))
        assertTrue(completed.sent(write))
        completed.finish()
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.TransportClosed)), completed.state())
        assertFalse(completed.sent(write))
        assertFalse(completed.accept(remoteBytes))
        completed.finish()
        for (end in listOf(1, 3, 4, remoteBytes.size - 1)) {
            val truncated = prepared()
            assertTrue(truncated.accept(remoteBytes.copyOfRange(0, end)))
            assertFailsWith<IllegalArgumentException> { truncated.finish() }
            assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.InvalidFrame), truncated.state())
            assertFalse(truncated.accept(remoteBytes))
        }
    }

    @Test
    fun malformedOrDuplicateBatchCannotLeaveAConfirmedState() {
        val malformed = prepared()
        val sensitive = "{\"sensitive-peer-content\":true}".encodeToByteArray()
        val failure = assertFailsWith<IllegalArgumentException> {
            malformed.accept(remoteBytes + GroupAdmissionConfirmationFraming.header(sensitive.size) + sensitive)
        }
        assertEquals("Invalid group confirmation frame", failure.message)
        assertNull(failure.cause)
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.InvalidFrame), malformed.state())
        val duplicate = prepared()
        assertFalse(duplicate.accept(remoteBytes + remoteBytes))
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.UnexpectedConfirmation)), duplicate.state())
    }

    @Test
    fun lifecycleEventsRevokeTicketsAndRetainTheFirstReason() {
        val closures: List<Pair<(GroupAdmissionConfirmationBridge) -> Unit, GroupAdmissionBridgeFailure>> = listOf(
            { bridge: GroupAdmissionConfirmationBridge -> bridge.cancel() } to GroupAdmissionBridgeFailure.Attempt(GroupAdmissionConfirmationFailure.Cancelled),
            { bridge: GroupAdmissionConfirmationBridge -> bridge.block() } to GroupAdmissionBridgeFailure.Attempt(GroupAdmissionConfirmationFailure.Blocked),
            { bridge: GroupAdmissionConfirmationBridge -> bridge.leaveGroup() } to GroupAdmissionBridgeFailure.Attempt(GroupAdmissionConfirmationFailure.LeftGroup),
            { bridge: GroupAdmissionConfirmationBridge -> bridge.transportFailed() } to GroupAdmissionBridgeFailure.Transport,
        )
        for ((close, reason) in closures) {
            val bridge = prepared()
            val comparison = assertNotNull(bridge.comparison())
            val sign = assertNotNull(bridge.confirm(comparison))
            val write = assertNotNull(bridge.signed(sign, "cHJvb2Y="))
            close(bridge)
            bridge.cancel()
            assertEquals(GroupAdmissionBridgeState.Closed(reason), bridge.state())
            assertNull(bridge.remainingMillis())
            assertNull(bridge.comparison())
            assertNull(bridge.confirm(comparison))
            assertNull(bridge.signed(sign, "cHJvb2Y="))
            assertFalse(bridge.sent(write))
            assertFalse(bridge.accept(remoteBytes))
            assertFalse(bridge.prepare())
            bridge.finish()
        }
    }

    @Test
    fun signingAndWriteFailuresOnlyAcceptTheCurrentTicket() {
        val signing = prepared()
        val sign = assertNotNull(signing.confirm(assertNotNull(signing.comparison())))
        assertTrue(signing.signingFailed(sign))
        assertFalse(signing.signingFailed(sign))
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.LocalOperationFailed)), signing.state())
        val writing = prepared()
        val write = pendingWrite(writing)
        assertTrue(writing.writeFailed(write))
        assertFalse(writing.writeFailed(write))
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Transport), writing.state())
    }

    @Test
    fun verifierCancellationOrDeadlineCannotRestoreBridgeProgress() {
        lateinit var cancelled: GroupAdmissionConfirmationBridge
        cancelled = bridge(remoteVerifier = { _, _ -> cancelled.cancel(); true })
        assertTrue(cancelled.prepare())
        assertFalse(cancelled.accept(remoteBytes))
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.Cancelled)), cancelled.state())
        val expired = bridge(remoteVerifier = { _, _ -> now += GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS; true })
        assertTrue(expired.prepare())
        val write = pendingWrite(expired)
        assertFalse(expired.accept(remoteBytes))
        assertFalse(expired.sent(write))
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.Expired)), expired.state())
    }

    @Test
    fun unexpectedOsErrorsAndCancellationCloseAndPropagate() {
        for (failure in listOf(IllegalStateException("Test OS failure"), CancellationException("Cancelled"))) {
            val bridge = bridge(remoteVerifier = { _, _ -> throw failure })
            assertTrue(bridge.prepare())
            assertSame(failure, assertFailsWith<Exception> { bridge.accept(remoteBytes) })
            assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Adapter), bridge.state())
            assertFalse(bridge.accept(remoteBytes))
        }
    }

    private fun pendingWrite(bridge: GroupAdmissionConfirmationBridge): GroupAdmissionBridgeWrite {
        val sign = assertNotNull(bridge.confirm(assertNotNull(bridge.comparison())))
        return assertNotNull(bridge.signed(sign, "cHJvb2Y="))
    }
    private fun prepared() = bridge().also { assertTrue(it.prepare()) }
    private fun bridge(
        localPin: String = member,
        selected: String = issuer,
        proofVerifier: (String, ByteArray, String) -> Boolean = { _, _, _ -> true },
        remoteVerifier: (ByteArray, String) -> Boolean = { _, _ -> true },
    ) = GroupAdmissionConfirmationBridge(context, member, localPin, selected, issuer, 10, { now }, proofVerifier, remoteVerifier)
}
