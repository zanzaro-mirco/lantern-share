package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ProtocolHandshakeBridgeTest {
    private val capabilities = ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text"))
    private val leftParticipant = ProtocolHandshakeParticipant("a".repeat(64), "1".repeat(64), capabilities)
    private val rightParticipant = ProtocolHandshakeParticipant("b".repeat(64), "2".repeat(64), capabilities)
    private val signature = "cHJvb2Y="

    @Test
    fun helloAndApprovalAdvanceOnlyAfterSuccessfulWriteCallbacks() {
        val left = bridge(leftParticipant, rightParticipant)
        val right = bridge(rightParticipant, leftParticipant)
        exchange(left, right)
        val leftCode = assertNotNull(left.comparison())
        assertContentEquals(leftCode.bytes, assertNotNull(right.comparison()).bytes)
        val signing = assertNotNull(left.confirm(leftCode))
        assertNull(left.confirm(leftCode))
        val sending = assertNotNull(left.signed(signing, signature))
        assertNull(left.signed(signing, signature))
        // Receiving proof does not imply local UI confirmation or a completed local write.
        assertTrue(right.accept(sending.bytes))
        assertEquals(active(ProtocolHandshakeState.AwaitingConfirmation(true)), right.state())
        val remoteSign = assertNotNull(right.confirm(assertNotNull(right.comparison())))
        val remoteSend = assertNotNull(right.signed(remoteSign, signature))
        assertTrue(left.accept(remoteSend.bytes))
        assertEquals(active(ProtocolHandshakeState.SendingApproval(true)), left.state())
        assertTrue(left.sent(sending))
        assertTrue(right.sent(remoteSend))
        assertIs<ProtocolHandshakeState.Ready>(assertIs<ProtocolHandshakeBridgeState.Active>(left.state()).handshake)
        assertFalse(left.sent(sending))
        left.cancel()
        assertClosed(left, ProtocolHandshakeFailure.Cancelled)
        assertFalse(left.accept(remoteSend.bytes))
    }

    @Test
    fun initialHelloTicketIsUniqueDefensiveAndBelongsToItsInstance() {
        val first = bridge(leftParticipant, rightParticipant)
        val second = bridge(leftParticipant, rightParticipant)
        val send = assertNotNull(first.start())
        val expected = send.bytes
        send.bytes.fill(0)
        assertContentEquals(expected, send.bytes)
        assertEquals(ProtocolHandshakeBridgeState.SendingHello, first.state())
        assertNull(first.start())
        assertFalse(second.sent(send))
        assertEquals(ProtocolHandshakeBridgeState.AwaitingStart, second.state())
        assertTrue(first.sent(send))
        assertEquals(active(ProtocolHandshakeState.AwaitingHello), first.state())
        assertNull(first.start())
        assertFalse(first.sent(send))
    }

    @Test
    fun inputBeforeHelloCompletionFailsClosedInsteadOfAdvancing() {
        for (started in listOf(false, true)) {
            val owner = bridge(leftParticipant, rightParticipant)
            if (started) owner.start()
            assertFailsWith<IllegalStateException> { owner.accept(ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Hello(rightParticipant))) }
            assertEquals(ProtocolHandshakeBridgeState.Closed(ProtocolHandshakeBridgeFailure.Adapter), owner.state())
            assertNull(owner.comparison())
        }
    }

    @Test
    fun fragmentedHelloIsRoutedOnlyWhenCompleteAndCorruptTailCloses() {
        val owner = started()
        val frame = ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Hello(rightParticipant))
        for (byte in frame.dropLast(1)) {
            assertTrue(owner.accept(byteArrayOf(byte)))
            assertNull(owner.comparison())
        }
        assertTrue(owner.accept(byteArrayOf(frame.last())))
        assertNotNull(owner.comparison())
        assertFailsWith<IllegalArgumentException> { owner.accept(byteArrayOf(0, 0, 0, 0)) }
        assertEquals(ProtocolHandshakeBridgeState.Closed(ProtocolHandshakeBridgeFailure.InvalidFrame), owner.state())
        assertNull(owner.comparison())
        assertFalse(owner.accept(frame))
    }

    @Test
    fun staleComparisonSignatureAndWriteCallbacksCannotAdvanceAnotherInstance() {
        val first = started()
        first.accept(ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Hello(rightParticipant)))
        val comparison = assertNotNull(first.comparison())
        val signing = assertNotNull(first.confirm(comparison))
        val second = started()
        second.accept(ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Hello(rightParticipant)))
        assertNull(second.confirm(comparison))
        assertNull(second.signed(signing, signature))
        assertFalse(second.signingFailed(signing))
        val send = assertNotNull(first.signed(signing, signature))
        assertFalse(second.sent(send))
        assertFalse(second.writeFailed(send))
        first.cancel()
        assertFalse(first.sent(send))
        assertNull(first.signed(signing, signature))
        assertEquals(active(ProtocolHandshakeState.AwaitingConfirmation(false)), second.state())
    }

    @Test
    fun failedHelloApprovalOrSignatureInvalidateTheCurrentTicketsOnly() {
        val helloOwner = bridge(leftParticipant, rightParticipant)
        val hello = assertNotNull(helloOwner.start())
        assertTrue(helloOwner.writeFailed(hello))
        assertEquals(ProtocolHandshakeBridgeState.Closed(ProtocolHandshakeBridgeFailure.Transport), helloOwner.state())
        assertFalse(helloOwner.sent(hello))
        for (signFails in listOf(false, true)) {
            val owner = started()
            owner.accept(ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Hello(rightParticipant)))
            val signing = assertNotNull(owner.confirm(assertNotNull(owner.comparison())))
            if (signFails) {
                assertTrue(owner.signingFailed(signing))
                assertClosed(owner, ProtocolHandshakeFailure.LocalOperationFailed)
            } else {
                val send = assertNotNull(owner.signed(signing, signature))
                assertTrue(owner.writeFailed(send))
                assertFalse(owner.sent(send))
                assertEquals(ProtocolHandshakeBridgeState.Closed(ProtocolHandshakeBridgeFailure.Transport), owner.state())
            }
        }
    }

    @Test
    fun exactDeadlineRevokesPendingHelloSignWriteAndIdleProgress() {
        for (stage in 0..3) {
            var now = 0L
            val owner = bridge(leftParticipant, rightParticipant, now = { now })
            val hello = assertNotNull(owner.start())
            var signing: ProtocolHandshakeBridgeSign? = null
            var sending: ProtocolHandshakeBridgeWrite? = null
            if (stage > 0) {
                owner.sent(hello)
                owner.accept(ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Hello(rightParticipant)))
                if (stage > 1) signing = owner.confirm(assertNotNull(owner.comparison()))
                if (stage > 2) sending = owner.signed(assertNotNull(signing), signature)
            }
            now = ProtocolHandshakeAttempt.TIMEOUT_MILLIS
            assertNull(owner.remainingMillis())
            assertClosed(owner, ProtocolHandshakeFailure.Expired)
            assertFalse(owner.sent(hello))
            signing?.let { assertNull(owner.signed(it, signature)) }
            sending?.let { assertFalse(owner.sent(it)) }
        }
    }

    @Test
    fun expirationInsideAWriteOrSignatureCallbackCannotReturnNewProgress() {
        var now = 0L
        var observations = 0
        var expireAt = Int.MAX_VALUE
        val owner = bridge(leftParticipant, rightParticipant, now = {
            observations++
            if (observations >= expireAt) now = ProtocolHandshakeAttempt.TIMEOUT_MILLIS
            now
        })
        owner.sent(assertNotNull(owner.start()))
        owner.accept(ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Hello(rightParticipant)))
        val signing = assertNotNull(owner.confirm(assertNotNull(owner.comparison())))
        // Bridge entry and machine.signed are live; its final snapshot reaches the deadline.
        expireAt = observations + 3
        assertNull(owner.signed(signing, signature))
        assertClosed(owner, ProtocolHandshakeFailure.Expired)

        var ticks = 0
        var expireHelloAt = Int.MAX_VALUE
        val helloOwner = bridge(leftParticipant, rightParticipant, now = {
            ticks++
            if (ticks >= expireHelloAt) ProtocolHandshakeAttempt.TIMEOUT_MILLIS else 0L
        })
        val hello = assertNotNull(helloOwner.start())
        expireHelloAt = ticks + 2
        assertFalse(helloOwner.sent(hello))
        assertClosed(helloOwner, ProtocolHandshakeFailure.Expired)
    }

    @Test
    fun eofAndTruncationAreTerminalAndDoNotResurrectProgress() {
        for (partial in listOf(byteArrayOf(), byteArrayOf(0), byteArrayOf(0, 0, 0, 10, 1))) {
            val owner = started()
            owner.accept(partial)
            if (partial.isEmpty()) owner.finish() else assertFailsWith<IllegalArgumentException> { owner.finish() }
            assertEquals(ProtocolHandshakeBridgeState.Closed(ProtocolHandshakeBridgeFailure.Transport), owner.state())
            assertNull(owner.start())
            owner.finish()
        }
    }

    @Test
    fun tlsPinsAndProtocolRejectionArePreservedAndVerifierErrorsAreRethrown() {
        assertFailsWith<IllegalArgumentException> { bridge(leftParticipant, rightParticipant, localPin = rightParticipant.identity) }
        val mismatch = bridge(leftParticipant, rightParticipant, peerPin = "c".repeat(64))
        assertNull(mismatch.start())
        assertClosed(mismatch, ProtocolHandshakeFailure.IdentityMismatch)
        val wrongHello = started()
        assertFalse(wrongHello.accept(ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Hello(leftParticipant))))
        assertClosed(wrongHello, ProtocolHandshakeFailure.IdentityMismatch)
        val error = IllegalStateException("test-only verifier error")
        val owner = bridge(leftParticipant, rightParticipant, verifier = { _, _ -> throw error })
        owner.sent(assertNotNull(owner.start()))
        owner.accept(ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Hello(rightParticipant)))
        assertSame(error, assertFailsWith<IllegalStateException> {
            owner.accept(ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Approve(ProtocolHandshakeApproval(rightParticipant.identity, leftParticipant.identity, signature))))
        })
        assertEquals(ProtocolHandshakeBridgeState.Closed(ProtocolHandshakeBridgeFailure.Adapter), owner.state())
    }

    private fun bridge(
        local: ProtocolHandshakeParticipant, peer: ProtocolHandshakeParticipant,
        localPin: String = local.identity, peerPin: String = peer.identity,
        now: () -> Long = { 0L }, verifier: (ByteArray, String) -> Boolean = { _, proof -> proof == signature },
    ) = ProtocolHandshakeBridge(local, localPin, peer.identity, peerPin, 0L, now, verifier)

    private fun started() = bridge(leftParticipant, rightParticipant).also { it.sent(assertNotNull(it.start())) }

    private fun exchange(left: ProtocolHandshakeBridge, right: ProtocolHandshakeBridge) {
        val helloLeft = assertNotNull(left.start())
        val helloRight = assertNotNull(right.start())
        assertTrue(left.sent(helloLeft))
        assertTrue(right.sent(helloRight))
        assertTrue(left.accept(helloRight.bytes))
        assertTrue(right.accept(helloLeft.bytes))
    }

    private fun active(state: ProtocolHandshakeState) = ProtocolHandshakeBridgeState.Active(state)
    private fun assertClosed(owner: ProtocolHandshakeBridge, reason: ProtocolHandshakeFailure) =
        assertEquals(ProtocolHandshakeBridgeState.Closed(ProtocolHandshakeBridgeFailure.Protocol(reason)), owner.state())
}
