package lantern.connectivity

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeApproval
import lantern.protocol.ProtocolHandshakeFrame
import lantern.protocol.ProtocolHandshakeFrameCodec
import lantern.protocol.ProtocolHandshakeParticipant
import lantern.protocol.GroupMembershipEvidence
import lantern.protocol.GroupMembershipEvidenceCodec
import lantern.domain.GroupTrustAnchor
import lantern.domain.SessionCandidate
import lantern.protocol.GroupSessionOffer
import lantern.protocol.GroupSessionOfferCodec
import lantern.protocol.GroupTextTransferCodec
import lantern.protocol.GroupTextTransferContext

class HandshakeV1FrameStreamTest {
    private val hello = ProtocolHandshakeFrame.Hello(
        ProtocolHandshakeParticipant("a".repeat(64), "1".repeat(64), ProtocolCapabilities(1, setOf("text"), setOf("text"))),
    )
    private val approve = ProtocolHandshakeFrame.Approve(ProtocolHandshakeApproval("a".repeat(64), "b".repeat(64), "cHJvb2Y="))

    @Test
    fun consecutiveFramesPreserveBoundariesAndFlush() {
        var flushes = 0
        val bytes = object : ByteArrayOutputStream() {
            override fun flush() { flushes++ }
        }
        val writer = HandshakeV1FrameStream(ByteArrayInputStream(byteArrayOf()), bytes)
        writer.write(hello)
        writer.write(approve)
        assertEquals(2, flushes)
        val reader = reader(bytes.toByteArray())
        assertFrameEquals(hello, reader.read())
        assertEquals(approve, reader.read())
        assertFailsWith<EOFException> { reader.read() }
    }

    @Test
    fun fragmentedHeaderAndBodyRecheckTheBudgetBeforeEveryRead() {
        val bytes = framed(ProtocolHandshakeFrameCodec.encode(hello))
        val fragmented = object : FilterInputStream(ByteArrayInputStream(bytes)) {
            override fun read(target: ByteArray, offset: Int, length: Int) = super.read(target, offset, minOf(1, length))
        }
        var checks = 0
        assertFrameEquals(hello, HandshakeV1FrameStream(fragmented, ByteArrayOutputStream()).read { checks++ })
        assertEquals(bytes.size, checks)
    }

    @Test
    fun unsignedLengthsAreRejectedAfterOnlyFourBytesBeforeAllocation() {
        for (length in listOf(0, -1, Int.MIN_VALUE, ProtocolHandshakeFrameCodec.MAX_BYTES + 1)) {
            val bytes = ByteArrayOutputStream().also { DataOutputStream(it).writeInt(length) }.toByteArray()
            val input = ByteArrayInputStream(bytes + byteArrayOf(1, 2, 3))
            assertFailsWith<InvalidHandshakeV1FrameException> { HandshakeV1FrameStream(input, ByteArrayOutputStream()).read() }
            assertEquals(3, input.available())
        }
    }

    @Test
    fun exactPayloadLimitIsAcceptedAndTruncationIsNot() {
        val encoded = ProtocolHandshakeFrameCodec.encode(hello)
        val padded = encoded + ByteArray(ProtocolHandshakeFrameCodec.MAX_BYTES - encoded.size) { ' '.code.toByte() }
        assertFrameEquals(hello, reader(framed(padded)).read())
        val bytes = framed(encoded)
        for (size in listOf(0, 1, 3, 4, bytes.size - 1)) {
            assertFailsWith<EOFException> { reader(bytes.copyOf(size)).read() }
        }
    }

    @Test
    fun invalidJsonUtf8AndV0AreRejectedWithoutPeerContentInTheDiagnostic() {
        val invalid = listOf(
            "{\"sensitive-peer-content\":true}".encodeToByteArray(),
            byteArrayOf(0xc3.toByte(), 0x28),
            "{\"version\":0,\"type\":\"HELLO\"}".encodeToByteArray(),
            ("[".repeat(5) + "]".repeat(5)).encodeToByteArray(),
        )
        for (payload in invalid) {
            val failure = assertFailsWith<InvalidHandshakeV1FrameException> { reader(framed(payload)).read() }
            assertEquals("Invalid v1 bootstrap frame", failure.message)
            assertEquals(null, failure.cause)
        }
    }

    @Test
    fun stalledStreamAndExpiredReadCallbackDoNotLoopOrConsumeInput() {
        val stalled = object : InputStream() {
            override fun read() = 0
            override fun read(bytes: ByteArray, offset: Int, length: Int) = 0
        }
        assertFailsWith<IOException> { HandshakeV1FrameStream(stalled, ByteArrayOutputStream()).read() }
        val input = ByteArrayInputStream(framed(ProtocolHandshakeFrameCodec.encode(hello)))
        val available = input.available()
        val expired = IOException("test-only deadline")
        assertSame(expired, assertFailsWith<IOException> {
            HandshakeV1FrameStream(input, ByteArrayOutputStream()).read { throw expired }
        })
        assertEquals(available, input.available())
    }

    @Test
    fun failedFlushIsNotAWriteSuccess() {
        val error = IOException("test-only flush failure")
        val output = object : OutputStream() {
            override fun write(value: Int) = Unit
            override fun flush(): Unit = throw error
        }
        assertSame(error, assertFailsWith<IOException> {
            HandshakeV1FrameStream(ByteArrayInputStream(byteArrayOf()), output).write(hello)
        })
    }

    @Test
    fun membershipReadsAreExactEvenWhenFragmentedAndLeaveFollowingDataUntouched() {
        val id = "a".repeat(64)
        val evidence = GroupMembershipEvidence(GroupTrustAnchor("b".repeat(64), id), id, null)
        val payload = GroupMembershipEvidenceCodec.encode(evidence)
        val input = ByteArrayInputStream(GroupMembershipEvidenceCodec.header(payload.size) + payload + byteArrayOf(7, 8))
        val fragmented = object : FilterInputStream(input) {
            override fun read(bytes: ByteArray, offset: Int, length: Int) = super.read(bytes, offset, minOf(1, length))
        }
        var checks = 0
        val decoded = HandshakeV1FrameStream(fragmented, ByteArrayOutputStream()).readMembership { checks++ }
        assertEquals(payload.size + 4, checks)
        assertContentEquals(payload, GroupMembershipEvidenceCodec.encode(decoded))
        assertEquals(7, input.read())
        assertEquals(8, input.read())
    }

    @Test
    fun membershipLengthAndExpiredReadsFailBeforeConsumingBodyAndFlushFailurePropagates() {
        val input = ByteArrayInputStream(byteArrayOf(-1, -1, -1, -1, 7))
        assertFailsWith<InvalidGroupEvidenceFrameException> { HandshakeV1FrameStream(input, ByteArrayOutputStream()).readMembership {} }
        assertEquals(7, input.read())
        val deadline = IOException("Test original deadline")
        assertSame(deadline, assertFailsWith<IOException> {
            HandshakeV1FrameStream(input, ByteArrayOutputStream()).readMembership { throw deadline }
        })
        val id = "a".repeat(64)
        val evidence = GroupMembershipEvidence(GroupTrustAnchor("b".repeat(64), id), id, null)
        val output = object : OutputStream() {
            override fun write(value: Int) = Unit
            override fun flush(): Unit = throw deadline
        }
        assertSame(deadline, assertFailsWith<IOException> { HandshakeV1FrameStream(input, output).writeMembership(evidence) })
        HandshakeV1FrameStream(ByteArrayInputStream(byteArrayOf()), ByteArrayOutputStream()).awaitMembershipEnd {}
        assertFailsWith<InvalidGroupEvidenceFrameException> {
            HandshakeV1FrameStream(ByteArrayInputStream(byteArrayOf(1)), ByteArrayOutputStream()).awaitMembershipEnd {}
        }
    }

    private fun framed(payload: ByteArray): ByteArray = ByteArrayOutputStream().also { bytes ->
        DataOutputStream(bytes).apply { writeInt(payload.size); write(payload) }
    }.toByteArray()

    @Test
    fun sessionReadIsExactFragmentedBoundedAndDoesNotOverread() {
        val value = GroupSessionOffer(SessionCandidate("a".repeat(64), "b".repeat(64), true))
        val bytes = GroupSessionOfferCodec.header() + GroupSessionOfferCodec.encode(value)
        val input = ByteArrayInputStream(bytes + byteArrayOf(7))
        val fragmented = object : FilterInputStream(input) {
            override fun read(bytes: ByteArray, offset: Int, length: Int) = super.read(bytes, offset, minOf(1, length))
        }
        var checks = 0
        assertEquals(value, HandshakeV1FrameStream(fragmented, ByteArrayOutputStream()).readSessionOffer { checks++ })
        assertEquals(bytes.size, checks)
        assertEquals(7, input.read())
        for (size in 0 until bytes.size) assertFailsWith<EOFException> {
            HandshakeV1FrameStream(ByteArrayInputStream(bytes.copyOf(size)), ByteArrayOutputStream()).readSessionOffer {}
        }
        for (bad in listOf(0, -1, Int.MIN_VALUE, GroupSessionOfferCodec.PAYLOAD_BYTES + 1)) {
            val header = ByteArrayOutputStream().also { DataOutputStream(it).writeInt(bad) }.toByteArray()
            val invalid = ByteArrayInputStream(header + byteArrayOf(7))
            assertFailsWith<InvalidGroupEvidenceFrameException> {
                HandshakeV1FrameStream(invalid, ByteArrayOutputStream()).readSessionOffer {}
            }
            assertEquals(7, invalid.read())
        }
    }

    @Test
    fun sessionIoChecksDeadlineAndPropagatesWriteFlushFailure() {
        val value = GroupSessionOffer(SessionCandidate("a".repeat(64), "b".repeat(64), false))
        val output = ByteArrayOutputStream()
        HandshakeV1FrameStream(ByteArrayInputStream(byteArrayOf()), output).writeSessionOffer(value)
        assertContentEquals(GroupSessionOfferCodec.header() + GroupSessionOfferCodec.encode(value), output.toByteArray())
        val input = ByteArrayInputStream(output.toByteArray())
        val remaining = input.available()
        val error = IOException("Test session deadline/flush")
        assertSame(error, assertFailsWith<IOException> {
            HandshakeV1FrameStream(input, output).readSessionOffer { throw error }
        })
        assertEquals(remaining, input.available())
        val failing = object : OutputStream() {
            override fun write(value: Int) = Unit
            override fun flush(): Unit = throw error
        }
        assertSame(error, assertFailsWith<IOException> { HandshakeV1FrameStream(input, failing).writeSessionOffer(value) })
    }

    private fun reader(bytes: ByteArray) = HandshakeV1FrameStream(ByteArrayInputStream(bytes), ByteArrayOutputStream())

    @Test
    fun textControlFramesAreExactBoundedAndCheckOriginalBudgetOnEveryRead() {
        val scope = GroupTextTransferCodec.scope(GroupTextTransferContext("a".repeat(64), "b".repeat(64), "c".repeat(64), "d".repeat(64)))
        val frame = GroupTextTransferCodec.header(scope.size) + scope
        val raw = ByteArrayInputStream(frame + byteArrayOf(7))
        val fragmented = object : FilterInputStream(raw) {
            override fun read(bytes: ByteArray, offset: Int, length: Int) = super.read(bytes, offset, minOf(1, length))
        }
        var checks = 0
        assertContentEquals(scope, HandshakeV1FrameStream(fragmented, ByteArrayOutputStream()).readTextControl(scope.size) { checks++ })
        assertEquals(frame.size, checks)
        assertEquals(7, raw.read())
        for (size in 0 until frame.size) assertFailsWith<EOFException> {
            reader(frame.copyOf(size)).readTextControl(scope.size) {}
        }
        for (size in listOf(0, -1, Int.MAX_VALUE, scope.size + 1)) {
            val header = ByteArrayOutputStream().also {
                DataOutputStream(it).writeInt(size)
            }.toByteArray()
            val invalid = ByteArrayInputStream(header + byteArrayOf(7))
            assertFailsWith<InvalidGroupEvidenceFrameException> {
                HandshakeV1FrameStream(invalid, ByteArrayOutputStream()).readTextControl(scope.size) {}
            }
            assertEquals(7, invalid.read())
        }
        val error = IOException("test deadline")
        assertSame(error, assertFailsWith<IOException> { reader(frame).readTextControl(scope.size) { throw error } })
        val failing = object : OutputStream() {
            override fun write(value: Int) = Unit
            override fun flush(): Unit = throw error
        }
        assertSame(error, assertFailsWith<IOException> { HandshakeV1FrameStream(raw, failing).writeTextControl(scope) })
    }

    private fun assertFrameEquals(expected: ProtocolHandshakeFrame, actual: ProtocolHandshakeFrame) = assertContentEquals(
        ProtocolHandshakeFrameCodec.encode(expected), ProtocolHandshakeFrameCodec.encode(actual),
    )
}
