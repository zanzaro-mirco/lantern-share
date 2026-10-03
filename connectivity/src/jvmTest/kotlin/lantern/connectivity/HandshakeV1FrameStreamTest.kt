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

    private fun framed(payload: ByteArray): ByteArray = ByteArrayOutputStream().also { bytes ->
        DataOutputStream(bytes).apply { writeInt(payload.size); write(payload) }
    }.toByteArray()

    private fun reader(bytes: ByteArray) = HandshakeV1FrameStream(ByteArrayInputStream(bytes), ByteArrayOutputStream())

    private fun assertFrameEquals(expected: ProtocolHandshakeFrame, actual: ProtocolHandshakeFrame) = assertContentEquals(
        ProtocolHandshakeFrameCodec.encode(expected), ProtocolHandshakeFrameCodec.encode(actual),
    )
}
