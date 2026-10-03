package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProtocolHandshakeFrameDecoderTest {
    private val hello = ProtocolHandshakeFrame.Hello(ProtocolHandshakeParticipant(
        "a".repeat(64), "1".repeat(64), ProtocolCapabilities(1, setOf("text"), emptySet()),
    ))
    private val approval = ProtocolHandshakeFrame.Approve(ProtocolHandshakeApproval(
        "b".repeat(64), "a".repeat(64), "cHJvb2Y=",
    ))
    private val helloBytes = ProtocolHandshakeFrameDecoder.encode(hello)
    private val approvalBytes = ProtocolHandshakeFrameDecoder.encode(approval)

    @Test
    fun everySplitAndSingleByteDeliveryPreserveHeaderPayloadAndFrameOrder() {
        val bytes = helloBytes + approvalBytes
        for (split in 0..bytes.size) {
            val decoder = ProtocolHandshakeFrameDecoder()
            val frames = decoder.accept(bytes.copyOfRange(0, split)) + decoder.accept(bytes.copyOfRange(split, bytes.size))
            assertFrames(listOf(hello, approval), frames)
            decoder.finish()
        }
        val decoder = ProtocolHandshakeFrameDecoder()
        assertFrames(listOf(hello, approval), bytes.flatMap { decoder.accept(byteArrayOf(it)) })
        decoder.finish()
    }

    @Test
    fun completeFramesAndPendingTailSurviveTheNextChunk() {
        val decoder = ProtocolHandshakeFrameDecoder()
        assertFrames(listOf(hello), decoder.accept(helloBytes + approvalBytes.copyOfRange(0, 5)))
        assertFrames(listOf(approval), decoder.accept(approvalBytes.copyOfRange(5, approvalBytes.size)))
        assertTrue(decoder.accept(byteArrayOf()).isEmpty())
        decoder.finish()
        assertClosed(decoder)
    }

    @Test
    fun inputBuffersAreCopiedAndNotRetainedByReference() {
        val decoder = ProtocolHandshakeFrameDecoder()
        val prefix = helloBytes.copyOfRange(0, 20)
        assertTrue(decoder.accept(prefix).isEmpty())
        prefix.fill(0)
        assertFrames(listOf(hello), decoder.accept(helloBytes.copyOfRange(20, helloBytes.size)))
        decoder.finish()
    }

    @Test
    fun unsignedInvalidLengthsAndOversizeChunksPermanentlyCloseDecoder() {
        val headers = listOf(
            byteArrayOf(0, 0, 0, 0), byteArrayOf(0, 0, 20, 1),
            byteArrayOf(0x80.toByte(), 0, 0, 0), ByteArray(4) { 0xff.toByte() },
        )
        for (header in headers) {
            val decoder = ProtocolHandshakeFrameDecoder()
            assertTrue(decoder.accept(header.copyOfRange(0, 3)).isEmpty())
            assertFailsWith<IllegalArgumentException> { decoder.accept(header.copyOfRange(3, 4)) }
            assertClosed(decoder)
        }
        val decoder = ProtocolHandshakeFrameDecoder()
        assertFailsWith<IllegalArgumentException> { decoder.accept(ByteArray(ProtocolHandshakeFrameDecoder.MAX_CHUNK_BYTES + 1)) }
        assertClosed(decoder)
    }

    @Test
    fun maximumPayloadAndChunkAreAcceptedWithoutAnotherHeader() {
        val json = ProtocolHandshakeFrameCodec.encode(hello)
        val payload = json + ByteArray(ProtocolHandshakeFrameCodec.MAX_BYTES - json.size) { ' '.code.toByte() }
        val bytes = ProtocolHandshakeFraming.header(payload.size) + payload
        assertEquals(ProtocolHandshakeFrameDecoder.MAX_CHUNK_BYTES, bytes.size)
        val decoder = ProtocolHandshakeFrameDecoder()
        assertFrames(listOf(hello), decoder.accept(bytes))
        decoder.finish()
    }

    @Test
    fun eofAtEveryIncompleteHeaderOrPayloadIsRejectedAndCannotBeResumed() {
        for (end in 1 until helloBytes.size) {
            val decoder = ProtocolHandshakeFrameDecoder()
            assertTrue(decoder.accept(helloBytes.copyOfRange(0, end)).isEmpty())
            assertFailsWith<IllegalArgumentException> { decoder.finish() }
            assertClosed(decoder)
        }
        val empty = ProtocolHandshakeFrameDecoder()
        empty.finish()
        assertClosed(empty)
    }

    @Test
    fun badJsonUtf8VersionAndNestingDoNotLeakInputOrResumeAfterFailure() {
        val invalid = listOf(
            "{\"sensitive-peer-content\":true}".encodeToByteArray(),
            byteArrayOf(0xc3.toByte(), 0x28),
            ProtocolHandshakeFrameCodec.encode(hello).decodeToString().replace("\"version\":1", "\"version\":0").encodeToByteArray(),
            ("[".repeat(1000) + "0" + "]".repeat(1000)).encodeToByteArray(),
        )
        for (payload in invalid) {
            val decoder = ProtocolHandshakeFrameDecoder()
            // A malformed tail must not return a partial batch as if the callback succeeded.
            val error = assertFailsWith<IllegalArgumentException> {
                decoder.accept(helloBytes + ProtocolHandshakeFraming.header(payload.size) + payload)
            }
            assertEquals("Invalid v1 bootstrap frame", error.message)
            assertNull(error.cause)
            assertClosed(decoder)
        }
    }

    @Test
    fun cancellationDiscardsPartialFrameAndCloseIsIdempotent() {
        val decoder = ProtocolHandshakeFrameDecoder()
        assertTrue(decoder.accept(helloBytes.copyOfRange(0, 10)).isEmpty())
        decoder.close()
        decoder.close()
        assertClosed(decoder)
    }

    private fun assertClosed(decoder: ProtocolHandshakeFrameDecoder) {
        assertFailsWith<IllegalStateException> { decoder.accept(helloBytes) }
        assertFailsWith<IllegalStateException> { decoder.accept(byteArrayOf()) }
        assertFailsWith<IllegalStateException> { decoder.finish() }
    }

    private fun assertFrames(expected: List<ProtocolHandshakeFrame>, actual: List<ProtocolHandshakeFrame>) {
        assertEquals(expected.size, actual.size)
        expected.zip(actual).forEach { (left, right) ->
            assertContentEquals(ProtocolHandshakeFrameCodec.encode(left), ProtocolHandshakeFrameCodec.encode(right))
        }
    }
}
