package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GroupAdmissionConfirmationFrameDecoderTest {
    private val confirmation = GroupAdmissionConfirmation("a".repeat(64), "b".repeat(64), "cHJvb2Y=")
    private val second = confirmation.copy(sender = confirmation.recipient, recipient = confirmation.sender)
    private val bytes = GroupAdmissionConfirmationFrameDecoder.encode(confirmation)
    private val secondBytes = GroupAdmissionConfirmationFrameDecoder.encode(second)

    @Test
    fun everySplitSingleByteAndCoalescedFramesPreserveOrder() {
        val both = bytes + secondBytes
        for (split in 0..both.size) {
            val decoder = GroupAdmissionConfirmationFrameDecoder()
            assertEquals(listOf(confirmation, second), decoder.accept(both.copyOfRange(0, split)) +
                decoder.accept(both.copyOfRange(split, both.size)))
            decoder.finish()
        }
        val decoder = GroupAdmissionConfirmationFrameDecoder()
        assertEquals(listOf(confirmation, second), both.flatMap { decoder.accept(byteArrayOf(it)) })
        decoder.finish()
    }

    @Test
    fun partialTailAndCallerMutationCannotCorruptPendingFrame() {
        val decoder = GroupAdmissionConfirmationFrameDecoder()
        val input = bytes + secondBytes.copyOfRange(0, 10)
        assertEquals(listOf(confirmation), decoder.accept(input))
        input.fill(0)
        assertEquals(listOf(second), decoder.accept(secondBytes.copyOfRange(10, secondBytes.size)))
        assertTrue(decoder.accept(byteArrayOf()).isEmpty())
        decoder.finish()
        assertClosed(decoder)
    }

    @Test
    fun framingUsesUnsignedBigEndianAndOwnLimitNotBootstrapLimit() {
        assertContentEquals(byteArrayOf(0, 0, 4, 0), GroupAdmissionConfirmationFraming.header(1024))
        assertEquals(1024, GroupAdmissionConfirmationFraming.payloadBytes(byteArrayOf(0, 0, 4, 0)))
        for (header in listOf(byteArrayOf(0, 0, 0, 0), byteArrayOf(0, 0, 4, 1),
            byteArrayOf(0x80.toByte(), 0, 0, 0), ByteArray(4) { 0xff.toByte() })) {
            val decoder = GroupAdmissionConfirmationFrameDecoder()
            assertTrue(decoder.accept(header.copyOfRange(0, 3)).isEmpty())
            assertFailsWith<IllegalArgumentException> { decoder.accept(header.copyOfRange(3, 4)) }
            assertClosed(decoder)
        }
        for (invalid in listOf(0, -1, 1025)) assertFailsWith<IllegalArgumentException> {
            GroupAdmissionConfirmationFraming.header(invalid)
        }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionConfirmationFraming.payloadBytes(ByteArray(3)) }
    }

    @Test
    fun exactPayloadAndChunkLimitIsAcceptedButOversizeChunkCloses() {
        val json = GroupAdmissionConfirmationCodec.encode(confirmation)
        val padded = json + ByteArray(GroupAdmissionConfirmationCodec.MAX_BYTES - json.size) { ' '.code.toByte() }
        val decoder = GroupAdmissionConfirmationFrameDecoder()
        val input = GroupAdmissionConfirmationFraming.header(padded.size) + padded
        assertEquals(GroupAdmissionConfirmationFrameDecoder.MAX_CHUNK_BYTES, input.size)
        assertEquals(listOf(confirmation), decoder.accept(input))
        decoder.finish()
        val oversized = GroupAdmissionConfirmationFrameDecoder()
        assertFailsWith<IllegalArgumentException> { oversized.accept(ByteArray(GroupAdmissionConfirmationFrameDecoder.MAX_CHUNK_BYTES + 1)) }
        assertClosed(oversized)
    }

    @Test
    fun everyTruncatedHeaderOrPayloadFailsAndCannotResumeAfterEof() {
        for (end in 1 until bytes.size) {
            val decoder = GroupAdmissionConfirmationFrameDecoder()
            assertTrue(decoder.accept(bytes.copyOfRange(0, end)).isEmpty())
            assertFailsWith<IllegalArgumentException> { decoder.finish() }
            assertClosed(decoder)
        }
        val empty = GroupAdmissionConfirmationFrameDecoder()
        empty.finish()
        assertClosed(empty)
    }

    @Test
    fun badTailDoesNotReturnPartialBatchOrLeakPeerControlledDiagnostics() {
        val invalid = listOf("{\"sensitive-peer-content\":true}".encodeToByteArray(),
            byteArrayOf(0xc3.toByte(), 0x28),
            GroupAdmissionConfirmationCodec.encode(confirmation).decodeToString().replace("\"version\":1", "\"version\":0").encodeToByteArray(),
            ("[".repeat(50) + "0" + "]".repeat(50)).encodeToByteArray())
        for (payload in invalid) {
            val decoder = GroupAdmissionConfirmationFrameDecoder()
            val error = assertFailsWith<IllegalArgumentException> {
                decoder.accept(bytes + GroupAdmissionConfirmationFraming.header(payload.size) + payload)
            }
            assertEquals("Invalid group confirmation frame", error.message)
            assertNull(error.cause)
            assertClosed(decoder)
        }
    }

    @Test
    fun bootstrapAndGroupDecodersNeverAcceptEachOthersMessages() {
        val bootstrap = ProtocolHandshakeFrameDecoder.encode(ProtocolHandshakeFrame.Approve(
            ProtocolHandshakeApproval(confirmation.sender, confirmation.recipient, confirmation.signature)))
        val groupDecoder = GroupAdmissionConfirmationFrameDecoder()
        assertFailsWith<IllegalArgumentException> { groupDecoder.accept(bootstrap) }
        assertClosed(groupDecoder)
        val bootstrapDecoder = ProtocolHandshakeFrameDecoder()
        assertFailsWith<IllegalArgumentException> { bootstrapDecoder.accept(bytes) }
        assertFailsWith<IllegalStateException> { bootstrapDecoder.accept(bootstrap) }
    }

    @Test
    fun cancellationDiscardsPendingBytesAndCloseIsIdempotent() {
        val decoder = GroupAdmissionConfirmationFrameDecoder()
        assertTrue(decoder.accept(bytes.copyOfRange(0, 10)).isEmpty())
        decoder.close()
        decoder.close()
        assertClosed(decoder)
        assertContentEquals(bytes, GroupAdmissionConfirmationFrameDecoder.encode(
            GroupAdmissionConfirmationOperation.Send(confirmation.sender, confirmation.recipient, confirmation.signature)))
    }

    private fun assertClosed(decoder: GroupAdmissionConfirmationFrameDecoder) {
        assertFailsWith<IllegalStateException> { decoder.accept(bytes) }
        assertFailsWith<IllegalStateException> { decoder.accept(byteArrayOf()) }
        assertFailsWith<IllegalStateException> { decoder.finish() }
    }
}
