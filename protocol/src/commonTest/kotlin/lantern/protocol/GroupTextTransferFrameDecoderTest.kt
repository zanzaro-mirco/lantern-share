package lantern.protocol

import kotlin.test.*

class GroupTextTransferFrameDecoderTest {
    @Test
    fun negotiatedRosterControlsHaveIndependentLengthsExactBudgetsAndTerminalFailure() {
        assertFails { GroupTextTransferFrameDecoder(GroupRosterTextCodec.SCOPE_BYTES) }
        assertFails { GroupTextTransferFrameDecoder(GroupTextTransferCodec.SCOPE_BYTES, rosterText = true) }
        for (size in listOf(GroupRosterTextCodec.SCOPE_BYTES, GroupRosterTextCodec.ACK_BYTES)) {
            val payload = ByteArray(size) { (it % 127).toByte() }
            val frame = GroupTextTransferCodec.header(size) + payload
            val decoder = GroupTextTransferFrameDecoder(size, rosterText = true)
            for (index in frame.indices) {
                assertEquals(if (index < 4) 4 - index else frame.size - index, decoder.nextReadBytes)
                val read = decoder.accept(byteArrayOf(frame[index]))
                assertEquals(1, read.consumedBytes)
                if (index == frame.lastIndex) assertContentEquals(payload, read.payload) else assertNull(read.payload)
            }
            assertFails { decoder.nextReadBytes }
            val combined = GroupTextTransferFrameDecoder(size, rosterText = true).accept(frame + byteArrayOf(42))
            assertEquals(frame.size, combined.consumedBytes)
            for (cut in 0 until frame.size) {
                val truncated = GroupTextTransferFrameDecoder(size, rosterText = true)
                assertNull(truncated.accept(frame.copyOf(cut)).payload)
                assertFails { truncated.finish() }
                assertFails { truncated.nextReadBytes }
            }
            for (length in listOf(0, -1, 260, size - 1, size + 1, 65537)) {
                val bad = GroupTextTransferFrameDecoder(size, rosterText = true)
                val header = ByteArray(4) { ((length ushr ((3 - it) * 8)) and 255).toByte() }
                assertFails { bad.accept(header) }
                assertFails { bad.accept(byteArrayOf(1)) }
            }
            val cancelled = GroupTextTransferFrameDecoder(size, rosterText = true)
            cancelled.accept(frame.copyOf(5)); cancelled.close()
            assertFails { cancelled.nextReadBytes }
        }
    }

    @Test
    fun exactBudgetsFragmentationAndNoOverreadForEveryTransferFrame() {
        for (size in listOf(GroupTextTransferCodec.SCOPE_BYTES, GroupTextTransferCodec.ACK_BYTES, GroupTextCodec.MAX_BYTES)) {
            val payload = ByteArray(size) { (it % 127).toByte() }
            val frame = GroupTextTransferCodec.header(size) + payload
            val fixed = if (size == GroupTextCodec.MAX_BYTES) 0 else size
            val decoder = GroupTextTransferFrameDecoder(fixed)
            for (index in frame.indices) {
                assertEquals(if (index < 4) 4 - index else frame.size - index, decoder.nextReadBytes)
                val read = decoder.accept(byteArrayOf(frame[index]))
                assertEquals(1, read.consumedBytes)
                if (index == frame.lastIndex) assertContentEquals(payload, read.payload) else assertNull(read.payload)
            }
            assertFailsWith<IllegalStateException> { decoder.nextReadBytes }
            if (fixed != 0) {
                val together = GroupTextTransferFrameDecoder(fixed).accept(frame + byteArrayOf(42))
                assertEquals(frame.size, together.consumedBytes)
                assertContentEquals(payload, together.payload)
            }
        }
    }

    @Test
    fun malformedLengthsAreTerminalBeforeAnyPayloadIsConsumed() {
        for ((expected, length) in listOf(260 to 259, 260 to 360, 360 to 260, 0 to 0, 0 to 65537, 0 to -1)) {
            val decoder = GroupTextTransferFrameDecoder(expected)
            val header = ByteArray(4) { ((length ushr ((3 - it) * 8)) and 255).toByte() }
            assertFailsWith<IllegalArgumentException> { decoder.accept(header) }
            assertFailsWith<IllegalStateException> { decoder.accept(byteArrayOf(1)) }
        }
    }

    @Test
    fun everyTruncationAndCancellationIsTerminal() {
        val frame = GroupTextTransferCodec.header(260) + ByteArray(260)
        for (end in 0 until frame.size) {
            val decoder = GroupTextTransferFrameDecoder(260)
            assertNull(decoder.accept(frame.copyOf(end)).payload)
            assertFailsWith<IllegalArgumentException> { decoder.finish() }
            assertFailsWith<IllegalStateException> { decoder.nextReadBytes }
        }
        val cancelled = GroupTextTransferFrameDecoder()
        cancelled.accept(frame.copyOf(7))
        cancelled.close()
        assertFailsWith<IllegalStateException> { cancelled.accept(frame) }
    }
}
