package lantern.protocol

import kotlin.test.*

class GroupSessionRosterFrameDecoderTest {
    @Test
    fun exactFragmentedReadsTerminalStateAndFollowingBytesAreNotConsumed() {
        for (agreement in listOf(false, true)) {
            val payload = ByteArray(if (agreement) GroupSessionRosterCodec.AGREEMENT_BYTES else GroupSessionRosterCodec.PREFIX_BYTES) { 7 }
            val frame = GroupSessionRosterCodec.header(payload.size) + payload
            val decoder = GroupSessionRosterFrameDecoder(agreement)
            assertEquals(4, decoder.nextReadBytes)
            for (index in frame.indices) {
                val read = decoder.accept(frame.copyOfRange(index, index + 1))
                assertEquals(1, read.consumedBytes)
                if (index < frame.lastIndex) assertNull(read.payload) else assertContentEquals(payload, read.payload)
            }
            assertFails { decoder.nextReadBytes }
            assertFails { decoder.accept(byteArrayOf()) }
            val combined = GroupSessionRosterFrameDecoder(agreement).accept(frame + byteArrayOf(99))
            assertEquals(frame.size, combined.consumedBytes)
            assertContentEquals(payload, combined.payload)
        }
    }

    @Test
    fun allTruncationsAndInvalidHeadersFailClosedBeforePayloadAllocation() {
        for (agreement in listOf(false, true)) {
            val length = if (agreement) GroupSessionRosterCodec.AGREEMENT_BYTES else GroupSessionRosterCodec.PREFIX_BYTES
            val frame = GroupSessionRosterCodec.header(length) + ByteArray(length)
            for (cut in frame.indices) {
                val decoder = GroupSessionRosterFrameDecoder(agreement)
                assertNull(decoder.accept(frame.copyOf(cut)).payload)
                assertFails { decoder.finish() }
                assertFails { decoder.nextReadBytes }
            }
            for (invalid in listOf(0, length - 1, GroupSessionRosterCodec.MAX_BYTES + 1, -1) +
                (if (agreement) listOf(length + 1) else emptyList())) {
                val decoder = GroupSessionRosterFrameDecoder(agreement)
                val header = ByteArray(4) { (invalid ushr ((3 - it) * 8)).toByte() }
                assertFails { decoder.accept(header) }
                assertFails { decoder.nextReadBytes }
            }
            val cancelled = GroupSessionRosterFrameDecoder(agreement)
            cancelled.close()
            assertFails { cancelled.accept(frame) }
        }
        val maximum = GroupSessionRosterFrameDecoder()
        assertNull(maximum.accept(GroupSessionRosterCodec.header(GroupSessionRosterCodec.MAX_BYTES)).payload)
        assertEquals(GroupSessionRosterCodec.MAX_BYTES, maximum.nextReadBytes)
        maximum.close()
    }
}
