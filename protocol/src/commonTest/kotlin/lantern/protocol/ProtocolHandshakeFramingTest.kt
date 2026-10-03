package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ProtocolHandshakeFramingTest {
    @Test
    fun exactBigEndianVectorsAndEveryAllowedLengthRoundTrip() {
        assertContentEquals(byteArrayOf(0, 0, 0, 1), ProtocolHandshakeFraming.header(1))
        assertContentEquals(byteArrayOf(0, 0, 1, 0), ProtocolHandshakeFraming.header(256))
        assertContentEquals(byteArrayOf(0, 0, 20, 0), ProtocolHandshakeFraming.header(5120))
        for (size in 1..ProtocolHandshakeFrameCodec.MAX_BYTES) {
            assertEquals(size, ProtocolHandshakeFraming.payloadBytes(ProtocolHandshakeFraming.header(size)))
        }
    }

    @Test
    fun zeroOversizeUnsignedOverflowAndNonFourByteHeadersAreRejected() {
        for (size in listOf(Int.MIN_VALUE, -1, 0, ProtocolHandshakeFrameCodec.MAX_BYTES + 1, Int.MAX_VALUE)) {
            assertFailsWith<IllegalArgumentException> { ProtocolHandshakeFraming.header(size) }
        }
        val invalid = listOf(
            byteArrayOf(), byteArrayOf(1), byteArrayOf(0, 0, 1), byteArrayOf(0, 0, 0, 0, 1),
            byteArrayOf(0, 0, 0, 0), byteArrayOf(0, 0, 20, 1),
            byteArrayOf(0x80.toByte(), 0, 0, 0), ByteArray(4) { 0xff.toByte() },
        )
        for (header in invalid) assertFailsWith<IllegalArgumentException> { ProtocolHandshakeFraming.payloadBytes(header) }
    }
}
