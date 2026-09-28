package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class WireFramingTest {
    private val sender = "a".repeat(64)

    @Test
    fun fragmentedAndConsecutiveFramesAreDecoded() {
        val first = Frame(type = FrameType.HELLO, sender = sender, nonce = "b".repeat(64))
        val second = Frame(type = FrameType.ACK, sender = sender, id = "12345678-1234-1234-1234-123456789abc")
        val bytes = WireFrameDecoder.encode(first) + WireFrameDecoder.encode(second)
        val decoder = WireFrameDecoder()

        assertEquals(emptyList(), decoder.accept(bytes.copyOfRange(0, 3)))
        assertEquals(listOf(first, second), decoder.accept(bytes.copyOfRange(3, bytes.size)))
    }

    @Test
    fun invalidLengthClearsPendingState() {
        val decoder = WireFrameDecoder()
        assertFailsWith<IllegalArgumentException> { decoder.accept(byteArrayOf(0, 0, 0, 0)) }

        val valid = Frame(type = FrameType.HELLO, sender = sender, nonce = "c".repeat(64))
        assertEquals(listOf(valid), decoder.accept(WireFrameDecoder.encode(valid)))
    }

    @Test
    fun invalidPayloadIsRejectedBySharedWireContract() {
        val invalid = "{}".encodeToByteArray()
        val framed = byteArrayOf(0, 0, 0, invalid.size.toByte()) + invalid
        assertFailsWith<Exception> { WireFrameDecoder().accept(framed) }
    }
}
