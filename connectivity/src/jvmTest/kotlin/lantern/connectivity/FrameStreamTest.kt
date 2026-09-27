package lantern.connectivity

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.EOFException
import lantern.protocol.Frame
import lantern.protocol.FrameType
import lantern.protocol.Wire
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class FrameStreamTest {
    @Test fun consecutiveFramesPreserveBoundaries() {
        val first = Frame(type = FrameType.HELLO, sender = "a".repeat(64), nonce = "b".repeat(64))
        val second = first.copy(nonce = "c".repeat(64))
        val output = ByteArrayOutputStream()
        val writer = FrameStream(ByteArrayInputStream(byteArrayOf()), output)
        writer.write(first)
        writer.write(second)
        val reader = FrameStream(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream())
        assertEquals(first, reader.read())
        assertEquals(second, reader.read())
        assertFailsWith<EOFException> { reader.read() }
    }

    @Test fun invalidLengthsAndTruncationAreRejectedBeforeDecoding() {
        for (length in listOf(-1, 0, Wire.MAX_FRAME + 1)) {
            assertFailsWith<IllegalArgumentException> { readerWithLength(length).read() }
        }
        assertFailsWith<EOFException> { readerWithLength(10).read() }
    }

    private fun readerWithLength(length: Int): FrameStream {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).writeInt(length)
        return FrameStream(ByteArrayInputStream(output.toByteArray()), ByteArrayOutputStream())
    }
}
