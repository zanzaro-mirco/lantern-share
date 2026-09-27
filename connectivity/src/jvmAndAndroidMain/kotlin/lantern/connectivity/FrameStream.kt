package lantern.connectivity

import lantern.protocol.Frame
import lantern.protocol.Wire
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream

/** One reader; writes are serialized. The owning connection closes the streams. */
internal class FrameStream(input: InputStream, output: OutputStream) {
    private val input = DataInputStream(input)
    private val output = DataOutputStream(output)

    fun read(): Frame {
        val length = input.readInt()
        require(length in 1..Wire.MAX_FRAME) { "Dimensione frame non valida" }
        val bytes = ByteArray(length)
        input.readFully(bytes)
        return Wire.decode(bytes)
    }

    @Synchronized
    fun write(frame: Frame) {
        val bytes = Wire.encode(frame)
        output.writeInt(bytes.size)
        output.write(bytes)
        output.flush()
    }
}
