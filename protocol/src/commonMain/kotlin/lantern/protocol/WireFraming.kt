package lantern.protocol

/** Incremental wire-v0 framing shared by stream transports. */
class WireFrameDecoder {
    private var pending = ByteArray(0)

    fun accept(chunk: ByteArray): List<Frame> {
        require(chunk.size <= Wire.MAX_FRAME + HEADER_BYTES) { "Blocco di trasporto troppo grande" }
        if (chunk.isEmpty()) return emptyList()

        val bytes = pending + chunk
        val frames = mutableListOf<Frame>()
        var offset = 0
        try {
            while (bytes.size - offset >= HEADER_BYTES) {
                val length = readLength(bytes, offset)
                require(length in 1..Wire.MAX_FRAME) { "Lunghezza frame non valida" }
                if (bytes.size - offset - HEADER_BYTES < length) break
                val start = offset + HEADER_BYTES
                frames += Wire.decode(bytes.copyOfRange(start, start + length))
                offset = start + length
            }
            pending = bytes.copyOfRange(offset, bytes.size)
            require(pending.size <= Wire.MAX_FRAME + HEADER_BYTES) { "Frame incompleto troppo grande" }
            return frames
        } catch (error: Exception) {
            pending = ByteArray(0)
            throw error
        }
    }

    fun reset() {
        pending = ByteArray(0)
    }

    companion object {
        const val HEADER_BYTES = 4

        fun encode(frame: Frame): ByteArray {
            val payload = Wire.encode(frame)
            val size = payload.size
            return byteArrayOf(
                (size ushr 24).toByte(),
                (size ushr 16).toByte(),
                (size ushr 8).toByte(),
                size.toByte(),
            ) + payload
        }

        private fun readLength(bytes: ByteArray, offset: Int): Int =
            ((bytes[offset].toInt() and 0xff) shl 24) or
                ((bytes[offset + 1].toInt() and 0xff) shl 16) or
                ((bytes[offset + 2].toInt() and 0xff) shl 8) or
                (bytes[offset + 3].toInt() and 0xff)
    }
}
