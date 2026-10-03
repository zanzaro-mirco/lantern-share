package lantern.protocol

/** Bootstrap v1 only: four-byte unsigned big-endian length, bounded before buffer allocation. */
object ProtocolHandshakeFraming {
    const val HEADER_BYTES = 4

    fun header(payloadBytes: Int): ByteArray {
        require(payloadBytes in 1..ProtocolHandshakeFrameCodec.MAX_BYTES) { "Invalid v1 bootstrap length" }
        return ByteArray(HEADER_BYTES) { index -> (payloadBytes ushr (8 * (HEADER_BYTES - index - 1))).toByte() }
    }

    fun payloadBytes(header: ByteArray): Int {
        require(header.size == HEADER_BYTES) { "Invalid v1 bootstrap header" }
        var length = 0L
        for (byte in header) length = (length shl 8) or (byte.toLong() and 0xff)
        require(length in 1..ProtocolHandshakeFrameCodec.MAX_BYTES.toLong()) { "Invalid v1 bootstrap length" }
        return length.toInt()
    }
}
