package lantern.protocol

/** Bootstrap v1 only: four-byte unsigned big-endian length, bounded before buffer allocation. */
object ProtocolHandshakeFraming {
    const val HEADER_BYTES = 4

    fun header(payloadBytes: Int): ByteArray {
        require(payloadBytes in 1..ProtocolHandshakeFrameCodec.MAX_BYTES) { "Invalid v1 bootstrap length" }
        return BoundedFrameLength.header(payloadBytes, ProtocolHandshakeFrameCodec.MAX_BYTES)
    }

    fun payloadBytes(header: ByteArray): Int {
        require(header.size == HEADER_BYTES) { "Invalid v1 bootstrap header" }
        return try {
            BoundedFrameLength.payloadBytes(header, ProtocolHandshakeFrameCodec.MAX_BYTES)
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid v1 bootstrap length")
        }
    }
}
