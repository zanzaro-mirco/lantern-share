package lantern.protocol

/** Shared length primitive only; each protocol keeps its own limit and decoder lifecycle. */
internal object BoundedFrameLength {
    const val HEADER_BYTES = 4

    fun header(payloadBytes: Int, maxBytes: Int): ByteArray {
        require(payloadBytes in 1..maxBytes) { "Invalid frame length" }
        return ByteArray(HEADER_BYTES) { index -> (payloadBytes ushr (8 * (HEADER_BYTES - index - 1))).toByte() }
    }

    fun payloadBytes(header: ByteArray, maxBytes: Int): Int {
        require(header.size == HEADER_BYTES) { "Invalid frame header" }
        var length = 0L
        for (byte in header) length = (length shl 8) or (byte.toLong() and 0xff)
        require(length in 1..maxBytes.toLong()) { "Invalid frame length" }
        return length.toInt()
    }
}
