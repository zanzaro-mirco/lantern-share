package lantern.protocol

/**
 * Incremental bootstrap-v1 framing for callback-based transports such as Network.framework.
 * One instance per connection; all calls must run on its serial owner queue. No reset/reuse.
 * Input chunks and retained payload are bounded; header is validated before payload allocation.
 * EOF, cancellation or any error permanently closes the decoder. The owner must close transport.
 */
class ProtocolHandshakeFrameDecoder {
    private val header = ByteArray(ProtocolHandshakeFraming.HEADER_BYTES)
    private var headerUsed = 0
    private var payload: ByteArray? = null
    private var payloadUsed = 0
    private var closed = false

    @Throws(Exception::class)
    fun accept(chunk: ByteArray): List<ProtocolHandshakeFrame> = guarded {
        require(chunk.size <= MAX_CHUNK_BYTES) { "V1 bootstrap chunk is too large" }
        val frames = mutableListOf<ProtocolHandshakeFrame>()
        var offset = 0
        while (offset < chunk.size) {
            if (payload == null) {
                val copied = minOf(header.size - headerUsed, chunk.size - offset)
                chunk.copyInto(header, headerUsed, offset, offset + copied)
                headerUsed += copied
                offset += copied
                if (headerUsed < header.size) continue
                payload = ByteArray(ProtocolHandshakeFraming.payloadBytes(header))
            }
            val current = checkNotNull(payload)
            val copied = minOf(current.size - payloadUsed, chunk.size - offset)
            chunk.copyInto(current, payloadUsed, offset, offset + copied)
            payloadUsed += copied
            offset += copied
            if (payloadUsed == current.size) {
                frames += decode(current)
                clearPending()
            }
        }
        frames
    }

    /** Call when the transport reports EOF, including after its final non-empty chunk. */
    @Throws(Exception::class)
    fun finish(): Unit = guarded {
        require(headerUsed == 0 && payload == null) { "Truncated v1 bootstrap stream" }
        close()
    }

    /** Discards incomplete bytes on local cancellation; never interprets them as a frame. */
    fun close() {
        closed = true
        clearPending()
    }

    private fun clearPending() {
        header.fill(0)
        headerUsed = 0
        payload = null
        payloadUsed = 0
    }

    private inline fun <T> guarded(block: () -> T): T {
        check(!closed) { "V1 bootstrap decoder is closed" }
        try {
            return block()
        } catch (error: Throwable) {
            close()
            throw error
        }
    }

    private fun decode(bytes: ByteArray): ProtocolHandshakeFrame = try {
        ProtocolHandshakeFrameCodec.decode(bytes)
    } catch (_: IllegalArgumentException) {
        // Do not forward parser diagnostics containing peer-controlled JSON or field values.
        throw IllegalArgumentException("Invalid v1 bootstrap frame")
    } catch (_: CharacterCodingException) {
        throw IllegalArgumentException("Invalid v1 bootstrap frame")
    }

    companion object {
        const val MAX_CHUNK_BYTES = ProtocolHandshakeFraming.HEADER_BYTES + ProtocolHandshakeFrameCodec.MAX_BYTES

        @Throws(Exception::class)
        fun encode(frame: ProtocolHandshakeFrame): ByteArray {
            val payload = ProtocolHandshakeFrameCodec.encode(frame)
            return ProtocolHandshakeFraming.header(payload.size) + payload
        }
    }
}
