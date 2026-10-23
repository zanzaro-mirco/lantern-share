package lantern.protocol

class GroupSessionOfferRead internal constructor(val consumedBytes: Int, val offer: GroupSessionOffer?)

/** One optional session frame. Serial caller; exact budgets, no overread, terminal on any error. */
class GroupSessionOfferFrameDecoder {
    private val header = ByteArray(4)
    private var headerUsed = 0
    private var payload: ByteArray? = null
    private var payloadUsed = 0
    private var closed = false

    val nextReadBytes: Int get() {
        check(!closed) { "Session decoder is closed" }
        return payload?.let { it.size - payloadUsed } ?: header.size - headerUsed
    }

    fun accept(chunk: ByteArray): GroupSessionOfferRead {
        check(!closed) { "Session decoder is closed" }
        try {
            require(chunk.size <= 4 + GroupSessionOfferCodec.PAYLOAD_BYTES) { "Session chunk is too large" }
            var offset = 0
            if (payload == null) {
                val copied = minOf(header.size - headerUsed, chunk.size)
                chunk.copyInto(header, headerUsed, 0, copied)
                headerUsed += copied
                offset += copied
                if (headerUsed < header.size) return GroupSessionOfferRead(offset, null)
                GroupSessionOfferCodec.checkHeader(header)
                payload = ByteArray(GroupSessionOfferCodec.PAYLOAD_BYTES)
            }
            val current = checkNotNull(payload)
            val copied = minOf(current.size - payloadUsed, chunk.size - offset)
            chunk.copyInto(current, payloadUsed, offset, offset + copied)
            payloadUsed += copied
            offset += copied
            if (payloadUsed < current.size) return GroupSessionOfferRead(offset, null)
            val offer = GroupSessionOfferCodec.decode(current)
            close()
            return GroupSessionOfferRead(offset, offer)
        } catch (failure: Throwable) {
            close()
            throw failure
        }
    }

    fun finish(): Nothing {
        check(!closed) { "Session decoder is closed" }
        close()
        throw IllegalArgumentException("Truncated session stream")
    }

    fun close() {
        closed = true
        header.fill(0)
        payload?.fill(0)
        payload = null
    }
}
