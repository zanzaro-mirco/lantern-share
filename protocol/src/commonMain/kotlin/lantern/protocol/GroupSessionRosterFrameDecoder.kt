package lantern.protocol

class GroupSessionRosterRead internal constructor(val consumedBytes: Int, val payload: ByteArray?)

/** One exact bounded LRO/LRA frame. Never reads bytes belonging to the following phase. */
class GroupSessionRosterFrameDecoder(private val agreement: Boolean = false) {
    private val header = ByteArray(4)
    private var headerUsed = 0
    private var payload: ByteArray? = null
    private var payloadUsed = 0
    private var closed = false

    val nextReadBytes: Int get() {
        check(!closed) { "Roster decoder is closed" }
        return payload?.let { it.size - payloadUsed } ?: 4 - headerUsed
    }

    fun accept(chunk: ByteArray): GroupSessionRosterRead {
        check(!closed) { "Roster decoder is closed" }
        try {
            require(chunk.size <= 4 + GroupSessionRosterCodec.MAX_BYTES)
            var offset = 0
            if (payload == null) {
                val count = minOf(4 - headerUsed, chunk.size)
                chunk.copyInto(header, headerUsed, 0, count)
                headerUsed += count
                offset += count
                if (headerUsed < 4) return GroupSessionRosterRead(offset, null)
                payload = ByteArray(GroupSessionRosterCodec.payloadBytes(header, agreement))
            }
            val current = checkNotNull(payload)
            val count = minOf(current.size - payloadUsed, chunk.size - offset)
            chunk.copyInto(current, payloadUsed, offset, offset + count)
            payloadUsed += count
            offset += count
            if (payloadUsed < current.size) return GroupSessionRosterRead(offset, null)
            val result = current.copyOf()
            close()
            return GroupSessionRosterRead(offset, result)
        } catch (failure: Throwable) { close(); throw failure }
    }

    fun finish(): Nothing {
        check(!closed) { "Roster decoder is closed" }
        close()
        throw IllegalArgumentException("Truncated session roster")
    }

    fun close() {
        closed = true
        header.fill(0)
        payload?.fill(0)
        payload = null
    }
}
