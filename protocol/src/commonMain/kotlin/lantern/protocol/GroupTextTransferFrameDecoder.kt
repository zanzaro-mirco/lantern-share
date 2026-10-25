package lantern.protocol

class GroupTextTransferRead internal constructor(val consumedBytes: Int, val payload: ByteArray?)

/** One bounded control frame, exact native read budgets, terminal on completion/error/cancel. */
class GroupTextTransferFrameDecoder(private val expectedBytes: Int = 0, private val rosterText: Boolean = false) {
    init {
        val scopeBytes = if (rosterText) GroupRosterTextCodec.SCOPE_BYTES else GroupTextTransferCodec.SCOPE_BYTES
        require(expectedBytes in setOf(0, scopeBytes, GroupTextTransferCodec.ACK_BYTES))
    }
    private val header = ByteArray(4)
    private var headerUsed = 0
    private var payload: ByteArray? = null
    private var payloadUsed = 0
    private var closed = false

    val nextReadBytes: Int get() {
        check(!closed) { "Text decoder is closed" }
        return payload?.let { it.size - payloadUsed } ?: header.size - headerUsed
    }

    fun accept(chunk: ByteArray): GroupTextTransferRead {
        check(!closed) { "Text decoder is closed" }
        try {
            require(chunk.size <= 4 + GroupTextCodec.MAX_BYTES)
            var offset = 0
            if (payload == null) {
                val count = minOf(4 - headerUsed, chunk.size)
                chunk.copyInto(header, headerUsed, 0, count)
                headerUsed += count
                offset += count
                if (headerUsed < 4) return GroupTextTransferRead(offset, null)
                if (expectedBytes != 0) {
                    if (rosterText) GroupRosterTextCodec.checkFixedHeader(header, expectedBytes)
                    else GroupTextTransferCodec.checkFixedHeader(header, expectedBytes)
                }
                payload = ByteArray(GroupTextTransferCodec.payloadBytes(header))
            }
            val current = checkNotNull(payload)
            val count = minOf(current.size - payloadUsed, chunk.size - offset)
            chunk.copyInto(current, payloadUsed, offset, offset + count)
            payloadUsed += count
            offset += count
            if (payloadUsed < current.size) return GroupTextTransferRead(offset, null)
            val result = current.copyOf()
            close()
            return GroupTextTransferRead(offset, result)
        } catch (failure: Throwable) {
            close()
            throw failure
        }
    }

    fun finish(): Nothing {
        check(!closed) { "Text decoder is closed" }
        close()
        throw IllegalArgumentException("Truncated text transfer")
    }

    fun close() {
        closed = true
        header.fill(0)
        payload?.fill(0)
        payload = null
    }
}
