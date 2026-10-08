package lantern.protocol

/** Four-byte unsigned big-endian framing, dedicated limit; no bootstrap dispatch or fallback. */
object GroupAdmissionConfirmationFraming {
    const val HEADER_BYTES = BoundedFrameLength.HEADER_BYTES

    fun header(payloadBytes: Int): ByteArray = BoundedFrameLength.header(payloadBytes, GroupAdmissionConfirmationCodec.MAX_BYTES)
    fun payloadBytes(header: ByteArray): Int = BoundedFrameLength.payloadBytes(header, GroupAdmissionConfirmationCodec.MAX_BYTES)
}

/**
 * One serial-queue-owned decoder per connection. Bounds chunks and validates length before
 * allocating payload. EOF/cancellation/error permanently closes it; never reset or reuse.
 * This component does not authenticate, confirm an attempt or close the OS transport itself.
 */
class GroupAdmissionConfirmationFrameDecoder {
    private val header = ByteArray(GroupAdmissionConfirmationFraming.HEADER_BYTES)
    private var headerUsed = 0
    private var payload: ByteArray? = null
    private var payloadUsed = 0
    private var closed = false

    @Throws(Exception::class)
    fun accept(chunk: ByteArray): List<GroupAdmissionConfirmation> = guarded {
        require(chunk.size <= MAX_CHUNK_BYTES) { "Group confirmation chunk is too large" }
        val confirmations = mutableListOf<GroupAdmissionConfirmation>()
        var offset = 0
        while (offset < chunk.size) {
            if (payload == null) {
                val copied = minOf(header.size - headerUsed, chunk.size - offset)
                chunk.copyInto(header, headerUsed, offset, offset + copied)
                headerUsed += copied
                offset += copied
                if (headerUsed < header.size) continue
                payload = ByteArray(GroupAdmissionConfirmationFraming.payloadBytes(header))
            }
            val current = checkNotNull(payload)
            val copied = minOf(current.size - payloadUsed, chunk.size - offset)
            chunk.copyInto(current, payloadUsed, offset, offset + copied)
            payloadUsed += copied
            offset += copied
            if (payloadUsed == current.size) {
                confirmations += decode(current)
                clearPending()
            }
        }
        confirmations
    }

    @Throws(Exception::class)
    fun finish(): Unit = guarded {
        require(headerUsed == 0 && payload == null) { "Truncated group confirmation stream" }
        close()
    }

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
        check(!closed) { "Group confirmation decoder is closed" }
        try {
            return block()
        } catch (failure: Throwable) {
            close()
            throw failure
        }
    }

    private fun decode(bytes: ByteArray): GroupAdmissionConfirmation = try {
        GroupAdmissionConfirmationCodec.decode(bytes)
    } catch (_: IllegalArgumentException) {
        // Parser diagnostics can contain peer-controlled content; never forward them to the owner.
        throw IllegalArgumentException("Invalid group confirmation frame")
    } catch (_: CharacterCodingException) {
        throw IllegalArgumentException("Invalid group confirmation frame")
    }

    companion object {
        const val MAX_CHUNK_BYTES = GroupAdmissionConfirmationFraming.HEADER_BYTES + GroupAdmissionConfirmationCodec.MAX_BYTES

        @Throws(Exception::class)
        fun encode(confirmation: GroupAdmissionConfirmation): ByteArray {
            val payload = GroupAdmissionConfirmationCodec.encode(confirmation)
            return GroupAdmissionConfirmationFraming.header(payload.size) + payload
        }

        @Throws(Exception::class)
        fun encode(request: GroupAdmissionConfirmationOperation.Send): ByteArray {
            val payload = GroupAdmissionConfirmationCodec.encode(request)
            return GroupAdmissionConfirmationFraming.header(payload.size) + payload
        }
    }
}
