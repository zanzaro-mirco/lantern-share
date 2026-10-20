package lantern.protocol

/** Syntax only. A bounded tail after consumedBytes remains the native owner's responsibility. */
class GroupMembershipEvidenceRead internal constructor(val consumedBytes: Int, val evidence: GroupMembershipEvidence?)

/** One frame, serial caller. Length checked before allocation; completion/error/EOF/cancel terminal. */
class GroupMembershipEvidenceFrameDecoder {
    private val header = ByteArray(4)
    private var headerUsed = 0
    private var payload: ByteArray? = null
    private var payloadUsed = 0
    private var closed = false

    val nextReadBytes: Int get() {
        check(!closed) { "Membership decoder is closed" }
        return minOf(MAX_CHUNK_BYTES, payload?.let { it.size - payloadUsed } ?: header.size - headerUsed)
    }

    fun accept(chunk: ByteArray): GroupMembershipEvidenceRead {
        check(!closed) { "Membership decoder is closed" }
        try {
            require(chunk.size <= MAX_CHUNK_BYTES) { "Membership chunk is too large" }
            var offset = 0
            if (payload == null) {
                val copied = minOf(header.size - headerUsed, chunk.size)
                chunk.copyInto(header, headerUsed, 0, copied)
                headerUsed += copied
                offset += copied
                if (headerUsed < header.size) return GroupMembershipEvidenceRead(offset, null)
                payload = ByteArray(GroupMembershipEvidenceCodec.payloadBytes(header))
            }
            val current = checkNotNull(payload)
            val copied = minOf(current.size - payloadUsed, chunk.size - offset)
            chunk.copyInto(current, payloadUsed, offset, offset + copied)
            payloadUsed += copied
            offset += copied
            if (payloadUsed < current.size) return GroupMembershipEvidenceRead(offset, null)
            val evidence = decode(current)
            close()
            return GroupMembershipEvidenceRead(offset, evidence)
        } catch (failure: Throwable) {
            close()
            throw failure
        }
    }

    fun finish(): Nothing {
        check(!closed) { "Membership decoder is closed" }
        close()
        throw IllegalArgumentException("Truncated membership stream")
    }

    fun close() {
        closed = true
        header.fill(0)
        headerUsed = 0
        payload = null
        payloadUsed = 0
    }

    private fun decode(bytes: ByteArray): GroupMembershipEvidence = try {
        GroupMembershipEvidenceCodec.decode(bytes)
    } catch (_: IllegalArgumentException) {
        throw IllegalArgumentException("Invalid membership frame")
    } catch (_: CharacterCodingException) {
        throw IllegalArgumentException("Invalid membership frame")
    }

    companion object { const val MAX_CHUNK_BYTES = 4096 }
}
