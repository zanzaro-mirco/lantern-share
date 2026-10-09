package lantern.protocol

/** Bytes after [consumedBytes] still belong to the caller, never to this decoder. No membership is granted. */
class GroupAdmissionEvidenceRead internal constructor(val consumedBytes: Int, val evidence: GroupAdmissionEvidence?)

/**
 * One evidence frame per attempt, used on the owner's serial queue. Payload allocation follows
 * validated length, chunks are bounded, and completion/error/EOF/cancel permanently ends the decoder.
 * A coalesced next-phase frame is not consumed: the caller must retain and route that bounded tail
 * only after proof validation and handover. This decoder neither owns nor closes the OS transport.
 */
class GroupAdmissionEvidenceFrameDecoder {
    private val header = ByteArray(GroupAdmissionEvidenceFraming.HEADER_BYTES)
    private var headerUsed = 0
    private var payload: ByteArray? = null
    private var payloadUsed = 0
    private var closed = false

    /** Maximum exact read for a blocking adapter; avoids read-ahead across phase ownership. */
    val nextReadBytes: Int get() {
        check(!closed) { "Group evidence decoder is closed" }
        return minOf(MAX_CHUNK_BYTES, payload?.let { it.size - payloadUsed } ?: (header.size - headerUsed))
    }

    @Throws(Exception::class)
    fun accept(chunk: ByteArray): GroupAdmissionEvidenceRead {
        check(!closed) { "Group evidence decoder is closed" }
        try {
            require(chunk.size <= MAX_CHUNK_BYTES) { "Group evidence chunk is too large" }
            var offset = 0
            if (payload == null) {
                val copied = minOf(header.size - headerUsed, chunk.size)
                chunk.copyInto(header, headerUsed, 0, copied)
                headerUsed += copied
                offset += copied
                if (headerUsed < header.size) return GroupAdmissionEvidenceRead(offset, null)
                payload = ByteArray(GroupAdmissionEvidenceFraming.payloadBytes(header))
            }
            val current = checkNotNull(payload)
            val copied = minOf(current.size - payloadUsed, chunk.size - offset)
            chunk.copyInto(current, payloadUsed, offset, offset + copied)
            payloadUsed += copied
            offset += copied
            if (payloadUsed < current.size) return GroupAdmissionEvidenceRead(offset, null)
            val evidence = decode(current)
            close()
            return GroupAdmissionEvidenceRead(offset, evidence)
        } catch (failure: Throwable) {
            close()
            throw failure
        }
    }

    /** EOF before the mandatory frame is complete is never success, even with no bytes received. */
    @Throws(Exception::class)
    fun finish() {
        check(!closed) { "Group evidence decoder is closed" }
        close()
        throw IllegalArgumentException("Truncated group evidence stream")
    }

    fun close() {
        closed = true
        header.fill(0)
        headerUsed = 0
        payload = null
        payloadUsed = 0
    }

    private fun decode(bytes: ByteArray): GroupAdmissionEvidence = try {
        GroupAdmissionEvidenceCodec.decode(bytes)
    } catch (_: IllegalArgumentException) {
        throw IllegalArgumentException("Invalid group evidence frame")
    } catch (_: CharacterCodingException) {
        throw IllegalArgumentException("Invalid group evidence frame")
    }

    companion object {
        const val MAX_CHUNK_BYTES = 4096
    }
}
