package lantern.protocol

/** Dedicated evidence limit, not the bootstrap or confirmation limit. Validate before allocating a payload. */
object GroupAdmissionEvidenceFraming {
    const val HEADER_BYTES = BoundedFrameLength.HEADER_BYTES

    @Throws(Exception::class)
    fun header(payloadBytes: Int): ByteArray = BoundedFrameLength.header(payloadBytes, GroupAdmissionEvidenceCodec.MAX_BYTES)

    @Throws(Exception::class)
    fun payloadBytes(header: ByteArray): Int = BoundedFrameLength.payloadBytes(header, GroupAdmissionEvidenceCodec.MAX_BYTES)

    /** Encoding only: no transport write, ownership transfer, signature verification or acknowledgment. */
    @Throws(Exception::class)
    fun encode(evidence: GroupAdmissionEvidence): ByteArray {
        val payload = GroupAdmissionEvidenceCodec.encode(evidence)
        return header(payload.size) + payload
    }
}
