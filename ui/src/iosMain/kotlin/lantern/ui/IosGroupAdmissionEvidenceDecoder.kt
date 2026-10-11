package lantern.ui

import lantern.protocol.GroupAdmissionEvidenceFrameDecoder

/** A tail after consumedBytes is still owned by the caller; evidence is untrusted syntax only. */
class IosGroupAdmissionEvidenceRead internal constructor(
    val consumedBytes: Int,
    val evidence: IosGroupAdmissionEvidence?,
)

/**
 * One frame on the native owner's serial queue. All framing/limits/errors stay in Kotlin.
 * The owner must retain any unconsumed tail and route it only after verification and handover.
 * This adapter does not own NWConnection, enforce a deadline, adopt roots or grant trust.
 * Completion, error, EOF and cancel are terminal: never reuse this decoder for another frame.
 */
class IosGroupAdmissionEvidenceDecoder {
    private val decoder = GroupAdmissionEvidenceFrameDecoder()

    val maximumChunkBytes: Int get() = GroupAdmissionEvidenceFrameDecoder.MAX_CHUNK_BYTES

    // A function rather than an exported property: a closed decoder throws across the Swift
    // boundary through NSError, never an unannotated getter terminating Kotlin/Native.
    @Throws(Exception::class)
    fun nextReadBytes(): Int = decoder.nextReadBytes

    @Throws(Exception::class)
    fun accept(chunk: ByteArray): IosGroupAdmissionEvidenceRead {
        val result = decoder.accept(chunk)
        return IosGroupAdmissionEvidenceRead(result.consumedBytes, result.evidence?.let(::IosGroupAdmissionEvidence))
    }

    @Throws(Exception::class)
    fun finish() = decoder.finish()

    fun cancel() = decoder.close()
}
