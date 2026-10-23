package lantern.connectivity

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.CharacterCodingException
import lantern.protocol.ProtocolHandshakeFrame
import lantern.protocol.ProtocolHandshakeFrameCodec
import lantern.protocol.ProtocolHandshakeFraming
import lantern.protocol.GroupAdmissionEvidence
import lantern.protocol.GroupAdmissionEvidenceFrameDecoder
import lantern.protocol.GroupAdmissionEvidenceFraming
import lantern.protocol.GroupMembershipEvidence
import lantern.protocol.GroupMembershipEvidenceCodec
import lantern.protocol.GroupSessionOffer
import lantern.protocol.GroupSessionOfferCodec
import lantern.protocol.GroupTextTransferCodec
import lantern.protocol.GroupTextCodec
import lantern.domain.SignedGroupText

internal class InvalidHandshakeV1FrameException : IOException("Invalid v1 bootstrap frame")
internal class InvalidGroupEvidenceFrameException : IOException("Invalid group evidence frame")

/** Selected v1 exchanges, including bounded text; never the active wire-0 FrameStream. */
internal class HandshakeV1FrameStream(private val input: InputStream, private val output: OutputStream) {
    /** Called before EVERY underlying read, so fragmented/slow input cannot reset the deadline. */
    fun read(beforeRead: () -> Unit = {}): ProtocolHandshakeFrame {
        val header = ByteArray(ProtocolHandshakeFraming.HEADER_BYTES)
        readFully(header, beforeRead)
        val length = try {
            ProtocolHandshakeFraming.payloadBytes(header)
        } catch (_: IllegalArgumentException) {
            throw InvalidHandshakeV1FrameException()
        }
        val payload = ByteArray(length)
        readFully(payload, beforeRead)
        return try {
            ProtocolHandshakeFrameCodec.decode(payload)
        } catch (_: IllegalArgumentException) {
            // Do not attach parser diagnostics containing peer-controlled content.
            throw InvalidHandshakeV1FrameException()
        } catch (_: CharacterCodingException) {
            throw InvalidHandshakeV1FrameException()
        }
    }

    fun write(frame: ProtocolHandshakeFrame) {
        val bytes = ProtocolHandshakeFrameCodec.encode(frame)
        output.write(ProtocolHandshakeFraming.header(bytes.size))
        output.write(bytes)
        output.flush()
    }

    /** Exact reads leave the next phase's bytes on the same transport, including coalesced records. */
    fun readEvidence(beforeRead: () -> Unit): GroupAdmissionEvidence {
        val decoder = GroupAdmissionEvidenceFrameDecoder()
        val buffer = ByteArray(GroupAdmissionEvidenceFrameDecoder.MAX_CHUNK_BYTES)
        try {
            while (true) {
                beforeRead()
                val count = input.read(buffer, 0, decoder.nextReadBytes)
                if (count < 0) throw EOFException("Truncated group evidence stream")
                if (count == 0) throw IOException("Group evidence stream made no progress")
                val result = decoder.accept(buffer.copyOf(count))
                check(result.consumedBytes == count) { "Evidence read crossed a frame boundary" }
                result.evidence?.let { return it }
            }
        } catch (_: IllegalArgumentException) {
            throw InvalidGroupEvidenceFrameException()
        } finally {
            decoder.close()
        }
    }

    fun writeEvidence(evidence: GroupAdmissionEvidence) {
        output.write(GroupAdmissionEvidenceFraming.encode(evidence))
        output.flush()
    }

    fun readMembership(beforeRead: () -> Unit): GroupMembershipEvidence {
        try {
            val header = ByteArray(4)
            readFully(header, beforeRead)
            val payload = ByteArray(GroupMembershipEvidenceCodec.payloadBytes(header))
            readFully(payload, beforeRead)
            return GroupMembershipEvidenceCodec.decode(payload)
        } catch (_: IllegalArgumentException) {
            throw InvalidGroupEvidenceFrameException()
        } catch (_: CharacterCodingException) {
            throw InvalidGroupEvidenceFrameException()
        }
    }

    fun writeMembership(evidence: GroupMembershipEvidence) {
        val payload = GroupMembershipEvidenceCodec.encode(evidence)
        output.write(GroupMembershipEvidenceCodec.header(payload.size))
        output.write(payload)
        output.flush()
    }

    fun readSessionOffer(beforeRead: () -> Unit): GroupSessionOffer {
        try {
            val header = ByteArray(4)
            readFully(header, beforeRead)
            GroupSessionOfferCodec.checkHeader(header)
            val payload = ByteArray(GroupSessionOfferCodec.PAYLOAD_BYTES)
            readFully(payload, beforeRead)
            return GroupSessionOfferCodec.decode(payload)
        } catch (_: IllegalArgumentException) {
            throw InvalidGroupEvidenceFrameException()
        }
    }

    fun writeSessionOffer(offer: GroupSessionOffer) {
        output.write(GroupSessionOfferCodec.header())
        output.write(GroupSessionOfferCodec.encode(offer))
        output.flush()
    }

    fun writeTextControl(payload: ByteArray) {
        output.write(GroupTextTransferCodec.header(payload.size))
        output.write(payload)
        output.flush()
    }

    fun readTextControl(expectedBytes: Int?, beforeRead: () -> Unit): ByteArray {
        try {
            val header = ByteArray(4)
            readFully(header, beforeRead)
            if (expectedBytes != null) GroupTextTransferCodec.checkFixedHeader(header, expectedBytes)
            val payload = ByteArray(GroupTextTransferCodec.payloadBytes(header))
            readFully(payload, beforeRead)
            return payload
        } catch (_: IllegalArgumentException) { throw InvalidGroupEvidenceFrameException() }
    }

    fun readGroupText(beforeRead: () -> Unit): SignedGroupText = try {
        GroupTextCodec.decode(readTextControl(null, beforeRead))
    } catch (_: IllegalArgumentException) { throw InvalidGroupEvidenceFrameException() }

    /** No follow-on data is permitted in this diagnostic protocol. EOF is not a remote ACK. */
    fun awaitMembershipEnd(beforeRead: () -> Unit) {
        beforeRead()
        if (input.read() >= 0) throw InvalidGroupEvidenceFrameException()
    }

    private fun readFully(bytes: ByteArray, beforeRead: () -> Unit) {
        var offset = 0
        while (offset < bytes.size) {
            beforeRead()
            val count = input.read(bytes, offset, bytes.size - offset)
            if (count < 0) throw EOFException("Truncated v1 bootstrap stream")
            if (count == 0) throw IOException("V1 bootstrap stream made no progress")
            offset += count
        }
    }
}
