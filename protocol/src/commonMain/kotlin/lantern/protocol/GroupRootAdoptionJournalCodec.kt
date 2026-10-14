package lantern.protocol

/**
 * Local-only versioned recovery payload; never a network frame or an authorization decoder.
 * LGRJ + one-byte version, then six big-endian uint32 lengths and their exact bytes:
 * evidence JSON, member HELLO, issuer HELLO, member DER Base64, local and remote GROUP_CONFIRM.
 * Existing bounded codecs own all nested syntax. No private key, clock, consent boolean or
 * commit status is encoded. Future SQLite journal state/transactions remain separate.
 */
object GroupRootAdoptionJournalCodec {
    const val VERSION = 1
    const val MAX_BYTES = 5 + 6 * 4 + GroupAdmissionEvidenceCodec.MAX_BYTES +
        2 * ProtocolHandshakeHelloCodec.MAX_BYTES + GroupAdmissionCertificate.MAX_ENCODED_LENGTH +
        2 * GroupAdmissionConfirmationCodec.MAX_BYTES
    private val magic = byteArrayOf(76, 71, 82, 74) // LGRJ

    fun encode(journal: GroupRootAdoptionJournal): ByteArray {
        val fields = listOf(
            GroupAdmissionEvidenceCodec.encode(journal.evidence),
            ProtocolHandshakeHelloCodec.encode(journal.localOffer),
            ProtocolHandshakeHelloCodec.encode(journal.remoteOffer),
            journal.memberCertificate.der.encodeToByteArray(),
            GroupAdmissionConfirmationCodec.encode(journal.localConfirmation),
            GroupAdmissionConfirmationCodec.encode(journal.remoteConfirmation),
        )
        val bytes = ByteArray(5 + fields.sumOf { 4 + it.size })
        magic.copyInto(bytes)
        bytes[4] = VERSION.toByte()
        var offset = 5
        for (field in fields) {
            for (shift in 24 downTo 0 step 8) bytes[offset++] = (field.size ushr shift).toByte()
            field.copyInto(bytes, offset)
            offset += field.size
        }
        check(bytes.size <= MAX_BYTES)
        return bytes
    }

    /** Syntax/binding only. Even a well-formed, round-tripped record is entirely untrusted. */
    fun decode(bytes: ByteArray): GroupRootAdoptionJournal {
        require(bytes.size in 5..MAX_BYTES) { "Invalid adoption journal size" }
        require(magic.indices.all { bytes[it] == magic[it] }) { "Invalid adoption journal magic" }
        require(bytes[4].toInt() == VERSION) { "Unsupported adoption journal version" }
        val reader = Reader(bytes)
        val evidence = GroupAdmissionEvidenceCodec.decode(reader.field(GroupAdmissionEvidenceCodec.MAX_BYTES))
        val local = ProtocolHandshakeHelloCodec.decode(reader.field(ProtocolHandshakeHelloCodec.MAX_BYTES))
        val remote = ProtocolHandshakeHelloCodec.decode(reader.field(ProtocolHandshakeHelloCodec.MAX_BYTES))
        val certificate = GroupAdmissionCertificate(local.identity,
            reader.field(GroupAdmissionCertificate.MAX_ENCODED_LENGTH).decodeToString(throwOnInvalidSequence = true))
        val localConfirmation = GroupAdmissionConfirmationCodec.decode(reader.field(GroupAdmissionConfirmationCodec.MAX_BYTES))
        val remoteConfirmation = GroupAdmissionConfirmationCodec.decode(reader.field(GroupAdmissionConfirmationCodec.MAX_BYTES))
        require(reader.finished()) { "Trailing adoption journal bytes" }
        return GroupRootAdoptionJournal(evidence, local, remote, certificate, localConfirmation, remoteConfirmation)
    }

    private class Reader(private val bytes: ByteArray) {
        private var offset = 5

        fun field(maxBytes: Int): ByteArray {
            require(bytes.size - offset >= 4) { "Truncated adoption journal length" }
            var length = 0L
            repeat(4) { length = (length shl 8) or (bytes[offset++].toLong() and 255) }
            require(length in 1..maxBytes.toLong()) { "Invalid adoption journal field size" }
            require(length <= bytes.size - offset) { "Truncated adoption journal field" }
            val end = offset + length.toInt() // Bounded before conversion/addition/allocation.
            return bytes.copyOfRange(offset, end).also { offset = end }
        }

        fun finished(): Boolean = offset == bytes.size
    }
}
