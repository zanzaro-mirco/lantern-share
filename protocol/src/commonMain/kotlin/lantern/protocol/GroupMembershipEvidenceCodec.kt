package lantern.protocol

import lantern.domain.GroupTrustAnchor

/**
 * Optional group-membership-check/1 payload, never sniffed as bootstrap/admission/wire 0.
 * LGM + version byte, three exact 64-byte ASCII identifiers (group/founder/member), mode
 * 0 (founder, no remainder) or 1 (existing GROUP_EVIDENCE JSON as the entire remainder).
 * Framing is the existing bounded uint32 length; nested evidence retains all strict rules.
 */
object GroupMembershipEvidenceCodec {
    const val FEATURE = "group-membership-check"
    const val PREFIX_BYTES = 197
    const val MAX_BYTES = PREFIX_BYTES + GroupAdmissionEvidenceCodec.MAX_BYTES
    private val magic = byteArrayOf(76, 71, 77, 1)

    fun encode(evidence: GroupMembershipEvidence): ByteArray {
        val path = evidence.admission?.let(GroupAdmissionEvidenceCodec::encode) ?: byteArrayOf()
        return magic + evidence.anchor.groupId.encodeToByteArray() + evidence.anchor.founderId.encodeToByteArray() +
            evidence.memberIdentity.encodeToByteArray() + byteArrayOf(if (evidence.admission == null) 0 else 1) + path
    }

    fun decode(bytes: ByteArray): GroupMembershipEvidence {
        require(bytes.size in PREFIX_BYTES..MAX_BYTES && magic.indices.all { bytes[it] == magic[it] }) {
            "Invalid membership payload"
        }
        fun id(offset: Int): String = bytes.copyOfRange(offset, offset + 64).decodeToString(throwOnInvalidSequence = true)
        val anchor = GroupTrustAnchor(id(4), id(68))
        val member = id(132)
        val admission = when (bytes[196].toInt()) {
            0 -> {
                require(bytes.size == PREFIX_BYTES) { "Trailing founder membership bytes" }
                null
            }
            1 -> GroupAdmissionEvidenceCodec.decode(bytes.copyOfRange(PREFIX_BYTES, bytes.size))
            else -> throw IllegalArgumentException("Invalid membership mode")
        }
        return GroupMembershipEvidence(anchor, member, admission)
    }

    fun header(size: Int): ByteArray {
        require(size >= PREFIX_BYTES) { "Undersized membership payload" }
        return BoundedFrameLength.header(size, MAX_BYTES)
    }

    fun payloadBytes(header: ByteArray): Int = BoundedFrameLength.payloadBytes(header, MAX_BYTES).also {
        require(it >= PREFIX_BYTES) { "Undersized membership payload" }
    }
}
