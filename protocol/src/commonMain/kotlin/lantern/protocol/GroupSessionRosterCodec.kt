package lantern.protocol

import lantern.domain.GroupTrustAnchor

/** Optional LGM -> LSN -> LRO -> exact LRA. Existing B5/LTX and durable formats are unchanged. */
object GroupSessionRosterCodec {
    const val FEATURE = "group-session-roster"
    const val MAX_BYTES = 4 * 1024 * 1024
    const val PREFIX_BYTES = 201
    const val AGREEMENT_BYTES = 196
    const val MIN_JOIN_BYTES = 4 + 4 * 64 + 3 * 4 + GroupMembershipEvidenceCodec.PREFIX_BYTES + 2
    const val MAX_JOIN_BYTES = 4 + 4 * 64 + 3 * 4 + GroupAdmissionCertificate.MAX_ENCODED_LENGTH +
        GroupMembershipEvidenceCodec.MAX_BYTES + 256
    private val rosterMagic = byteArrayOf(76, 82, 79, 1)
    private val joinMagic = byteArrayOf(76, 83, 74, 1)

    fun sendsFirst(offers: ProtocolHandshakeOffers): Boolean {
        check(listOf(offers.local, offers.remote).all { participant ->
            listOf(FEATURE, GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE).all {
                it in participant.capabilities.requiredFeatures && it in participant.capabilities.supportedFeatures
            }
        }) { "Session roster not negotiated" }
        return offers.local.identity < offers.remote.identity
    }

    fun signingBytes(sessionId: String, membership: GroupMembershipEvidence, certificate: GroupAdmissionCertificate): ByteArray {
        require(Wire.isFingerprint(sessionId) && certificate.identity == membership.memberIdentity)
        return pack(listOf(joinMagic, membership.anchor.groupId.encodeToByteArray(), membership.anchor.founderId.encodeToByteArray(),
            sessionId.encodeToByteArray(), membership.memberIdentity.encodeToByteArray(), field(certificate.der.encodeToByteArray()),
            field(GroupMembershipEvidenceCodec.encode(membership))), MAX_JOIN_BYTES)
    }

    fun encodeJoin(entry: GroupSessionJoin): ByteArray = pack(listOf(
        signingBytes(entry.sessionId, entry.membership, entry.certificate), field(entry.signature.encodeToByteArray())), MAX_JOIN_BYTES)

    fun decodeJoin(payload: ByteArray): GroupSessionJoin {
        require(payload.size in MIN_JOIN_BYTES..MAX_JOIN_BYTES)
        val reader = Reader(payload)
        require(reader.take(4).contentEquals(joinMagic))
        val anchor = GroupTrustAnchor(reader.id(), reader.id())
        val session = reader.id()
        val member = reader.id()
        val certificate = GroupAdmissionCertificate(member, reader.field(GroupAdmissionCertificate.MAX_ENCODED_LENGTH).decodeToString(throwOnInvalidSequence = true))
        val membership = GroupMembershipEvidenceCodec.decode(reader.field(GroupMembershipEvidenceCodec.MAX_BYTES))
        require(membership.anchor == anchor && membership.memberIdentity == member)
        val signature = reader.field(256).decodeToString(throwOnInvalidSequence = true)
        reader.end()
        return GroupSessionJoin(session, membership, certificate, signature)
    }

    fun encode(roster: GroupSessionRoster): ByteArray {
        val entries = roster.entries
        // Transport budget only: fail rather than truncate participants. No product member limit.
        require(entries.size <= (MAX_BYTES - PREFIX_BYTES) / (4 + MIN_JOIN_BYTES))
        val parts = mutableListOf(rosterMagic, roster.anchor.groupId.encodeToByteArray(), roster.anchor.founderId.encodeToByteArray(),
            roster.sessionId.encodeToByteArray(), byteArrayOf(if (roster.retainedSnapshot) 1 else 0), integer(entries.size))
        var total = PREFIX_BYTES
        for (entry in entries) {
            val bytes = encodeJoin(entry)
            require(total <= MAX_BYTES - 4 - bytes.size) { "Roster exceeds exchange budget" }
            total += 4 + bytes.size
            parts += field(bytes)
        }
        return pack(parts, MAX_BYTES)
    }

    fun decode(payload: ByteArray): GroupSessionRoster {
        require(payload.size in PREFIX_BYTES..MAX_BYTES)
        val reader = Reader(payload)
        require(reader.take(4).contentEquals(rosterMagic))
        val anchor = GroupTrustAnchor(reader.id(), reader.id())
        val session = reader.id()
        val retained = reader.take(1).single().also { require(it == 0.toByte() || it == 1.toByte()) } == 1.toByte()
        val count = reader.number((payload.size - PREFIX_BYTES) / (4 + MIN_JOIN_BYTES))
        require(count > 0)
        val entries = List(count) { decodeJoin(reader.field(MAX_JOIN_BYTES)) }
        reader.end()
        return GroupSessionRoster(anchor, session, entries, retained)
    }

    fun agreement(roster: GroupSessionRoster, digest: String): ByteArray {
        require(Wire.isFingerprint(digest))
        return byteArrayOf(76, 82, 65, 1) + (roster.anchor.groupId + roster.sessionId + digest).encodeToByteArray()
    }

    fun header(payloadBytes: Int): ByteArray = BoundedFrameLength.header(payloadBytes, MAX_BYTES)
    fun payloadBytes(header: ByteArray, agreement: Boolean = false): Int = BoundedFrameLength.payloadBytes(header, MAX_BYTES).also {
        if (agreement) require(it == AGREEMENT_BYTES) else require(it >= PREFIX_BYTES)
    }

    private fun integer(value: Int) = ByteArray(4) { (value ushr ((3 - it) * 8)).toByte() }
    private fun field(bytes: ByteArray) = integer(bytes.size) + bytes
    private fun pack(parts: List<ByteArray>, maximum: Int): ByteArray {
        val size = parts.sumOf { it.size.toLong() }
        require(size <= maximum)
        val result = ByteArray(size.toInt())
        var offset = 0
        for (part in parts) {
            part.copyInto(result, offset)
            offset += part.size
        }
        return result
    }

    private class Reader(private val bytes: ByteArray) {
        private var offset = 0
        fun take(count: Int): ByteArray {
            require(count >= 0 && count <= bytes.size - offset) { "Truncated roster" }
            return bytes.copyOfRange(offset, offset + count).also { offset += count }
        }
        fun number(maximum: Int): Int {
            var value = 0L
            for (byte in take(4)) value = (value shl 8) or (byte.toLong() and 255)
            require(value <= maximum.toLong()) { "Invalid roster length/count" }
            return value.toInt()
        }
        fun id(): String = take(64).decodeToString(throwOnInvalidSequence = true).also { require(Wire.isFingerprint(it)) }
        fun field(maximum: Int): ByteArray = take(number(minOf(maximum, bytes.size - offset - 4)))
        fun end() { require(offset == bytes.size) { "Trailing roster bytes" } }
    }
}
