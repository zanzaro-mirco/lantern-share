package lantern.protocol

import lantern.domain.GroupTrustAnchor
import lantern.domain.SessionCandidate
import lantern.domain.SessionSelection
import lantern.domain.SessionSelector

/**
 * Untrusted current-LAN observation, not history or membership authority. An unestablished
 * empty proposal is only a fallback when NEITHER participant is holding a session already.
 */
data class GroupSessionOffer(val session: SessionCandidate, val established: Boolean = true) {
    init {
        require(Wire.isFingerprint(session.groupId) && Wire.isFingerprint(session.sessionId)) {
            "Invalid session identifiers"
        }
        require(established || !session.used) { "A new proposal cannot be used" }
    }

    /** Both HELLOs must opt into this continuation; B4 alone must never consume these bytes. */
    fun sendsFirst(offers: ProtocolHandshakeOffers): Boolean {
        check(listOf(offers.local, offers.remote).all {
            GroupSessionOfferCodec.FEATURE in it.capabilities.requiredFeatures &&
                GroupSessionOfferCodec.FEATURE in it.capabilities.supportedFeatures
        }) { "Session selection not negotiated" }
        return offers.local.identity < offers.remote.identity
    }

    /** Caller must first verify membership on this exact live TLS transport. */
    fun select(expectedAnchor: GroupTrustAnchor, remote: GroupSessionOffer): SessionSelection {
        require(session.groupId == expectedAnchor.groupId && remote.session.groupId == expectedAnchor.groupId) {
            "Session group mismatch"
        }
        val held = listOf(this, remote).filter { it.established }
        val candidates = (held.ifEmpty { listOf(this, remote) }).map { it.session }
        return SessionSelector.select(expectedAnchor.groupId, candidates)
    }
}

/** Fixed, bounded optional v1 continuation. Existing frames and durable formats are unchanged. */
object GroupSessionOfferCodec {
    const val FEATURE = "group-session-selection"
    const val PAYLOAD_BYTES = 133

    fun encode(value: GroupSessionOffer): ByteArray = byteArrayOf(76, 83, 78, 1) +
        value.session.groupId.encodeToByteArray() + value.session.sessionId.encodeToByteArray() +
        byteArrayOf(((if (value.session.used) 1 else 0) + (if (value.established) 2 else 0)).toByte())

    fun decode(payload: ByteArray): GroupSessionOffer {
        require(payload.size == PAYLOAD_BYTES && payload[0] == 76.toByte() && payload[1] == 83.toByte() &&
            payload[2] == 78.toByte() && payload[3] == 1.toByte() && payload[132] in setOf<Byte>(0, 2, 3)) {
            "Invalid session offer"
        }
        // ASCII is checked without platform-dependent replacement/normalization of malformed UTF-8.
        fun fingerprint(offset: Int): String {
            val bytes = payload.copyOfRange(offset, offset + 64)
            require(bytes.all { it in 48.toByte()..57.toByte() || it in 97.toByte()..102.toByte() }) {
                "Invalid session offer"
            }
            return bytes.decodeToString()
        }
        return GroupSessionOffer(SessionCandidate(fingerprint(4), fingerprint(68), payload[132] == 3.toByte()),
            established = payload[132] != 0.toByte())
    }

    fun header(): ByteArray = byteArrayOf(0, 0, 0, PAYLOAD_BYTES.toByte())

    /** Reject all other lengths BEFORE allocation or reading payload bytes. */
    fun checkHeader(header: ByteArray) {
        require(header.contentEquals(header())) { "Invalid session frame" }
    }
}
