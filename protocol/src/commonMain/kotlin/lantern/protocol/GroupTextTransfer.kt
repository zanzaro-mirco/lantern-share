package lantern.protocol

import lantern.domain.SignedGroupText

/** Initial direct transfer scope; not a reusable permission or a multiparty roster protocol. */
data class GroupTextTransferContext(val groupId: String, val sessionId: String, val senderId: String, val recipientId: String) {
    init {
        require(listOf(groupId, sessionId, senderId, recipientId).all(Wire::isFingerprint))
        require(senderId != recipientId)
    }
    val recipients: Set<String> get() = setOf(senderId, recipientId)

    fun checkMessage(message: SignedGroupText) {
        val c = message.content
        require(c.groupId == groupId && c.sessionId == sessionId && c.authorId == senderId && c.recipients.toSet() == recipients) {
            "Group text transfer context mismatch"
        }
    }
}

/** Opt-in only: LGM -> LSN -> matching scope -> one signed text -> exact post-commit ACK. */
object GroupTextTransferCodec {
    const val FEATURE = "group-text-transfer"
    const val SENDER_FEATURE = "group-text-sender"
    const val RECEIVER_FEATURE = "group-text-receiver"
    const val SCOPE_BYTES = 260
    const val ACK_BYTES = 360

    fun sendsFirst(offers: ProtocolHandshakeOffers, sending: Boolean): Boolean {
        for (participant in listOf(offers.local, offers.remote)) {
            check(listOf(FEATURE, GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE).all {
                it in participant.capabilities.supportedFeatures && it in participant.capabilities.requiredFeatures
            }) { "Group text transfer not negotiated" }
        }
        fun checkRole(participant: ProtocolHandshakeParticipant, sender: Boolean) {
            val features = participant.capabilities.supportedFeatures
            check((SENDER_FEATURE in features) == sender && (RECEIVER_FEATURE in features) != sender) {
                "Group text transfer role mismatch"
            }
        }
        checkRole(offers.local, sending)
        checkRole(offers.remote, !sending)
        return offers.local.identity < offers.remote.identity
    }

    fun scope(context: GroupTextTransferContext): ByteArray = byteArrayOf(76, 84, 88, 1) +
        (context.groupId + context.sessionId + context.senderId + context.recipientId).encodeToByteArray()

    fun acknowledgement(context: GroupTextTransferContext, message: SignedGroupText, envelopeDigest: String): ByteArray {
        context.checkMessage(message)
        require(Wire.isFingerprint(envelopeDigest))
        return byteArrayOf(76, 84, 65, 1) + (message.content.id + context.groupId + context.sessionId +
            context.senderId + context.recipientId + envelopeDigest).encodeToByteArray()
    }

    fun header(payloadBytes: Int): ByteArray = BoundedFrameLength.header(payloadBytes, GroupTextCodec.MAX_BYTES)
    fun payloadBytes(header: ByteArray): Int = BoundedFrameLength.payloadBytes(header, GroupTextCodec.MAX_BYTES)
    fun checkFixedHeader(header: ByteArray, expected: Int) {
        require(expected == SCOPE_BYTES || expected == ACK_BYTES)
        require(payloadBytes(header) == expected) { "Invalid group text control frame size" }
    }
}
