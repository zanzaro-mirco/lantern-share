package lantern.protocol

import lantern.domain.SignedGroupText

/** One delivery of a text addressed to the entire freshly verified session roster. */
class GroupRosterTextContext(
    val roster: GroupSessionRoster,
    override val senderId: String,
    override val recipientId: String,
    val rosterDigest: String,
) : GroupTextDeliveryContext {
    override val groupId: String get() = roster.anchor.groupId
    override val sessionId: String get() = roster.sessionId
    override val recipients: Set<String> get() = roster.participants

    init {
        require(Wire.isFingerprint(rosterDigest))
        require(senderId != recipientId && senderId in recipients && recipientId in recipients)
    }
}

/** Additive continuation after LRA; legacy LTX/LTA and the signed envelope are unchanged. */
object GroupRosterTextCodec {
    const val FEATURE = "group-roster-text"
    const val SCOPE_BYTES = 324
    const val ACK_BYTES = 360
    val requiredFeatures: Set<String> get() = setOf(FEATURE, GroupSessionRosterCodec.FEATURE,
        GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE)

    fun sendsFirst(offers: ProtocolHandshakeOffers, sending: Boolean): Boolean {
        GroupSessionRosterCodec.sendsFirst(offers)
        for ((participant, sender) in listOf(offers.local to sending, offers.remote to !sending)) {
            val capabilities = participant.capabilities
            check(requiredFeatures.all { it in capabilities.supportedFeatures && it in capabilities.requiredFeatures }) {
                "Roster text not negotiated"
            }
            check((GroupTextTransferCodec.SENDER_FEATURE in capabilities.supportedFeatures) == sender &&
                (GroupTextTransferCodec.RECEIVER_FEATURE in capabilities.supportedFeatures) != sender) {
                "Roster text role mismatch"
            }
        }
        return offers.local.identity < offers.remote.identity
    }

    fun scope(context: GroupRosterTextContext): ByteArray = byteArrayOf(76, 84, 67, 1) +
        (context.groupId + context.sessionId + context.senderId + context.recipientId + context.rosterDigest).encodeToByteArray()

    fun acknowledgement(context: GroupRosterTextContext, message: SignedGroupText, envelopeDigest: String): ByteArray {
        context.checkMessage(message)
        require(Wire.isFingerprint(envelopeDigest))
        return byteArrayOf(76, 71, 65, 1) + (message.content.id + context.groupId + context.sessionId +
            context.senderId + context.recipientId + envelopeDigest).encodeToByteArray()
    }

    fun checkFixedHeader(header: ByteArray, expected: Int) {
        require(expected == SCOPE_BYTES || expected == ACK_BYTES)
        require(GroupTextTransferCodec.payloadBytes(header) == expected) { "Invalid roster text control frame size" }
    }
}
