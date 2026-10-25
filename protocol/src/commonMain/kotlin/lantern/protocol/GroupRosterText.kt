package lantern.protocol

import lantern.domain.SignedGroupText

/**
 * One delivery bound to the entire freshly verified session roster. A new text addresses all of
 * it. A negotiated saved copy keeps the author's original signed snapshot, which must still be a
 * subset of this live roster and contain the TLS recipient: later joiners are never added. A
 * negotiated relayed copy applies the same rules when the TLS sender is another original recipient.
 */
class GroupRosterTextContext(
    val roster: GroupSessionRoster,
    override val senderId: String,
    override val recipientId: String,
    val rosterDigest: String,
    val savedCopy: Boolean = false,
    val relayedCopy: Boolean = false,
) : GroupTextDeliveryContext {
    override val groupId: String get() = roster.anchor.groupId
    override val sessionId: String get() = roster.sessionId
    /** Live roster used for scope/run checks; a copy's frozen recipients come from its signed snapshot. */
    override val recipients: Set<String> get() = roster.participants

    init {
        require(Wire.isFingerprint(rosterDigest))
        require(senderId != recipientId && senderId in recipients && recipientId in recipients)
        require(!(savedCopy && relayedCopy))
    }

    override fun checkMessage(message: SignedGroupText) {
        val c = message.content
        if (relayedCopy) {
            // The relay and its target are both frozen recipients; the author is neither of them.
            require(c.groupId == groupId && c.sessionId == sessionId && c.authorId != senderId && c.authorId != recipientId &&
                senderId in c.recipients && recipientId in c.recipients && recipients.containsAll(c.recipients)) {
                "Relayed group text copy context mismatch"
            }
            return
        }
        if (!savedCopy) return super.checkMessage(message)
        require(c.groupId == groupId && c.sessionId == sessionId && c.authorId == senderId &&
            recipientId in c.recipients && recipients.containsAll(c.recipients)) { "Saved group text copy context mismatch" }
    }

    override fun expectedRecipients(message: SignedGroupText): Set<String> {
        checkMessage(message)
        return if (savedCopy || relayedCopy) message.content.recipients.toSet() else recipients
    }

    /** The author's own join certificate in this freshly verified roster, never the relay's TLS certificate. */
    fun authorCertificate(message: SignedGroupText): GroupAdmissionCertificate {
        require(relayedCopy) { "Only a relayed copy needs the author's roster certificate" }
        checkMessage(message)
        return roster.entries.single { it.memberId == message.content.authorId }.certificate
    }
}

/** Additive continuation after LRA; legacy LTX/LTA and the signed envelope are unchanged. */
object GroupRosterTextCodec {
    const val FEATURE = "group-roster-text"
    /** Required by the author of a saved copy, only supported by receivers; never inferred from payloads. */
    const val COPY_FEATURE = "group-roster-text-copy"
    /** Required by an original non-author recipient forwarding a saved copy, only supported by receivers. */
    const val RELAY_FEATURE = "group-roster-text-relay"
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

    /** True only when the author explicitly required saved-copy delivery and the receiver supports it. */
    fun savedCopy(offers: ProtocolHandshakeOffers, sending: Boolean): Boolean {
        val author = (if (sending) offers.local else offers.remote).capabilities
        val receiver = (if (sending) offers.remote else offers.local).capabilities
        val required = COPY_FEATURE in author.requiredFeatures
        check((COPY_FEATURE in author.supportedFeatures) == required) { "Saved copy must be required by its author" }
        check(COPY_FEATURE !in receiver.requiredFeatures) { "Receiver cannot demand a saved copy" }
        check(!required || COPY_FEATURE in receiver.supportedFeatures) { "Saved copy not negotiated" }
        return required
    }

    /** True only when the sender explicitly required relaying a copy it received; exclusive with [savedCopy]. */
    fun relayedCopy(offers: ProtocolHandshakeOffers, sending: Boolean): Boolean {
        val relay = (if (sending) offers.local else offers.remote).capabilities
        val receiver = (if (sending) offers.remote else offers.local).capabilities
        val required = RELAY_FEATURE in relay.requiredFeatures
        check((RELAY_FEATURE in relay.supportedFeatures) == required) { "Relayed copy must be required by its sender" }
        check(RELAY_FEATURE !in receiver.requiredFeatures) { "Receiver cannot demand a relayed copy" }
        check(!required || RELAY_FEATURE in receiver.supportedFeatures) { "Relayed copy not negotiated" }
        check(!required || !savedCopy(offers, sending)) { "Author and relayed copies are exclusive" }
        return required
    }

    /** Versions 2 and 3 bind the negotiated author or relayed copy mode into the same exact 324-byte agreement. */
    fun scope(context: GroupRosterTextContext): ByteArray = byteArrayOf(76, 84, 67,
        if (context.relayedCopy) 3 else if (context.savedCopy) 2 else 1) +
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
