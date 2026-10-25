package lantern.ui

import lantern.domain.GroupTextContent
import lantern.domain.GroupTextRepository
import lantern.domain.GroupTrustAnchor
import lantern.domain.SignedGroupText
import lantern.domain.StoredGroupText
import lantern.protocol.GroupMembershipEvidenceCodec
import lantern.protocol.GroupSessionOfferCodec
import lantern.protocol.GroupTextCodec
import lantern.protocol.GroupTextReceiver
import lantern.protocol.GroupTextTransferCodec
import lantern.protocol.GroupTextTransferContext
import lantern.protocol.GroupTextDeliveryContext
import lantern.protocol.GroupRosterTextContext
import lantern.protocol.GroupRosterTextCodec
import lantern.protocol.GroupTextTransferFrameDecoder

class IosGroupTextSelection internal constructor(val context: IosGroupTextContext?, val failure: IosGroupTextFailure?)

/** Independent run scope, not built from an incoming message or reusable transport authority. */
class IosGroupTextContext internal constructor(internal val context: GroupTextDeliveryContext,
    internal val anchor: GroupTrustAnchor, internal val marker: IosGroupAdoptionJournalSnapshot?)

class IosGroupTextEnvelope internal constructor(internal val message: SignedGroupText) {
    val id: String get() = message.content.id
    val groupId: String get() = message.content.groupId
    val sessionId: String get() = message.content.sessionId
    val body: String get() = message.content.body
    val authorSequence: Long get() = message.content.authorSequence
    val recipients: List<String> get() = message.content.recipients
    @Throws(Exception::class)
    fun payload(): ByteArray = GroupTextCodec.encode(message)
}

class IosStoredGroupText internal constructor(stored: StoredGroupText) {
    val envelope = IosGroupTextEnvelope(stored.message)
    val receivedBy: List<String> = stored.receivedBy.sorted()
}

/** Serial service-queue boundary; native owner supplies actual TLS certificate, OS crypto and lifetime. */
class IosGroupTextTransfer(private val persistence: IosPersistence, private val memory: IosGroupSessionMemory,
                           private val scope: IosGroupTextContext, private val localIdentity: String) {
    private val context = scope.context
    private val rosterContext: GroupRosterTextContext? get() = context as? GroupRosterTextContext
    val scopeBytes: Int get() = if (rosterContext != null) GroupRosterTextCodec.SCOPE_BYTES else GroupTextTransferCodec.SCOPE_BYTES
    var failure: IosGroupTextFailure = IosGroupTextFailure.FAILED
        private set
    var attemptedMessageId: String? = null
        private set

    init { require(localIdentity == context.senderId || localIdentity == context.recipientId) }

    @Throws(Exception::class)
    fun checkBinding(offers: IosHandshakeV1Offers, membership: IosGroupMembershipEvidence, sending: Boolean) {
        if (rosterContext != null) GroupRosterTextCodec.sendsFirst(offers.offers, sending)
        else GroupTextTransferCodec.sendsFirst(offers.offers, sending)
        require(localIdentity == offers.localIdentity && membership.evidence.anchor == scope.anchor &&
            context.groupId == scope.anchor.groupId && context.senderId == (if (sending) offers.localIdentity else offers.remoteIdentity) &&
            context.recipientId == (if (sending) offers.remoteIdentity else offers.localIdentity))
    }

    @Throws(Exception::class)
    fun scopeFrame(): ByteArray = frame(scopePayload())

    @Throws(Exception::class)
    fun checkScope(payload: ByteArray) { require(payload.contentEquals(scopePayload())) }

    /** An existing authored copy still needs the freshly verified run/scope; never reserves counters. */
    @Throws(Exception::class)
    fun prepareSaved(id: String, isCurrent: () -> Boolean, verify: (ByteArray, String) -> Boolean): IosGroupTextEnvelope {
        require(localIdentity == context.senderId && rosterContext != null)
        current(isCurrent)
        val message = checkNotNull(persistence.groupTexts.groupText(id)).message
        if (message.content.groupId != context.groupId || message.content.sessionId != context.sessionId ||
            message.content.recipients.toSet() != context.recipients) {
            failure = IosGroupTextFailure.ROSTER_REQUIRED
            error("Saved copy does not match current session snapshot")
        }
        context.checkMessage(message)
        GroupTextCodec.encode(message)
        check(verify(GroupTextCodec.signedBytes(message.content), message.signature))
        current(isCurrent)
        memory.markTextUsed(scope)
        attemptedMessageId = id
        persistence.groupTexts.saveGroupText(message, localIdentity)
        current(isCurrent)
        return IosGroupTextEnvelope(message)
    }

    @Throws(Exception::class)
    fun prepareOutgoing(id: String, body: String, isCurrent: () -> Boolean,
                        sign: (ByteArray) -> String?): IosGroupTextEnvelope {
        require(localIdentity == context.senderId)
        current(isCurrent)
        val counters = persistence.groupTexts.reserveGroupTextCounters(context.groupId, localIdentity)
        current(isCurrent)
        val content = GroupTextContent(id, context.groupId, context.sessionId, localIdentity,
            counters.authorSequence, counters.logicalTime, context.recipients, body)
        val message = SignedGroupText(content, checkNotNull(sign(GroupTextCodec.signedBytes(content))))
        GroupTextCodec.encode(message)
        current(isCurrent)
        memory.markTextUsed(scope) // Conservative before entering the transaction, even on an ambiguous error.
        attemptedMessageId = id
        persistence.groupTexts.saveGroupText(message, localIdentity)
        current(isCurrent)
        return IosGroupTextEnvelope(message)
    }

    @Throws(Exception::class)
    fun receive(payload: ByteArray, isCurrent: () -> Boolean,
                verify: (ByteArray, String) -> Boolean): IosGroupTextEnvelope {
        require(localIdentity == context.recipientId)
        val message = GroupTextCodec.decode(payload)
        context.checkMessage(message)
        val store = object : GroupTextRepository by persistence.groupTexts {
            override fun saveGroupText(message: SignedGroupText, localIdentity: String): Boolean {
                current(isCurrent)
                memory.markTextUsed(scope) // Inbox calls only after successful OS signature verification.
                attemptedMessageId = message.content.id
                return persistence.groupTexts.saveGroupText(message, localIdentity)
            }
        }
        GroupTextReceiver(store).receive(message, context.groupId, context.sessionId, localIdentity,
            context.senderId, context.recipients, { current(isCurrent); true }, verify)
        return IosGroupTextEnvelope(message)
    }

    @Throws(Exception::class)
    fun textFrame(envelope: IosGroupTextEnvelope): ByteArray {
        context.checkMessage(envelope.message)
        return frame(envelope.payload())
    }

    @Throws(Exception::class)
    fun acknowledgementFrame(envelope: IosGroupTextEnvelope, digest: String): ByteArray =
        frame(acknowledgement(envelope.message, digest))

    @Throws(Exception::class)
    fun acknowledge(payload: ByteArray, envelope: IosGroupTextEnvelope, digest: String, isCurrent: () -> Boolean) {
        require(localIdentity == context.senderId)
        current(isCurrent)
        require(payload.contentEquals(acknowledgement(envelope.message, digest)))
        persistence.groupTexts.acknowledgeGroupText(envelope.message, context.recipientId)
        current(isCurrent)
    }

    private fun current(isCurrent: () -> Boolean) { check(isCurrent()); memory.checkCurrent(scope) }
    private fun frame(payload: ByteArray) = GroupTextTransferCodec.header(payload.size) + payload
    private fun scopePayload(): ByteArray = rosterContext?.let(GroupRosterTextCodec::scope)
        ?: GroupTextTransferCodec.scope(context as GroupTextTransferContext)
    private fun acknowledgement(message: SignedGroupText, digest: String): ByteArray =
        rosterContext?.let { GroupRosterTextCodec.acknowledgement(it, message, digest) }
            ?: GroupTextTransferCodec.acknowledgement(context as GroupTextTransferContext, message, digest)

    @Throws(Exception::class)
    fun decoder(expectedBytes: Int): IosGroupTextDecoder =
        IosGroupTextDecoder(GroupTextTransferFrameDecoder(expectedBytes, rosterText = rosterContext != null))

    @Throws(Exception::class)
    fun publishDelivery(controller: IosGroupAdmissionController, selection: IosGroupAdmissionSelection,
                        envelope: IosGroupTextEnvelope, isCurrent: () -> Boolean) {
        require(rosterContext != null)
        current(isCurrent)
        context.checkMessage(envelope.message)
        val stored = checkNotNull(persistence.groupTexts.groupText(envelope.id))
        require(stored.message.sameMessage(envelope.message))
        require(localIdentity in stored.receivedBy && context.recipientId in stored.receivedBy)
        current(isCurrent)
        controller.rosterTextCompleted(selection, stored)
    }
}

/** Framing/role checks only, no membership or storage permission. */
object IosGroupTextProtocol {
    val scopeBytes: Int get() = GroupTextTransferCodec.SCOPE_BYTES
    val acknowledgementBytes: Int get() = GroupTextTransferCodec.ACK_BYTES
    fun capabilities(sending: Boolean): String {
        val features = listOf(GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE, GroupTextTransferCodec.FEATURE)
        val role = if (sending) GroupTextTransferCodec.SENDER_FEATURE else GroupTextTransferCodec.RECEIVER_FEATURE
        fun json(values: List<String>) = values.joinToString(",", "[", "]") { "\"$it\"" }
        return "{\"version\":1,\"supportedFeatures\":${json(features + role)},\"requiredFeatures\":${json(features)}}"
    }
    @Throws(Exception::class)
    fun sendsFirst(offers: IosHandshakeV1Offers, sending: Boolean): Boolean =
        GroupTextTransferCodec.sendsFirst(offers.offers, sending)

    fun completed(controller: IosGroupAdmissionController, selection: IosGroupAdmissionSelection, envelope: IosGroupTextEnvelope) =
        controller.textCompleted(selection, envelope.message)
}

class IosGroupTextRead internal constructor(val consumedBytes: Int, val payload: ByteArray?)
class IosGroupTextDecoder internal constructor(private val decoder: GroupTextTransferFrameDecoder) {
    constructor(expectedBytes: Int) : this(GroupTextTransferFrameDecoder(expectedBytes))
    @Throws(Exception::class)
    fun nextReadBytes(): Int = decoder.nextReadBytes
    @Throws(Exception::class)
    fun accept(chunk: ByteArray): IosGroupTextRead = decoder.accept(chunk).let { IosGroupTextRead(it.consumedBytes, it.payload) }
    @Throws(Exception::class)
    fun finish() { decoder.finish() }
    fun cancel() = decoder.close()
}
