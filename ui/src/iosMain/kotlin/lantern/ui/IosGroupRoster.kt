package lantern.ui

import lantern.domain.GroupTrustAnchor
import lantern.domain.SessionCandidate
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupMembershipEvidenceCodec
import lantern.protocol.GroupSessionJoin
import lantern.protocol.GroupSessionOfferCodec
import lantern.protocol.GroupSessionRoster
import lantern.protocol.GroupSessionRosterCodec
import lantern.protocol.GroupSessionRosterFrameDecoder
import lantern.protocol.GroupRosterTextContext
import lantern.protocol.GroupRosterTextCodec
import lantern.protocol.GroupTextTransferCodec

class IosGroupRosterSelection internal constructor(val exchange: IosGroupRosterExchange?, val failure: IosGroupRosterFailure?)

/** Opaque snapshot: not a reusable TLS authority. All encoding/union/proof rules remain Kotlin. */
class IosGroupRosterSnapshot internal constructor(internal val roster: GroupSessionRoster) {
    val sessionId: String get() = roster.sessionId
    val participants: List<String> get() = roster.participants.sorted()
    @Throws(Exception::class)
    fun payload(): ByteArray = GroupSessionRosterCodec.encode(roster)
    @Throws(Exception::class)
    fun framedBytes(): ByteArray = payload().let { GroupSessionRosterCodec.header(it.size) + it }
    @Throws(Exception::class)
    fun agreement(digest: String): ByteArray = GroupSessionRosterCodec.agreement(roster, digest)
}

/** One queue-confined exchange, bound to the exact run revision and local membership marker. */
class IosGroupRosterExchange internal constructor(private val memory: IosGroupSessionMemory,
    internal val revision: Long, internal val anchor: GroupTrustAnchor,
    internal val marker: IosGroupAdoptionJournalSnapshot?, internal val session: SessionCandidate,
    private val requiredParticipants: Set<String>?, private val previous: GroupSessionRoster?) {
    var failure: IosGroupRosterFailure = IosGroupRosterFailure.FAILED
        private set
    private var proposed: GroupSessionRoster? = null
    private var merged: GroupSessionRoster? = null

    @Throws(Exception::class)
    fun propose(membership: IosGroupMembershipEvidence, certificateDer: String,
                isCurrent: () -> Boolean, sign: (ByteArray) -> String?): IosGroupRosterSnapshot {
        current(isCurrent)
        check(proposed == null)
        require(membership.evidence.anchor == anchor)
        val certificate = GroupAdmissionCertificate(membership.evidence.memberIdentity, certificateDer)
        val signature = checkNotNull(sign(GroupSessionRosterCodec.signingBytes(session.sessionId, membership.evidence, certificate)))
        current(isCurrent)
        val own = GroupSessionRoster(anchor, session.sessionId,
            listOf(GroupSessionJoin(session.sessionId, membership.evidence, certificate, signature)), requiredParticipants != null)
        return IosGroupRosterSnapshot(previous?.merge(own) ?: own).also { proposed = it.roster }
    }

    @Throws(Exception::class)
    fun merge(payload: ByteArray, peerId: String, peerCertificateDer: String, isCurrent: () -> Boolean,
              verify: (IosGroupAdmissionCertificate, ByteArray, String) -> Boolean?): IosGroupRosterSnapshot {
        current(isCurrent)
        check(merged == null)
        val local = checkNotNull(proposed)
        val remote = GroupSessionRosterCodec.decode(payload)
        require(remote.anchor == anchor && remote.sessionId == session.sessionId)
        require(remote.entries.single { it.memberId == peerId }.certificate.der == peerCertificateDer)
        if (session.used && !local.retainedSnapshot && !remote.retainedSnapshot) missing()
        fun verifyCurrent(cert: GroupAdmissionCertificate, bytes: ByteArray, signature: String): Boolean {
            current(isCurrent)
            val valid = checkNotNull(verify(IosGroupAdmissionCertificate(cert), bytes, signature))
            current(isCurrent)
            return valid
        }
        check(local.verify(::verifyCurrent) && remote.verify(::verifyCurrent))
        val result = local.merge(remote)
        if (!result.participants.containsAll(requiredParticipants.orEmpty())) missing()
        GroupSessionRosterCodec.encode(result) // Enforce outbound budget before agreement/installation.
        current(isCurrent)
        merged = result
        return IosGroupRosterSnapshot(result)
    }

    @Throws(Exception::class)
    fun install(snapshot: IosGroupRosterSnapshot, isCurrent: () -> Boolean) {
        current(isCurrent)
        check(merged === snapshot.roster)
        memory.installRoster(this, snapshot.roster)
    }

    /** Only after exact LRA on the live owner; construction alone cannot install or authorize text. */
    @Throws(Exception::class)
    fun installForText(snapshot: IosGroupRosterSnapshot, senderId: String, recipientId: String, digest: String,
                       isCurrent: () -> Boolean): IosGroupTextContext =
        installForText(snapshot, senderId, recipientId, digest, savedCopy = false, isCurrent = isCurrent)

    /** [savedCopy] comes from the negotiated HELLO and is checked again by the transfer binding. */
    @Throws(Exception::class)
    fun installForText(snapshot: IosGroupRosterSnapshot, senderId: String, recipientId: String, digest: String,
                       savedCopy: Boolean, isCurrent: () -> Boolean): IosGroupTextContext {
        val context = GroupRosterTextContext(snapshot.roster, senderId, recipientId, digest, savedCopy)
        install(snapshot, isCurrent)
        return IosGroupTextContext(context, anchor, marker)
    }

    private fun current(isCurrent: () -> Boolean) { check(isCurrent() && memory.revision == revision) }
    private fun missing(): Nothing {
        failure = IosGroupRosterFailure.MISSING_PARTICIPANTS
        error("Known session participants unavailable")
    }
}

object IosGroupRosterProtocol {
    fun capabilities(): String {
        val features = listOf(GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE, GroupSessionRosterCodec.FEATURE)
            .joinToString(",", "[", "]") { "\"$it\"" }
        return "{\"version\":1,\"supportedFeatures\":$features,\"requiredFeatures\":$features}"
    }
    @Throws(Exception::class)
    fun sendsFirst(offers: IosHandshakeV1Offers): Boolean = GroupSessionRosterCodec.sendsFirst(offers.offers)
    @Throws(Exception::class)
    fun frame(payload: ByteArray): ByteArray = GroupSessionRosterCodec.header(payload.size) + payload
    fun completed(controller: IosGroupAdmissionController, selection: IosGroupAdmissionSelection, snapshot: IosGroupRosterSnapshot) =
        controller.rosterCompleted(selection, snapshot.roster.anchor.groupId, snapshot.sessionId, snapshot.participants)
}

class IosGroupRosterRead internal constructor(val consumedBytes: Int, val payload: ByteArray?)
class IosGroupRosterDecoder(agreement: Boolean) {
    private val decoder = GroupSessionRosterFrameDecoder(agreement)
    @Throws(Exception::class)
    fun nextReadBytes(): Int = decoder.nextReadBytes
    @Throws(Exception::class)
    fun accept(chunk: ByteArray): IosGroupRosterRead = decoder.accept(chunk).let { IosGroupRosterRead(it.consumedBytes, it.payload) }
    @Throws(Exception::class)
    fun finish() { decoder.finish() }
    fun cancel() = decoder.close()
}

object IosGroupRosterTextProtocol {
    @Throws(Exception::class)
    fun checkSavedCopy(persistence: IosPersistence, id: String, groupId: String, authorId: String, recipientId: String) {
        val saved = checkNotNull(persistence.groupTexts.groupText(id)).message.content
        require(saved.groupId == groupId && saved.authorId == authorId && recipientId in saved.recipients)
    }

    fun capabilities(sending: Boolean): String = capabilities(sending, savedCopy = false)

    /** Same rule as Node: a copy author requires the copy feature, every receiver only supports it. */
    fun capabilities(sending: Boolean, savedCopy: Boolean): String {
        require(sending || !savedCopy)
        val features = GroupRosterTextCodec.requiredFeatures.toList()
        val role = if (sending) GroupTextTransferCodec.SENDER_FEATURE else GroupTextTransferCodec.RECEIVER_FEATURE
        val copy = if (savedCopy || !sending) listOf(GroupRosterTextCodec.COPY_FEATURE) else emptyList()
        val required = if (savedCopy) features + copy else features
        fun json(values: List<String>) = values.joinToString(",", "[", "]") { "\"$it\"" }
        return "{\"version\":1,\"supportedFeatures\":${json(features + role + copy)},\"requiredFeatures\":${json(required)}}"
    }
    @Throws(Exception::class)
    fun sendsFirst(offers: IosHandshakeV1Offers, sending: Boolean): Boolean = GroupRosterTextCodec.sendsFirst(offers.offers, sending)
    @Throws(Exception::class)
    fun savedCopy(offers: IosHandshakeV1Offers, sending: Boolean): Boolean = GroupRosterTextCodec.savedCopy(offers.offers, sending)
}
