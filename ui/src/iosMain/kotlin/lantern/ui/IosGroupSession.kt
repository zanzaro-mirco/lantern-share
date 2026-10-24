package lantern.ui

import lantern.domain.GroupTrustAnchor
import lantern.domain.SessionCandidate
import lantern.domain.SessionSelection
import lantern.protocol.GroupSessionOffer
import lantern.protocol.GroupSessionOfferCodec
import lantern.protocol.GroupSessionOfferFrameDecoder
import lantern.protocol.GroupTextTransferContext
import lantern.protocol.GroupSessionRoster

/** Untrusted observation; only the native owner can establish live membership before using it. */
class IosGroupSessionOffer internal constructor(internal val offer: GroupSessionOffer) {
    @Throws(Exception::class)
    fun framedBytes(): ByteArray = GroupSessionOfferCodec.header() + GroupSessionOfferCodec.encode(offer)

    @Throws(Exception::class)
    fun sendsFirst(offers: IosHandshakeV1Offers, membership: IosGroupMembershipEvidence): Boolean {
        require(offer.session.groupId == membership.evidence.anchor.groupId) { "Local session group mismatch" }
        val first = offer.sendsFirst(offers.offers)
        check(first == membership.evidence.sendsFirst(offers.offers))
        return first
    }
}

/** Run-owned, serial native service queue only. No DB, OS, traffic permissions or callbacks. */
class IosGroupSessionMemory {
    private class Held(val anchor: GroupTrustAnchor, val marker: IosGroupAdoptionJournalSnapshot?,
                       var session: SessionCandidate, val participants: Set<String>? = null,
                       val roster: GroupSessionRoster? = null)
    private var held: Held? = null
    internal var revision: Long = 0
        private set
    val feature: String get() = GroupSessionOfferCodec.FEATURE

    @Throws(Exception::class)
    fun propose(groupId: String, founderId: String, marker: IosGroupAdoptionJournalSnapshot?, newSessionId: String): IosGroupSessionOffer {
        val anchor = GroupTrustAnchor(groupId, founderId)
        val previous = held?.takeIf { it.anchor == anchor && sameMarker(it.marker, marker) }
        return IosGroupSessionOffer(GroupSessionOffer(previous?.session ?: SessionCandidate(groupId, newSessionId, false),
            established = previous != null))
    }

    /** Caller rechecks exact local marker, live TLS and original deadline immediately before this call. */
    @Throws(Exception::class)
    fun select(local: IosGroupSessionOffer, remote: IosGroupSessionOffer, groupId: String, founderId: String,
               marker: IosGroupAdoptionJournalSnapshot?): IosGroupSessionResult {
        val anchor = GroupTrustAnchor(groupId, founderId)
        val result = local.offer.select(anchor, remote.offer)
        if (result is SessionSelection.Join) {
            val previous = held?.takeIf { it.anchor == anchor && sameMarker(it.marker, marker) &&
                it.session.sessionId == result.session.sessionId }
            held = Held(anchor, marker, result.session, previous?.participants, previous?.roster)
            revision++
        }
        return IosGroupSessionResult(result)
    }

    /** Only after fresh membership/LSN on this TLS; never derive a used roster from its endpoints. */
    @Throws(Exception::class)
    fun selectText(local: IosGroupSessionOffer, remote: IosGroupSessionOffer, groupId: String, founderId: String,
                   marker: IosGroupAdoptionJournalSnapshot?, senderId: String, recipientId: String): IosGroupTextSelection {
        val anchor = GroupTrustAnchor(groupId, founderId)
        val decision = local.offer.select(anchor, remote.offer)
        if (decision !is SessionSelection.Join) return IosGroupTextSelection(null, IosGroupTextFailure.SESSION_CHOICE_REQUIRED)
        val context = GroupTextTransferContext(groupId, decision.session.sessionId, senderId, recipientId)
        val previous = held?.takeIf { it.anchor == anchor && sameMarker(it.marker, marker) &&
            it.session.sessionId == decision.session.sessionId }
        if ((decision.session.used || previous?.roster != null) && previous?.participants != context.recipients) {
            return IosGroupTextSelection(null, IosGroupTextFailure.ROSTER_REQUIRED)
        }
        held = Held(anchor, marker, decision.session, context.recipients, previous?.roster)
        revision++
        return IosGroupTextSelection(IosGroupTextContext(context, anchor, marker), null)
    }

    internal fun checkCurrent(context: IosGroupTextContext) {
        check(held?.let { it.anchor == context.anchor && sameMarker(it.marker, context.marker) &&
            it.session.sessionId == context.context.sessionId && it.participants == context.context.recipients } == true) {
            "Group text session changed"
        }
    }

    internal fun markTextUsed(context: IosGroupTextContext) {
        checkCurrent(context)
        checkNotNull(held).let { it.session = it.session.copy(used = true) }
        revision++
    }

    /** No installation until the owner has verified all entries and the exact live LRA. */
    @Throws(Exception::class)
    fun selectRoster(local: IosGroupSessionOffer, remote: IosGroupSessionOffer, groupId: String, founderId: String,
                     marker: IosGroupAdoptionJournalSnapshot?): IosGroupRosterSelection {
        val anchor = GroupTrustAnchor(groupId, founderId)
        val decision = local.offer.select(anchor, remote.offer)
        if (decision !is SessionSelection.Join) return IosGroupRosterSelection(null, IosGroupRosterFailure.SESSION_CHOICE_REQUIRED)
        val previous = held?.takeIf { it.anchor == anchor && sameMarker(it.marker, marker) &&
            it.session.sessionId == decision.session.sessionId }
        return IosGroupRosterSelection(IosGroupRosterExchange(this, revision, anchor, marker, decision.session,
            previous?.participants, previous?.roster), null)
    }

    internal fun installRoster(exchange: IosGroupRosterExchange, roster: GroupSessionRoster) {
        check(revision == exchange.revision)
        check(roster.anchor == exchange.anchor && roster.sessionId == exchange.session.sessionId)
        held = Held(exchange.anchor, exchange.marker, exchange.session, roster.participants, roster)
        revision++
    }

    fun reset() { held = null; revision++ }

    private fun sameMarker(a: IosGroupAdoptionJournalSnapshot?, b: IosGroupAdoptionJournalSnapshot?): Boolean =
        if (a == null) b == null else b != null && a.sameRecord(b)
}

class IosGroupSessionRead internal constructor(val consumedBytes: Int, val offer: IosGroupSessionOffer?)

class IosGroupSessionDecoder {
    private val decoder = GroupSessionOfferFrameDecoder()
    @Throws(Exception::class)
    fun nextReadBytes(): Int = decoder.nextReadBytes
    @Throws(Exception::class)
    fun accept(chunk: ByteArray): IosGroupSessionRead = decoder.accept(chunk).let {
        IosGroupSessionRead(it.consumedBytes, it.offer?.let(::IosGroupSessionOffer))
    }
    @Throws(Exception::class)
    fun finish() { decoder.finish() }
    fun cancel() = decoder.close()
}
