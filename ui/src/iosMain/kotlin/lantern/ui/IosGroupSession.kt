package lantern.ui

import lantern.domain.GroupTrustAnchor
import lantern.domain.SessionCandidate
import lantern.domain.SessionSelection
import lantern.protocol.GroupSessionOffer
import lantern.protocol.GroupSessionOfferCodec
import lantern.protocol.GroupSessionOfferFrameDecoder

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
    private class Held(val anchor: GroupTrustAnchor, val marker: IosGroupAdoptionJournalSnapshot?, val session: SessionCandidate)
    private var held: Held? = null
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
        if (result is SessionSelection.Join) held = Held(anchor, marker, result.session)
        return IosGroupSessionResult(result)
    }

    fun reset() { held = null }

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
