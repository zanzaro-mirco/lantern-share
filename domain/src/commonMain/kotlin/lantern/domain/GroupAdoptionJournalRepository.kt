package lantern.domain

/**
 * Opaque, untrusted staged material. Never membership, consent or a reusable commit ticket.
 * Metadata is not authenticated here and may disagree with the payload: the future recovery
 * owner must decode, cross-check it and verify cryptographic context before any use.
 */
class PendingGroupAdoption(
    val attemptId: String,
    val localIdentity: String,
    val peerIdentity: String,
    val anchor: GroupTrustAnchor,
    payload: ByteArray,
) {
    private val content: ByteArray
    fun payload(): ByteArray = content.copyOf()

    init {
        require(listOf(attemptId, localIdentity, peerIdentity, anchor.groupId, anchor.founderId).all {
            it.length == 64 && it.all { character -> character in '0'..'9' || character in 'a'..'f' }
        }) { "Invalid staged adoption identifier" }
        require(localIdentity != peerIdentity) { "Staged adoption needs distinct identities" }
        require(payload.size in 1..MAX_PAYLOAD_BYTES) { "Invalid staged adoption payload size" }
        content = payload.copyOf()
    }

    /** Exact idempotency, not merely matching an ID supplied by a caller. */
    fun sameRecord(other: PendingGroupAdoption): Boolean =
        attemptId == other.attemptId && localIdentity == other.localIdentity && peerIdentity == other.peerIdentity &&
            anchor == other.anchor && content.contentEquals(other.content)

    companion object {
        /** Storage budget, independent of and larger than the protocol codec's stricter limit. */
        const val MAX_PAYLOAD_BYTES = 524288
    }
}

/**
 * One pending candidate per installation, separate from durable membership and PoC trust.
 * Payload decoding, signature/certificate checks and recovery policy belong to the caller.
 * Reads never resume consent or delete corrupt/unknown data. Errors propagate, not absence.
 * The caller serializes identity/lifecycle changes and keeps the repository alive until drain.
 * Each distinct attempt requires a fresh OS-generated ID; never recycle an earlier attempt ID.
 */
interface GroupAdoptionJournalRepository {
    fun pendingGroupAdoption(): PendingGroupAdoption?

    /**
     * Atomically insert without replacing anything: true inserted, false exact retry.
     * A different pending record, changed OS identity or existing local group throws.
     * This is not a membership reservation: another actor can subsequently found a group.
     * No acknowledgements, peer trust or application traffic may follow from staging alone.
     */
    fun stageGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean

    /**
     * Delete only the exact record observed by the caller, not different metadata or payload.
     * False means absent/different. No group or peer data is changed. No automatic cleanup.
     */
    fun removeGroupAdoption(record: PendingGroupAdoption): Boolean
}
