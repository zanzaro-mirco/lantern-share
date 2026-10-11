package lantern.connectivity

import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository
import lantern.protocol.GroupFoundationAttempt
import lantern.protocol.GroupFoundationDraft
import lantern.protocol.GroupFoundationCommit
import lantern.protocol.GroupFoundationState
import lantern.protocol.GroupFoundationTicket

/** OS randomness and the existing identity only; no persistence or implicit group adoption. */
internal fun prepareLocalGroupFoundation(
    identity: Identity,
    currentAnchor: GroupTrustAnchor?,
): GroupFoundationDraft = GroupFoundationDraft.prepare(identity.id, currentAnchor, ::randomNonce)

internal typealias LocalGroupFoundationCommit = GroupFoundationCommit

/**
 * JVM/Android owner for one explicit create-group request. Calls must be serialized
 * by the service owner, off the UI thread. Only existing OS identity/randomness is used.
 * Direct release transfers the draft, not durable membership: its receiver owns the transaction
 * and cancellation. Alternatively commit() persists through the domain repository contract.
 * No service is activated and no remote peer is authorized here.
 */
internal class LocalGroupFoundation(identity: Identity) {
    private val attempt = GroupFoundationAttempt(identity.id)

    fun state(): GroupFoundationState = attempt.state()

    fun prepare(currentAnchor: GroupTrustAnchor?): GroupFoundationTicket? =
        attempt.prepare(currentAnchor, ::randomNonce)

    fun releaseForCommit(
        ticket: GroupFoundationTicket,
        currentIdentity: Identity,
        currentAnchor: GroupTrustAnchor?,
    ): GroupFoundationDraft? = attempt.releaseForCommit(ticket, currentIdentity.id, currentAnchor)

    fun cancel(): Boolean = attempt.cancel()

    fun leaveGroup(): Boolean = attempt.leaveGroup()

    /**
     * Synchronous commit boundary; the service must serialize this with cancellation and OS
     * identity changes. The repository arbitrates concurrent database writers atomically.
     * Return Committed only after persistence. Exceptions propagate; after handoff this ticket
     * is consumed and must not be replayed. Recovery reads durable state before a new request.
     */
    fun commit(
        ticket: GroupFoundationTicket,
        currentIdentity: Identity,
        repository: LocalGroupRepository,
    ): LocalGroupFoundationCommit = attempt.commit(ticket, currentIdentity.id, repository)
}
