package lantern.protocol

import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository
import kotlin.coroutines.cancellation.CancellationException

sealed interface GroupRootAdoptionFailure {
    data class Confirmation(val reason: GroupAdmissionConfirmationFailure) : GroupRootAdoptionFailure
    data object IdentityChanged : GroupRootAdoptionFailure
    data object AlreadyInGroup : GroupRootAdoptionFailure
    data object StorageFailed : GroupRootAdoptionFailure
}

sealed interface GroupRootAdoptionState {
    data class Active(val confirmation: GroupAdmissionConfirmationState) : GroupRootAdoptionState
    /** Ownership transferred, not persisted membership or authorization. */
    data object ReleasedForCommit : GroupRootAdoptionState
    data class Closed(val reason: GroupRootAdoptionFailure) : GroupRootAdoptionState
}

/**
 * Frozen result of this live comparison and both confirmations. Only a future recoverable
 * commit owner may use it, after rechecking identity, empty membership, block and liveness.
 * It is not a reusable authorization ticket and cannot be passed to foundLocalGroup.
 * Transport/timer ownership and their original deadline must accompany the handoff separately;
 * retaining these bytes after that connection ends grants no permission to commit.
 */
class GroupRootAdoptionDraft internal constructor(
    val proof: GroupAdmissionProof,
    val memberIdentity: String,
    comparisonBytes: ByteArray,
) {
    val anchor: GroupTrustAnchor get() = proof.anchor
    private val comparisonContent = comparisonBytes.copyOf()
    fun comparisonBytes(): ByteArray = comparisonContent.copyOf()
}

/**
 * One new member's explicit adoption request, before any durable write. The received root is
 * only a candidate: verifying its chain proves internal consistency, not independent trust.
 * The exact full comparison binds that candidate, path, signatures and this connection's
 * fresh offers; only an explicit user confirm of its instance-owned ticket can sign approval.
 * Both directional confirmations and a successful local write are mandatory before release.
 *
 * The OS owner supplies offers from the selected, mutually pinned TLS connection, resolves
 * each certificate against its expected pin, serializes ALL calls/identity/group/lifecycle,
 * schedules the inherited deadline while idle and closes transport on Closed. No socket,
 * repository lifetime, peer trust, distributed commit or application traffic is owned here.
 */
class GroupRootAdoptionAttempt(
    offers: ProtocolHandshakeOffers,
    private val localIdentity: String,
    selectedPeerIdentity: String,
    authenticatedPeerIdentity: String,
    private val proof: GroupAdmissionProof,
    selectedAtMillis: Long,
    nowMillis: () -> Long,
    verifyAdmissionSignature: (String, ByteArray, String) -> Boolean,
    verifyRemoteSignature: (ByteArray, String) -> Boolean,
) {
    private val context = GroupAdmissionConfirmationContext.forRootCandidate(offers, proof)
    private val confirmation: GroupAdmissionConfirmationAttempt
    private var terminal: GroupRootAdoptionState? = null
    private var readingLocalContext = false

    init {
        require(offers.local.identity == localIdentity && context.memberIdentity == localIdentity) {
            "Root adoption requires the local TLS member, not the issuer"
        }
        confirmation = GroupAdmissionConfirmationAttempt(
            context, localIdentity, selectedPeerIdentity, authenticatedPeerIdentity, selectedAtMillis,
            nowMillis, verifyAdmissionSignature, verifyRemoteSignature, offers.observedAtMillis,
        )
    }

    fun state(): GroupRootAdoptionState {
        terminal?.let { return it }
        val state = confirmation.state
        terminal?.let { return it } // A trusted clock callback may reenter lifecycle methods.
        if (state is GroupAdmissionConfirmationState.Closed) {
            return close(GroupRootAdoptionFailure.Confirmation(state.reason))
        }
        return GroupRootAdoptionState.Active(state)
    }

    fun remainingMillis(): Long? = if (active()) confirmation.remainingMillis else null

    /** Read failures are not empty membership. No proof verification before this preflight. */
    fun prepare(currentIdentityId: String, repository: LocalGroupRepository): Boolean {
        if (readingLocalContext || !active() || confirmation.state != GroupAdmissionConfirmationState.AwaitingProof) return false
        if (!checkLocalContext(currentIdentityId, repository)) return false
        return confirmation.prepare() && active()
    }

    fun comparison(): GroupAdmissionComparison? = if (active()) confirmation.comparison() else null

    fun confirm(ticket: GroupAdmissionComparison): GroupAdmissionConfirmationOperation.Sign? =
        if (active()) confirmation.confirm(ticket) else null

    fun signed(request: GroupAdmissionConfirmationOperation.Sign, signature: String): GroupAdmissionConfirmationOperation.Send? =
        if (active()) confirmation.signed(request, signature) else null

    fun sent(request: GroupAdmissionConfirmationOperation.Send): Boolean = active() && confirmation.sent(request)

    fun receive(sender: String, recipient: String, signature: String): Boolean =
        active() && confirmation.receive(sender, recipient, signature)

    fun operationFailed(request: GroupAdmissionConfirmationOperation): Boolean =
        active() && confirmation.operationFailed(request)

    /**
     * One-time handoff to a future commit owner, never an insert or commit acknowledgement.
     * A synchronous read can reenter cancellation/expiry, so liveness is checked after it too.
     * The receiving owner must arbitrate concurrent writers inside its own transaction;
     * this empty snapshot does not reserve SQLite or provide OS/database atomicity.
     */
    fun releaseForCommit(currentIdentityId: String, repository: LocalGroupRepository): GroupRootAdoptionDraft? {
        if (readingLocalContext || !active() || confirmation.state != GroupAdmissionConfirmationState.Confirmed) return null
        if (!checkLocalContext(currentIdentityId, repository)) return null
        val ticket = confirmation.comparison() ?: return null
        if (!active()) return null
        val draft = GroupRootAdoptionDraft(proof, localIdentity, ticket.bytes)
        terminal = GroupRootAdoptionState.ReleasedForCommit
        return draft
    }

    fun cancel() = invalidate { confirmation.cancel() }
    fun block() = invalidate { confirmation.block() }
    fun leaveGroup() = invalidate { confirmation.leaveGroup() }
    fun transportClosed() = invalidate { confirmation.transportClosed() }

    private inline fun invalidate(action: () -> Unit) {
        if (terminal == null) {
            action()
            state()
        }
    }

    private fun checkLocalContext(currentIdentityId: String, repository: LocalGroupRepository): Boolean {
        if (currentIdentityId != localIdentity) {
            close(GroupRootAdoptionFailure.IdentityChanged)
            return false
        }
        readingLocalContext = true
        val anchor = try {
            repository.localGroup()
        } catch (cancelled: CancellationException) {
            cancel()
            state()
            throw cancelled
        } catch (failure: Throwable) {
            close(GroupRootAdoptionFailure.StorageFailed)
            throw failure
        } finally {
            readingLocalContext = false
        }
        if (!active()) return false
        if (anchor != null) {
            close(GroupRootAdoptionFailure.AlreadyInGroup)
            return false
        }
        return true
    }

    private fun active(): Boolean = state() is GroupRootAdoptionState.Active

    private fun close(reason: GroupRootAdoptionFailure): GroupRootAdoptionState {
        if (terminal == null) {
            terminal = GroupRootAdoptionState.Closed(reason)
            confirmation.cancel()
        }
        return checkNotNull(terminal)
    }
}
