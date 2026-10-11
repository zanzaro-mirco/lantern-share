package lantern.protocol

import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository
import kotlin.coroutines.cancellation.CancellationException

enum class GroupFoundationFailure {
    Cancelled,
    LeftGroup,
    IdentityChanged,
    AlreadyInGroup,
    PreparationFailed,
}

sealed interface GroupFoundationState {
    data object AwaitingPreparation : GroupFoundationState
    data object Preparing : GroupFoundationState
    data object AwaitingCommit : GroupFoundationState
    /** Ownership transferred, NOT persisted or authorized. */
    data object ReleasedForCommit : GroupFoundationState
    data class Closed(val reason: GroupFoundationFailure) : GroupFoundationState
}

/** Opaque, instance-owned permission to request commit; not a membership credential. */
class GroupFoundationTicket internal constructor()

enum class GroupFoundationCommit { Committed, AlreadyInGroup, Invalidated }

/**
 * One explicit local create-group request. The platform owner serializes all calls.
 * No database, transport or trust is owned here. After release, the receiving commit owner
 * owns cancellation/cleanup and must atomically verify identity and absence of membership
 * before persistence. Neither the supplied snapshot nor this ticket reserves a database row.
 */
class GroupFoundationAttempt(private val localIdentityId: String) {
    private var current: GroupFoundationState = GroupFoundationState.AwaitingPreparation
    private var draft: GroupFoundationDraft? = null
    private var ticket: GroupFoundationTicket? = null

    init {
        require(Wire.isFingerprint(localIdentityId)) { "Invalid local foundation identity" }
    }

    fun state(): GroupFoundationState = current

    fun prepare(
        currentAnchor: GroupTrustAnchor?,
        generateGroupId: () -> String,
    ): GroupFoundationTicket? {
        if (current != GroupFoundationState.AwaitingPreparation) return null
        if (currentAnchor != null) {
            close(GroupFoundationFailure.AlreadyInGroup)
            return null
        }
        current = GroupFoundationState.Preparing
        val prepared = try {
            GroupFoundationDraft.prepare(localIdentityId, null, generateGroupId)
        } catch (cancelled: CancellationException) {
            close(GroupFoundationFailure.Cancelled)
            throw cancelled
        } catch (failure: Throwable) {
            close(GroupFoundationFailure.PreparationFailed)
            throw failure
        }
        // A synchronous OS callback may reenter cancel/leave; never revive its result.
        if (current != GroupFoundationState.Preparing) return null
        draft = prepared
        return GroupFoundationTicket().also {
            ticket = it
            current = GroupFoundationState.AwaitingCommit
        }
    }

    /**
     * One-time handoff, not a commit acknowledgement. Supply authoritative local snapshots
     * under the receiving owner's serialization; it must recheck them inside its transaction.
     * A foreign or consumed ticket is ignored without invalidating the legitimate request.
     */
    fun releaseForCommit(
        request: GroupFoundationTicket,
        currentIdentityId: String,
        currentAnchor: GroupTrustAnchor?,
    ): GroupFoundationDraft? {
        if (current != GroupFoundationState.AwaitingCommit || request !== ticket) return null
        if (currentIdentityId != localIdentityId) {
            close(GroupFoundationFailure.IdentityChanged)
            return null
        }
        if (currentAnchor != null) {
            close(GroupFoundationFailure.AlreadyInGroup)
            return null
        }
        val released = checkNotNull(draft)
        draft = null
        ticket = null
        current = GroupFoundationState.ReleasedForCommit
        return released
    }

    fun cancel(): Boolean = close(GroupFoundationFailure.Cancelled)

    fun leaveGroup(): Boolean = close(GroupFoundationFailure.LeftGroup)

    /**
     * The platform owner serializes this synchronous boundary with cancellation and identity
     * changes, off the UI thread. SQLite arbitrates competing writers; this does not make
     * OS identity storage and the database one distributed transaction.
     * After handoff a failed write consumes the ticket. Recover by reading durable state,
     * never by replaying the old request. A failed preliminary read has not handed off ownership.
     */
    fun commit(
        request: GroupFoundationTicket,
        currentIdentityId: String,
        repository: LocalGroupRepository,
    ): GroupFoundationCommit {
        if (current != GroupFoundationState.AwaitingCommit) return GroupFoundationCommit.Invalidated
        val released = releaseForCommit(request, currentIdentityId, repository.localGroup())
            ?: return if (current == GroupFoundationState.Closed(GroupFoundationFailure.AlreadyInGroup)) {
                GroupFoundationCommit.AlreadyInGroup
            } else {
                GroupFoundationCommit.Invalidated
            }
        return if (repository.foundLocalGroup(released.anchor, currentIdentityId)) {
            GroupFoundationCommit.Committed
        } else {
            GroupFoundationCommit.AlreadyInGroup
        }
    }

    private fun close(reason: GroupFoundationFailure): Boolean {
        if (current is GroupFoundationState.Closed || current == GroupFoundationState.ReleasedForCommit) {
            return false
        }
        draft = null
        ticket = null
        current = GroupFoundationState.Closed(reason)
        return true
    }
}
