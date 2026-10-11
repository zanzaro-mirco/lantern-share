package lantern.ui

import lantern.protocol.GroupFoundationAttempt
import lantern.protocol.GroupFoundationCommit
import lantern.protocol.GroupFoundationFailure
import lantern.protocol.GroupFoundationState
import lantern.protocol.GroupFoundationTicket

/** Read-only persisted local root; not a peer credential or a session. */
class IosLocalGroupAnchor internal constructor(val groupId: String, val founderId: String)

enum class IosGroupFoundationPhase { AWAITING_PREPARATION, PREPARING, AWAITING_COMMIT, RELEASED_FOR_COMMIT, CLOSED }
enum class IosGroupFoundationFailure { NONE, CANCELLED, LEFT_GROUP, IDENTITY_CHANGED, ALREADY_IN_GROUP, PREPARATION_FAILED }
enum class IosGroupFoundationCommit { COMMITTED, ALREADY_IN_GROUP, INVALIDATED }

data class IosGroupFoundationSnapshot(val phase: IosGroupFoundationPhase, val failure: IosGroupFoundationFailure)

class IosGroupFoundationTicket internal constructor(internal val ticket: GroupFoundationTicket)

/** Swift supplies OS identity/randomness; Kotlin owns lifecycle, tickets and durable commit. */
class IosLocalGroupFoundation private constructor(private val attempt: GroupFoundationAttempt) {
    fun snapshot(): IosGroupFoundationSnapshot = when (val state = attempt.state()) {
        GroupFoundationState.AwaitingPreparation -> view(IosGroupFoundationPhase.AWAITING_PREPARATION)
        GroupFoundationState.Preparing -> view(IosGroupFoundationPhase.PREPARING)
        GroupFoundationState.AwaitingCommit -> view(IosGroupFoundationPhase.AWAITING_COMMIT)
        GroupFoundationState.ReleasedForCommit -> view(IosGroupFoundationPhase.RELEASED_FOR_COMMIT)
        is GroupFoundationState.Closed -> IosGroupFoundationSnapshot(
            IosGroupFoundationPhase.CLOSED,
            when (state.reason) {
                GroupFoundationFailure.Cancelled -> IosGroupFoundationFailure.CANCELLED
                GroupFoundationFailure.LeftGroup -> IosGroupFoundationFailure.LEFT_GROUP
                GroupFoundationFailure.IdentityChanged -> IosGroupFoundationFailure.IDENTITY_CHANGED
                GroupFoundationFailure.AlreadyInGroup -> IosGroupFoundationFailure.ALREADY_IN_GROUP
                GroupFoundationFailure.PreparationFailed -> IosGroupFoundationFailure.PREPARATION_FAILED
            },
        )
    }

    /** Null OS result is a failure, never a fallback group ID. All calls must be serialized. */
    @Throws(Exception::class)
    fun prepare(persistence: IosPersistence, generateGroupId: () -> String?): IosGroupFoundationTicket? {
        if (attempt.state() != GroupFoundationState.AwaitingPreparation) return null
        return attempt.prepare(persistence.localGroups.localGroup()) {
            checkNotNull(generateGroupId()) { "OS group randomness failed" }
        }?.let(::IosGroupFoundationTicket)
    }

    @Throws(Exception::class)
    fun commit(
        ticket: IosGroupFoundationTicket,
        currentIdentityId: String,
        persistence: IosPersistence,
    ): IosGroupFoundationCommit = when (attempt.commit(ticket.ticket, currentIdentityId, persistence.localGroups)) {
        GroupFoundationCommit.Committed -> IosGroupFoundationCommit.COMMITTED
        GroupFoundationCommit.AlreadyInGroup -> IosGroupFoundationCommit.ALREADY_IN_GROUP
        GroupFoundationCommit.Invalidated -> IosGroupFoundationCommit.INVALIDATED
    }

    fun cancel(): Boolean = attempt.cancel()
    fun leaveGroup(): Boolean = attempt.leaveGroup()

    private fun view(phase: IosGroupFoundationPhase) = IosGroupFoundationSnapshot(phase, IosGroupFoundationFailure.NONE)

    companion object {
        @Throws(Exception::class)
        fun create(identityId: String) = IosLocalGroupFoundation(GroupFoundationAttempt(identityId))
    }
}
