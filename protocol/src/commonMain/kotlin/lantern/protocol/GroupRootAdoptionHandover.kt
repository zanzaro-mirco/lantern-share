package lantern.protocol

import lantern.domain.PendingGroupAdoption
import lantern.domain.GroupAdoptionRepository
import kotlin.coroutines.cancellation.CancellationException

/**
 * Process-local, revocable continuation, constructible only by a live adoption attempt.
 * The new OS owner serializes every call and forwards cancel/block/leave/EOF, including
 * while idle. It inherits the original timer and monotonic watermark: never start a new
 * timeout on handover. This class neither owns nor closes the socket/database/timer.
 *
 * The handle itself is not durable membership or a recovery token. commitLocal consumes
 * live consent under the owner's serial lifecycle; SQLite arbitrates the exact record and
 * absence of membership. Retaining draft/record cannot resume consent after an interruption.
 */
class GroupRootAdoptionHandover internal constructor(
    val draft: GroupRootAdoptionDraft,
    val record: PendingGroupAdoption,
    private val confirmation: GroupAdmissionConfirmationAttempt,
) {
    private var outcome: GroupRootAdoptionState? = null
    private var committing = false

    /** Transient confirmation only; use rootState for the durable/unknown commit outcome. */
    fun state(): GroupAdmissionConfirmationState = confirmation.state

    fun remainingMillis(): Long? = if (outcome == null) confirmation.remainingMillis else null

    fun rootState(): GroupRootAdoptionState {
        outcome?.let { return it }
        val current = confirmation.state
        outcome?.let { return it } // A trusted clock callback may have reentered the owner.
        return when (current) {
            is GroupAdmissionConfirmationState.Closed ->
                GroupRootAdoptionState.Closed(GroupRootAdoptionFailure.Confirmation(current.reason))
            else -> GroupRootAdoptionState.Active(current)
        }
    }

    /**
     * Policy A: one synchronous serial operation, no callbacks from storage. The owner holds
     * its lifecycle executor/lock through this call and supplies the fresh OS identity.
     * Stage is non-authorizing; recheck deadline/revocation AFTER it, immediately before
     * entering the atomic commit. Events queued during that transaction are ordered after it.
     * A database operation cannot be interrupted/undone by a later timer/EOF. Success is
     * published only on return from commit; failures never cause an automatic replay.
     */
    fun commitLocal(
        currentIdentityId: String, repository: GroupAdoptionRepository,
        replacingInterrupted: PendingGroupAdoption? = null,
    ): Boolean {
        if (committing || rootState() != GroupRootAdoptionState.Active(GroupAdmissionConfirmationState.Confirmed)) return false
        if (currentIdentityId != record.localIdentity) {
            outcome = GroupRootAdoptionState.Closed(GroupRootAdoptionFailure.IdentityChanged)
            confirmation.cancel()
            return false
        }
        committing = true
        var enteredCommit = false
        try {
            if (replacingInterrupted != null) {
                require(replacingInterrupted.localIdentity == currentIdentityId &&
                    replacingInterrupted.attemptId != record.attemptId) { "Invalid interrupted adoption retry" }
                check(repository.removeGroupAdoption(replacingInterrupted)) { "Interrupted adoption changed" }
                if (rootState() != GroupRootAdoptionState.Active(GroupAdmissionConfirmationState.Confirmed)) return false
            }
            repository.stageGroupAdoption(record, currentIdentityId)
            if (rootState() != GroupRootAdoptionState.Active(GroupAdmissionConfirmationState.Confirmed)) return false
            enteredCommit = true
            repository.commitGroupAdoption(record, currentIdentityId)
            outcome = GroupRootAdoptionState.Committed
            confirmation.cancel() // Retire transient consent; the durable result is independent.
            return true
        } catch (failure: Throwable) {
            if (enteredCommit) outcome = GroupRootAdoptionState.CommitOutcomeUnknown
            else {
                if (failure is CancellationException) confirmation.cancel()
                try {
                    if (rootState() !is GroupRootAdoptionState.Closed) {
                        outcome = GroupRootAdoptionState.Closed(GroupRootAdoptionFailure.StorageFailed)
                    }
                } catch (secondary: Throwable) {
                    if (secondary !== failure) failure.addSuppressed(secondary)
                    outcome = GroupRootAdoptionState.Closed(GroupRootAdoptionFailure.StorageFailed)
                }
            }
            confirmation.cancel()
            throw failure
        } finally {
            committing = false
        }
    }

    /** Exact snapshot comparison only, not a storage read or authorization to write. */
    fun matchesRecord(candidate: PendingGroupAdoption): Boolean =
        record.sameRecord(candidate) && rootState() == GroupRootAdoptionState.Active(GroupAdmissionConfirmationState.Confirmed)

    fun cancel() = confirmation.cancel()
    fun block() = confirmation.block()
    fun leaveGroup() = confirmation.leaveGroup()
    fun transportClosed() = confirmation.transportClosed()
}
