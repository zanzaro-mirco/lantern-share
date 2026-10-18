package lantern.protocol

import lantern.domain.PendingGroupAdoption

/**
 * Process-local, revocable continuation, constructible only by a live adoption attempt.
 * The new OS owner serializes every call and forwards cancel/block/leave/EOF, including
 * while idle. It inherits the original timer and monotonic watermark: never start a new
 * timeout on handover. This class neither owns nor closes the socket/database/timer.
 *
 * This is NOT durable membership, a commit permit or a recovery token. Before a future
 * atomic write, the owner must recheck actual OS identity, empty membership, block policy,
 * exact staged record and current liveness. Retaining draft/record cannot resume consent.
 */
class GroupRootAdoptionHandover internal constructor(
    val draft: GroupRootAdoptionDraft,
    val record: PendingGroupAdoption,
    private val confirmation: GroupAdmissionConfirmationAttempt,
) {
    /** Only Confirmed or Closed; querying also observes expiry/backwards clock. */
    fun state(): GroupAdmissionConfirmationState = confirmation.state

    fun remainingMillis(): Long? = confirmation.remainingMillis

    /** Exact snapshot comparison only, not a storage read or authorization to write. */
    fun matchesRecord(candidate: PendingGroupAdoption): Boolean =
        record.sameRecord(candidate) && state() == GroupAdmissionConfirmationState.Confirmed

    fun cancel() = confirmation.cancel()
    fun block() = confirmation.block()
    fun leaveGroup() = confirmation.leaveGroup()
    fun transportClosed() = confirmation.transportClosed()
}
