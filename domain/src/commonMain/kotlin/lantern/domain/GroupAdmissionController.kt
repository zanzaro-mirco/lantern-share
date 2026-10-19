package lantern.domain

import kotlinx.coroutines.flow.StateFlow

enum class GroupAdmissionRole { FOUNDER, NEW_MEMBER }
enum class GroupAdmissionFailure { UNAVAILABLE, INTERRUPTED, FAILED, COMMIT_OUTCOME_UNKNOWN }

/** Presentation only. Neither a comparison nor an issuer's completion grants application traffic. */
sealed interface GroupAdmissionState {
    data object Idle : GroupAdmissionState
    data class Selecting(val peer: Peer) : GroupAdmissionState
    data class Comparing(
        val peer: Peer,
        val role: GroupAdmissionRole,
        val groupId: String,
        val code: String,
    ) : GroupAdmissionState
    data class AwaitingPeer(val peer: Peer) : GroupAdmissionState
    data class Completed(val groupId: String, val adoptedLocally: Boolean) : GroupAdmissionState
    data class Failed(val peer: Peer, val reason: GroupAdmissionFailure) : GroupAdmissionState
}

interface GroupAdmissionController {
    val admissionState: StateFlow<GroupAdmissionState>
    /** Read-only refresh signal, including a commit whose selection was closed meanwhile. */
    val membershipRevision: StateFlow<Long>
    /** Both devices select explicitly. Replacement permits only exact interrupted-journal cleanup. */
    fun selectGroupPeer(peer: Peer, replaceInterrupted: Boolean = false)
    /** Retain the exact displayed snapshot; stale/reconstructed confirmations are ignored. */
    fun confirmGroup(comparison: GroupAdmissionState.Comparing)
    fun cancelGroup()
}
