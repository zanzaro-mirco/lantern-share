package lantern.domain

import kotlinx.coroutines.flow.StateFlow

/** A local view of authenticated session participants, not presence or delivery receipts. */
sealed interface GroupRosterState {
    data object Idle : GroupRosterState
    data class Synchronizing(val peer: Peer) : GroupRosterState
    class Synchronized(val peer: Peer, val groupId: String, val sessionId: String,
                       participants: Collection<String>) : GroupRosterState {
        private val snapshot = participants.sorted()
        val participants: List<String> get() = snapshot.toList()
    }
    data class Failed(val peer: Peer, val reason: GroupRosterFailure) : GroupRosterState
}

enum class GroupRosterFailure { UNAVAILABLE, SESSION_CHOICE_REQUIRED, MISSING_PARTICIPANTS, FAILED }

interface GroupRosterController : GroupTextController {
    val groupRosterState: StateFlow<GroupRosterState>
    fun synchronizeGroupRoster(peer: Peer)
}
