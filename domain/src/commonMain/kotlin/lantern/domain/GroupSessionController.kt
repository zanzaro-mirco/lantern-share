package lantern.domain

import kotlinx.coroutines.flow.StateFlow

/** Negotiation progress only, never a reusable traffic authorization or a remote commit ACK. */
sealed interface GroupSessionState {
    data object Idle : GroupSessionState
    data class Negotiating(val peer: Peer) : GroupSessionState
    data class Selected(val peer: Peer, val session: SessionCandidate) : GroupSessionState
    data class NeedsChoice(val peer: Peer, val sessions: List<SessionCandidate>) : GroupSessionState
    data class Failed(val peer: Peer, val reason: GroupAdmissionFailure) : GroupSessionState
}

/** Shares the exclusive group selection. No automatic discovery/reconnect is implied. */
interface GroupSessionController : GroupMembershipController {
    val groupSessionState: StateFlow<GroupSessionState>
    fun negotiateGroupSession(peer: Peer)
}
