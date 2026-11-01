package lantern.domain

import kotlinx.coroutines.flow.StateFlow

/** Negotiation progress only, never a reusable traffic authorization or a remote commit ACK. */
sealed interface GroupSessionState {
    data object Idle : GroupSessionState
    data class Negotiating(val peer: Peer) : GroupSessionState
    data class Selected(val peer: Peer, val session: SessionCandidate) : GroupSessionState
    /** [held] is this device's own session among [sessions], when known. */
    data class NeedsChoice(val peer: Peer, val sessions: List<SessionCandidate>, val held: SessionCandidate? = null) : GroupSessionState
    data class Failed(val peer: Peer, val reason: GroupAdmissionFailure) : GroupSessionState
}

/** Shares the exclusive group selection. No automatic discovery/reconnect is implied. */
interface GroupSessionController : GroupMembershipController {
    val groupSessionState: StateFlow<GroupSessionState>
    fun negotiateGroupSession(peer: Peer)
}

/**
 * Local, explicit choice among used sessions (ADR 022). Agreement still needs a new explicit negotiation.
 * [choice] must be the exact published `NeedsChoice`; a stale or foreign one is ignored.
 */
interface GroupSessionChoiceController : GroupSessionController {
    fun chooseGroupSession(choice: GroupSessionState.NeedsChoice, session: SessionCandidate)
}
