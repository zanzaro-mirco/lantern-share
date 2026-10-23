package lantern.domain

import kotlinx.coroutines.flow.StateFlow

enum class GroupTextFailure { UNAVAILABLE, ROSTER_REQUIRED, SESSION_CHOICE_REQUIRED, FAILED }

/** One explicit bounded transfer, separate from diagnostic negotiation and PoC messages. */
sealed interface GroupTextState {
    data object Idle : GroupTextState
    data class Waiting(val peer: Peer, val sending: Boolean) : GroupTextState
    data class Transferring(val peer: Peer) : GroupTextState
    data class Sent(val peer: Peer, val message: SignedGroupText) : GroupTextState
    data class Received(val peer: Peer, val message: SignedGroupText) : GroupTextState
    data class Failed(val peer: Peer, val reason: GroupTextFailure, val attemptedMessageId: String?) : GroupTextState
}

interface GroupTextController : GroupSessionController {
    val groupTextState: StateFlow<GroupTextState>
    fun sendGroupText(peer: Peer, text: String)
    fun receiveGroupText(peer: Peer)
}
