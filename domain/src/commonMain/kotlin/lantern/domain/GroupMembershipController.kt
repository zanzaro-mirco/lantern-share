package lantern.domain

import kotlinx.coroutines.flow.StateFlow

/** A local, short-lived verification result only; never session/chat or remote acknowledgement. */
sealed interface GroupMembershipCheckState {
    data object Idle : GroupMembershipCheckState
    data class Checking(val peer: Peer) : GroupMembershipCheckState
    data class Verified(val peer: Peer, val groupId: String) : GroupMembershipCheckState
    data class Failed(val peer: Peer, val reason: GroupAdmissionFailure) : GroupMembershipCheckState
}

/** Uses the same exclusive selection/cancellation as admission, not a parallel transport. */
interface GroupMembershipController : GroupAdmissionController {
    val membershipCheckState: StateFlow<GroupMembershipCheckState>
    fun verifyGroupPeer(peer: Peer)
}
