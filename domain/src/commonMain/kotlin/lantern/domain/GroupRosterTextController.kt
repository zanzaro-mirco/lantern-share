package lantern.domain

import kotlinx.coroutines.flow.StateFlow

/** Explicit author-to-recipient deliveries; no automatic fan-out or archived-session restoration. */
interface GroupRosterTextController : GroupRosterController {
    val lastRosterTextDelivery: StateFlow<StoredGroupText?>
    fun sendRosterText(peer: Peer, text: String)
    fun receiveRosterText(peer: Peer)
    fun deliverRosterText(peer: Peer, messageId: String)
}
