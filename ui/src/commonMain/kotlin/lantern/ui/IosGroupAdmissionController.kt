package lantern.ui

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import lantern.domain.ContentLimits
import lantern.domain.GroupRosterTextController
import lantern.domain.StoredGroupText
import lantern.domain.GroupRosterState
import lantern.domain.GroupRosterFailure
import lantern.domain.GroupTextState
import lantern.domain.GroupTextFailure
import lantern.domain.SignedGroupText
import lantern.domain.GroupSessionState
import lantern.domain.SessionSelection
import lantern.domain.GroupMembershipCheckState
import lantern.domain.GroupAdmissionFailure
import lantern.domain.GroupAdmissionRole
import lantern.domain.GroupAdmissionState
import lantern.domain.Peer

enum class IosGroupSelectionMode { ADMISSION, MEMBERSHIP_CHECK, SESSION, TEXT, ROSTER, ROSTER_TEXT }

/** Opaque selection identity, not a TLS permission or a recoverable consent. */
class IosGroupAdmissionSelection internal constructor(
    internal val peer: Peer,
    val replaceInterrupted: Boolean,
    val mode: IosGroupSelectionMode = IosGroupSelectionMode.ADMISSION,
    val text: String? = null,
    val messageId: String? = null,
) {
    val peerId: String get() = peer.id
    val sending: Boolean get() = text != null || messageId != null
}

/** Presentation identity only. The native owner privately retains the actual Kotlin core ticket. */
class IosGroupAdmissionDisplayTicket internal constructor(
    val selection: IosGroupAdmissionSelection,
    internal val comparison: GroupAdmissionState.Comparing,
) {
    val code: String get() = comparison.code
    val groupId: String get() = comparison.groupId
}

enum class IosGroupServiceFailure { UNAVAILABLE, INTERRUPTED, FAILED, COMMIT_OUTCOME_UNKNOWN }
enum class IosGroupServicePhase { IDLE, SELECTING, COMPARING, AWAITING_PEER, COMPLETED, FAILED }
data class IosGroupServiceDisplay(val phase: IosGroupServicePhase, val groupId: String, val adoptedLocally: Boolean)
enum class IosGroupMembershipPhase { IDLE, CHECKING, VERIFIED, FAILED }
data class IosGroupMembershipDisplay(val phase: IosGroupMembershipPhase, val groupId: String)

enum class IosGroupSessionPhase { IDLE, NEGOTIATING, SELECTED, NEEDS_CHOICE, FAILED }
data class IosGroupSessionDisplay(val phase: IosGroupSessionPhase, val groupId: String, val sessionId: String)
class IosGroupSessionResult internal constructor(internal val decision: SessionSelection)

/**
 * Shared presentation contract for the native service. Native callbacks only enqueue work;
 * all service publications are serialized on its queue, UI actions use StateFlow/CAS.
 * Kept in commonMain so stale UI and delayed native publications have maintained host tests.
 */
class IosGroupAdmissionController(
    private val requestSelect: (IosGroupAdmissionSelection) -> Unit,
    private val requestConfirm: (IosGroupAdmissionDisplayTicket) -> Unit,
    private val requestCancel: () -> Unit,
) : GroupRosterTextController {
    private val state = MutableStateFlow<GroupAdmissionState>(GroupAdmissionState.Idle)
    private val revision = MutableStateFlow(0L)
    private var selection: IosGroupAdmissionSelection? = null
    private val displayed = MutableStateFlow<IosGroupAdmissionDisplayTicket?>(null)
    override val admissionState: StateFlow<GroupAdmissionState> = state.asStateFlow()
    override val membershipRevision: StateFlow<Long> = revision.asStateFlow()
    private val membership = MutableStateFlow<GroupMembershipCheckState>(GroupMembershipCheckState.Idle)
    override val membershipCheckState = membership.asStateFlow()
    private val session = MutableStateFlow<GroupSessionState>(GroupSessionState.Idle)
    override val groupSessionState = session.asStateFlow()
    private val text = MutableStateFlow<GroupTextState>(GroupTextState.Idle)
    override val groupTextState = text.asStateFlow()
    private val roster = MutableStateFlow<GroupRosterState>(GroupRosterState.Idle)
    override val groupRosterState = roster.asStateFlow()
    private val lastDelivery = MutableStateFlow<StoredGroupText?>(null)
    override val lastRosterTextDelivery = lastDelivery.asStateFlow()

    override fun sendRosterText(peer: Peer, text: String) {
        if (ContentLimits.isValidText(text)) requestSelect(IosGroupAdmissionSelection(peer, false, IosGroupSelectionMode.ROSTER_TEXT, text))
    }
    override fun receiveRosterText(peer: Peer) = requestSelect(IosGroupAdmissionSelection(peer, false, IosGroupSelectionMode.ROSTER_TEXT))
    override fun deliverRosterText(peer: Peer, messageId: String) =
        requestSelect(IosGroupAdmissionSelection(peer, false, IosGroupSelectionMode.ROSTER_TEXT, messageId = messageId))

    fun sendRosterText(id: String, name: String, body: String) = sendRosterText(Peer(id, name, "", 0), body)
    fun receiveRosterText(id: String, name: String) = receiveRosterText(Peer(id, name, "", 0))
    fun deliverRosterText(id: String, name: String, messageId: String) = deliverRosterText(Peer(id, name, "", 0), messageId)

    fun rosterTextCompleted(value: IosGroupAdmissionSelection, stored: StoredGroupText) {
        if (selection !== value || value.mode != IosGroupSelectionMode.ROSTER_TEXT || text.value !is GroupTextState.Transferring) return
        text.value = if (value.sending) GroupTextState.Sent(value.peer, stored.message) else GroupTextState.Received(value.peer, stored.message)
        if (value.sending) lastDelivery.value = StoredGroupText(stored.message, stored.receivedBy.toSet())
    }

    override fun synchronizeGroupRoster(peer: Peer) {
        requestSelect(IosGroupAdmissionSelection(peer, false, IosGroupSelectionMode.ROSTER))
    }

    fun synchronizeRoster(id: String, name: String) = synchronizeGroupRoster(Peer(id, name, "", 0))

    fun rosterCompleted(value: IosGroupAdmissionSelection, groupId: String, sessionId: String, participants: List<String>) {
        if (selection === value && value.mode == IosGroupSelectionMode.ROSTER && roster.value is GroupRosterState.Synchronizing) {
            roster.value = GroupRosterState.Synchronized(value.peer, groupId, sessionId, participants.toSet())
        }
    }

    fun rosterFailed(value: IosGroupAdmissionSelection, reason: IosGroupRosterFailure) {
        if (selection === value && value.mode == IosGroupSelectionMode.ROSTER && roster.value is GroupRosterState.Synchronizing) {
            roster.value = GroupRosterState.Failed(value.peer, GroupRosterFailure.valueOf(reason.name))
        }
    }

    fun rosterSnapshot(): IosGroupRosterDisplay = when (val current = roster.value) {
        GroupRosterState.Idle -> IosGroupRosterDisplay(IosGroupRosterPhase.IDLE, "", emptyList(), null)
        is GroupRosterState.Synchronizing -> IosGroupRosterDisplay(IosGroupRosterPhase.SYNCHRONIZING, "", emptyList(), null)
        is GroupRosterState.Synchronized -> IosGroupRosterDisplay(IosGroupRosterPhase.SYNCHRONIZED, current.sessionId, current.participants.sorted(), null)
        is GroupRosterState.Failed -> IosGroupRosterDisplay(IosGroupRosterPhase.FAILED, "", emptyList(), IosGroupRosterFailure.valueOf(current.reason.name))
    }

    override fun sendGroupText(peer: Peer, text: String) {
        if (ContentLimits.isValidText(text)) requestSelect(IosGroupAdmissionSelection(peer, false, IosGroupSelectionMode.TEXT, text))
    }

    override fun receiveGroupText(peer: Peer) {
        requestSelect(IosGroupAdmissionSelection(peer, false, IosGroupSelectionMode.TEXT))
    }

    fun sendText(id: String, name: String, body: String) = sendGroupText(Peer(id, name, "", 0), body)
    fun receiveText(id: String, name: String) = receiveGroupText(Peer(id, name, "", 0))

    // Public entries and service publications must use the same serial native service queue,
    // except UI actions below: their callbacks enqueue; state CAS rejects already-stale clicks.
    override fun selectGroupPeer(peer: Peer, replaceInterrupted: Boolean) {
        requestSelect(IosGroupAdmissionSelection(peer, replaceInterrupted))
    }

    override fun verifyGroupPeer(peer: Peer) {
        requestSelect(IosGroupAdmissionSelection(peer, false, IosGroupSelectionMode.MEMBERSHIP_CHECK))
    }

    fun verifyPeer(id: String, name: String) = verifyGroupPeer(Peer(id, name, "", 0))

    override fun negotiateGroupSession(peer: Peer) {
        requestSelect(IosGroupAdmissionSelection(peer, false, IosGroupSelectionMode.SESSION))
    }

    fun negotiateSession(id: String, name: String) = negotiateGroupSession(Peer(id, name, "", 0))

    override fun confirmGroup(comparison: GroupAdmissionState.Comparing) {
        val current = displayed.value ?: return
        if (current.comparison !== comparison || !state.compareAndSet(comparison, GroupAdmissionState.AwaitingPeer(comparison.peer))) return
        requestConfirm(current)
    }

    override fun cancelGroup() = requestCancel()

    fun selectPeer(id: String, name: String, replaceInterrupted: Boolean) =
        selectGroupPeer(Peer(id, name, "", 0), replaceInterrupted)

    fun confirmDisplayed(ticket: IosGroupAdmissionDisplayTicket) = confirmGroup(ticket.comparison)

    fun displayedComparison(): IosGroupAdmissionDisplayTicket? = displayed.value

    fun snapshot(): IosGroupServiceDisplay = when (val current = state.value) {
        GroupAdmissionState.Idle -> IosGroupServiceDisplay(IosGroupServicePhase.IDLE, "", false)
        is GroupAdmissionState.Selecting -> IosGroupServiceDisplay(IosGroupServicePhase.SELECTING, "", false)
        is GroupAdmissionState.Comparing -> IosGroupServiceDisplay(IosGroupServicePhase.COMPARING, current.groupId, false)
        is GroupAdmissionState.AwaitingPeer -> IosGroupServiceDisplay(IosGroupServicePhase.AWAITING_PEER, "", false)
        is GroupAdmissionState.Completed -> IosGroupServiceDisplay(IosGroupServicePhase.COMPLETED, current.groupId, current.adoptedLocally)
        is GroupAdmissionState.Failed -> IosGroupServiceDisplay(IosGroupServicePhase.FAILED, "", false)
    }

    /** Native caller starts the selection before TLS and after retiring its preceding owner. */
    fun selected(value: IosGroupAdmissionSelection) {
        selection = value
        displayed.value = null
        state.value = GroupAdmissionState.Idle
        membership.value = GroupMembershipCheckState.Idle
        session.value = GroupSessionState.Idle
        text.value = GroupTextState.Idle
        roster.value = GroupRosterState.Idle
        when (value.mode) {
            IosGroupSelectionMode.ADMISSION -> state.value = GroupAdmissionState.Selecting(value.peer)
            IosGroupSelectionMode.MEMBERSHIP_CHECK -> membership.value = GroupMembershipCheckState.Checking(value.peer)
            IosGroupSelectionMode.SESSION -> session.value = GroupSessionState.Negotiating(value.peer)
            IosGroupSelectionMode.TEXT, IosGroupSelectionMode.ROSTER_TEXT -> text.value = GroupTextState.Waiting(value.peer, value.sending)
            IosGroupSelectionMode.ROSTER -> roster.value = GroupRosterState.Synchronizing(value.peer)
        }
    }

    fun textTransferring(value: IosGroupAdmissionSelection) {
        if (selection === value && (value.mode == IosGroupSelectionMode.TEXT || value.mode == IosGroupSelectionMode.ROSTER_TEXT) && text.value is GroupTextState.Waiting) {
            text.value = GroupTextState.Transferring(value.peer)
        }
    }

    fun textCompleted(value: IosGroupAdmissionSelection, message: SignedGroupText) {
        if (selection !== value || value.mode != IosGroupSelectionMode.TEXT || text.value !is GroupTextState.Transferring) return
        text.value = if (value.text != null) GroupTextState.Sent(value.peer, message) else GroupTextState.Received(value.peer, message)
    }

    fun textFailed(value: IosGroupAdmissionSelection, reason: IosGroupTextFailure, attemptedMessageId: String?) {
        if (selection !== value || (value.mode != IosGroupSelectionMode.TEXT && value.mode != IosGroupSelectionMode.ROSTER_TEXT) ||
            (text.value !is GroupTextState.Waiting && text.value !is GroupTextState.Transferring)) return
        text.value = GroupTextState.Failed(value.peer, GroupTextFailure.valueOf(reason.name), attemptedMessageId)
    }

    fun textSnapshot(): IosGroupTextDisplay = when (val current = text.value) {
        GroupTextState.Idle -> IosGroupTextDisplay(IosGroupTextPhase.IDLE, "", "", "", null)
        is GroupTextState.Waiting -> IosGroupTextDisplay(IosGroupTextPhase.WAITING, "", "", "", null)
        is GroupTextState.Transferring -> IosGroupTextDisplay(IosGroupTextPhase.TRANSFERRING, "", "", "", null)
        is GroupTextState.Sent -> IosGroupTextDisplay(IosGroupTextPhase.SENT, current.message.content.id, current.message.content.sessionId, current.message.content.body, null)
        is GroupTextState.Received -> IosGroupTextDisplay(IosGroupTextPhase.RECEIVED, current.message.content.id, current.message.content.sessionId, current.message.content.body, null)
        is GroupTextState.Failed -> IosGroupTextDisplay(IosGroupTextPhase.FAILED, current.attemptedMessageId.orEmpty(), "", "", IosGroupTextFailure.valueOf(current.reason.name))
    }

    fun sessionSnapshot(): IosGroupSessionDisplay = when (val current = session.value) {
        GroupSessionState.Idle -> IosGroupSessionDisplay(IosGroupSessionPhase.IDLE, "", "")
        is GroupSessionState.Negotiating -> IosGroupSessionDisplay(IosGroupSessionPhase.NEGOTIATING, "", "")
        is GroupSessionState.Selected -> IosGroupSessionDisplay(IosGroupSessionPhase.SELECTED, current.session.groupId, current.session.sessionId)
        is GroupSessionState.NeedsChoice -> IosGroupSessionDisplay(IosGroupSessionPhase.NEEDS_CHOICE, "", "")
        is GroupSessionState.Failed -> IosGroupSessionDisplay(IosGroupSessionPhase.FAILED, "", "")
    }

    fun sessionSelected(value: IosGroupAdmissionSelection, result: IosGroupSessionResult) {
        if (selection !== value || value.mode != IosGroupSelectionMode.SESSION || session.value !is GroupSessionState.Negotiating) return
        session.value = when (val decision = result.decision) {
            is SessionSelection.Join -> GroupSessionState.Selected(value.peer, decision.session)
            is SessionSelection.Choose -> GroupSessionState.NeedsChoice(value.peer, decision.sessions)
            SessionSelection.Create -> GroupSessionState.Failed(value.peer, GroupAdmissionFailure.FAILED)
        }
    }

    fun membershipSnapshot(): IosGroupMembershipDisplay = when (val current = membership.value) {
        GroupMembershipCheckState.Idle -> IosGroupMembershipDisplay(IosGroupMembershipPhase.IDLE, "")
        is GroupMembershipCheckState.Checking -> IosGroupMembershipDisplay(IosGroupMembershipPhase.CHECKING, "")
        is GroupMembershipCheckState.Verified -> IosGroupMembershipDisplay(IosGroupMembershipPhase.VERIFIED, current.groupId)
        is GroupMembershipCheckState.Failed -> IosGroupMembershipDisplay(IosGroupMembershipPhase.FAILED, "")
    }

    fun membershipVerified(value: IosGroupAdmissionSelection, groupId: String) {
        if (selection !== value || value.mode != IosGroupSelectionMode.MEMBERSHIP_CHECK ||
            membership.value !is GroupMembershipCheckState.Checking) return
        membership.value = GroupMembershipCheckState.Verified(value.peer, groupId)
    }

    fun comparing(value: IosGroupAdmissionSelection, issuer: Boolean, groupId: String, code: String): IosGroupAdmissionDisplayTicket? {
        if (selection !== value || state.value !is GroupAdmissionState.Selecting) return null
        val comparison = GroupAdmissionState.Comparing(value.peer,
            if (issuer) GroupAdmissionRole.ISSUER else GroupAdmissionRole.NEW_MEMBER, groupId, code)
        return IosGroupAdmissionDisplayTicket(value, comparison).also {
            displayed.value = it
            state.value = comparison
        }
    }

    fun completed(value: IosGroupAdmissionSelection, groupId: String, adoptedLocally: Boolean) {
        if (selection !== value || value.mode != IosGroupSelectionMode.ADMISSION || state.value is GroupAdmissionState.Failed) return
        displayed.value = null
        state.value = GroupAdmissionState.Completed(groupId, adoptedLocally)
    }

    fun failed(value: IosGroupAdmissionSelection, reason: IosGroupServiceFailure) {
        if (selection !== value || state.value is GroupAdmissionState.Completed) return
        displayed.value = null
        val failure = when (reason) {
            IosGroupServiceFailure.UNAVAILABLE -> GroupAdmissionFailure.UNAVAILABLE
            IosGroupServiceFailure.INTERRUPTED -> GroupAdmissionFailure.INTERRUPTED
            IosGroupServiceFailure.FAILED -> GroupAdmissionFailure.FAILED
            IosGroupServiceFailure.COMMIT_OUTCOME_UNKNOWN -> GroupAdmissionFailure.COMMIT_OUTCOME_UNKNOWN
        }
        if (value.mode == IosGroupSelectionMode.ROSTER) {
            rosterFailed(value, if (reason == IosGroupServiceFailure.UNAVAILABLE) IosGroupRosterFailure.UNAVAILABLE else IosGroupRosterFailure.FAILED)
        } else if (value.mode == IosGroupSelectionMode.TEXT || value.mode == IosGroupSelectionMode.ROSTER_TEXT) {
            textFailed(value, if (reason == IosGroupServiceFailure.UNAVAILABLE) IosGroupTextFailure.UNAVAILABLE else IosGroupTextFailure.FAILED, null)
        } else if (value.mode == IosGroupSelectionMode.SESSION) {
            if (session.value is GroupSessionState.Negotiating) session.value = GroupSessionState.Failed(value.peer, failure)
        } else if (value.mode == IosGroupSelectionMode.MEMBERSHIP_CHECK) {
            if (membership.value !is GroupMembershipCheckState.Verified) {
                membership.value = GroupMembershipCheckState.Failed(value.peer, failure)
            }
        } else state.value = GroupAdmissionState.Failed(value.peer, failure)
    }

    fun cancelled() {
        selection = null
        displayed.value = null
        state.value = GroupAdmissionState.Idle
        membership.value = GroupMembershipCheckState.Idle
        session.value = GroupSessionState.Idle
        text.value = GroupTextState.Idle
        roster.value = GroupRosterState.Idle
    }

    /** Independent of selection state, including an ambiguous result or a dismissed attempt. */
    fun membershipChanged() { revision.value += 1 }
}

enum class IosGroupTextPhase { IDLE, WAITING, TRANSFERRING, SENT, RECEIVED, FAILED }
enum class IosGroupTextFailure { UNAVAILABLE, ROSTER_REQUIRED, SESSION_CHOICE_REQUIRED, FAILED }
data class IosGroupTextDisplay(val phase: IosGroupTextPhase, val messageId: String, val sessionId: String,
                             val body: String, val failure: IosGroupTextFailure?)

enum class IosGroupRosterPhase { IDLE, SYNCHRONIZING, SYNCHRONIZED, FAILED }
enum class IosGroupRosterFailure { UNAVAILABLE, SESSION_CHOICE_REQUIRED, MISSING_PARTICIPANTS, FAILED }
data class IosGroupRosterDisplay(val phase: IosGroupRosterPhase, val sessionId: String,
                               val participants: List<String>, val failure: IosGroupRosterFailure?)
