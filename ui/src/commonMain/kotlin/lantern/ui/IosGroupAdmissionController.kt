package lantern.ui

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import lantern.domain.GroupMembershipController
import lantern.domain.GroupMembershipCheckState
import lantern.domain.GroupAdmissionFailure
import lantern.domain.GroupAdmissionRole
import lantern.domain.GroupAdmissionState
import lantern.domain.Peer

enum class IosGroupSelectionMode { ADMISSION, MEMBERSHIP_CHECK }

/** Opaque selection identity, not a TLS permission or a recoverable consent. */
class IosGroupAdmissionSelection internal constructor(
    internal val peer: Peer,
    val replaceInterrupted: Boolean,
    val mode: IosGroupSelectionMode = IosGroupSelectionMode.ADMISSION,
) {
    val peerId: String get() = peer.id
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

/**
 * Shared presentation contract for the native service. Native callbacks only enqueue work;
 * all service publications are serialized on its queue, UI actions use StateFlow/CAS.
 * Kept in commonMain so stale UI and delayed native publications have maintained host tests.
 */
class IosGroupAdmissionController(
    private val requestSelect: (IosGroupAdmissionSelection) -> Unit,
    private val requestConfirm: (IosGroupAdmissionDisplayTicket) -> Unit,
    private val requestCancel: () -> Unit,
) : GroupMembershipController {
    private val state = MutableStateFlow<GroupAdmissionState>(GroupAdmissionState.Idle)
    private val revision = MutableStateFlow(0L)
    private var selection: IosGroupAdmissionSelection? = null
    private val displayed = MutableStateFlow<IosGroupAdmissionDisplayTicket?>(null)
    override val admissionState: StateFlow<GroupAdmissionState> = state.asStateFlow()
    override val membershipRevision: StateFlow<Long> = revision.asStateFlow()
    private val membership = MutableStateFlow<GroupMembershipCheckState>(GroupMembershipCheckState.Idle)
    override val membershipCheckState = membership.asStateFlow()

    // Public entries and service publications must use the same serial native service queue,
    // except UI actions below: their callbacks enqueue; state CAS rejects already-stale clicks.
    override fun selectGroupPeer(peer: Peer, replaceInterrupted: Boolean) {
        requestSelect(IosGroupAdmissionSelection(peer, replaceInterrupted))
    }

    override fun verifyGroupPeer(peer: Peer) {
        requestSelect(IosGroupAdmissionSelection(peer, false, IosGroupSelectionMode.MEMBERSHIP_CHECK))
    }

    fun verifyPeer(id: String, name: String) = verifyGroupPeer(Peer(id, name, "", 0))

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
        if (value.mode == IosGroupSelectionMode.ADMISSION) state.value = GroupAdmissionState.Selecting(value.peer)
        else membership.value = GroupMembershipCheckState.Checking(value.peer)
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
        if (value.mode == IosGroupSelectionMode.MEMBERSHIP_CHECK) {
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
    }

    /** Independent of selection state, including an ambiguous result or a dismissed attempt. */
    fun membershipChanged() { revision.value += 1 }
}
