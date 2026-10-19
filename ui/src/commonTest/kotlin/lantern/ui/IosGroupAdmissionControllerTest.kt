package lantern.ui

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import lantern.domain.GroupAdmissionState
import lantern.domain.Peer

class IosGroupAdmissionControllerTest {
    private val peer = Peer("a".repeat(64), "iPhone", "", 0)
    private val selections = mutableListOf<IosGroupAdmissionSelection>()
    private val clicks = mutableListOf<IosGroupAdmissionDisplayTicket>()
    private var cancels = 0
    private val controller = IosGroupAdmissionController(selections::add, clicks::add, { cancels++ })

    @Test
    fun onlyExactDisplayedComparisonCanDispatchOneNativeClick() {
        controller.selectGroupPeer(peer)
        val selection = selections.single()
        controller.selected(selection)
        val display = assertNotNull(controller.comparing(selection, false, "b".repeat(64), "c".repeat(64)))
        val state = assertIs<GroupAdmissionState.Comparing>(controller.admissionState.value)
        controller.confirmGroup(state.copy())
        assertEquals(emptyList(), clicks)
        controller.confirmGroup(state)
        controller.confirmDisplayed(display)
        assertSame(display, clicks.single())
        assertIs<GroupAdmissionState.AwaitingPeer>(controller.admissionState.value)
    }

    @Test
    fun replacementAndCancelRejectOldPublicationsAndClicks() {
        controller.selectGroupPeer(peer)
        val first = selections.last()
        controller.selected(first)
        val display = assertNotNull(controller.comparing(first, true, "b".repeat(64), "c".repeat(64)))
        controller.selectGroupPeer(peer, replaceInterrupted = true)
        val next = selections.last()
        assertEquals(true, next.replaceInterrupted)
        controller.selected(next)
        controller.confirmDisplayed(display)
        controller.completed(first, "b".repeat(64), true)
        controller.failed(first, IosGroupServiceFailure.FAILED)
        assertNull(controller.comparing(first, false, "b".repeat(64), "c".repeat(64)))
        assertIs<GroupAdmissionState.Selecting>(controller.admissionState.value)
        assertEquals(emptyList(), clicks)
        controller.cancelGroup()
        assertEquals(1, cancels)
        controller.cancelled()
        controller.completed(next, "b".repeat(64), true)
        assertSame(GroupAdmissionState.Idle, controller.admissionState.value)
    }

    @Test
    fun membershipRefreshSurvivesDismissalButNeverClaimsMembershipItself() {
        controller.selectGroupPeer(peer)
        val selection = selections.single()
        controller.selected(selection)
        controller.failed(selection, IosGroupServiceFailure.COMMIT_OUTCOME_UNKNOWN)
        controller.cancelled()
        controller.membershipChanged()
        assertEquals(1L, controller.membershipRevision.value)
        assertSame(GroupAdmissionState.Idle, controller.admissionState.value)
    }

    @Test
    fun issuerCompletionCannotBeOverwrittenByLaterEOFOrShownAsRemoteSave() {
        controller.selectGroupPeer(peer)
        val selection = selections.single()
        controller.selected(selection)
        controller.completed(selection, "b".repeat(64), false)
        controller.failed(selection, IosGroupServiceFailure.FAILED)
        val completed = assertIs<GroupAdmissionState.Completed>(controller.admissionState.value)
        assertEquals(false, completed.adoptedLocally)
    }
}
