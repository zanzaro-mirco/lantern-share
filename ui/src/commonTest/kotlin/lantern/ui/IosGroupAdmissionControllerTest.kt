package lantern.ui

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import lantern.domain.GroupAdmissionState
import lantern.domain.GroupMembershipCheckState
import lantern.domain.GroupSessionState
import lantern.domain.SessionCandidate
import lantern.domain.SessionSelection
import lantern.domain.Peer

class IosGroupAdmissionControllerTest {
    @Test
    fun rosterSelectionRejectsStaleResultsAndPreservesInstalledFactAfterCleanup() {
        controller.synchronizeGroupRoster(peer)
        val old = selections.last()
        assertEquals(IosGroupSelectionMode.ROSTER, old.mode)
        controller.selected(old)
        controller.synchronizeRoster(peer.id, peer.name)
        val current = selections.last()
        controller.selected(current)
        controller.rosterCompleted(old, "b".repeat(64), "c".repeat(64), listOf(peer.id))
        controller.rosterFailed(old, IosGroupRosterFailure.FAILED)
        assertEquals(IosGroupRosterPhase.SYNCHRONIZING, controller.rosterSnapshot().phase)
        val participants = mutableListOf(peer.id, "d".repeat(64))
        controller.rosterCompleted(current, "b".repeat(64), "c".repeat(64), participants)
        participants.clear()
        controller.failed(current, IosGroupServiceFailure.FAILED)
        controller.rosterFailed(current, IosGroupRosterFailure.FAILED)
        assertEquals(IosGroupRosterPhase.SYNCHRONIZED, controller.rosterSnapshot().phase)
        assertEquals(2, controller.rosterSnapshot().participants.size)
        assertEquals(0L, controller.membershipRevision.value)
        controller.cancelled()
        controller.rosterCompleted(current, "b".repeat(64), "c".repeat(64), listOf(peer.id))
        assertEquals(IosGroupRosterPhase.IDLE, controller.rosterSnapshot().phase)
    }

    @Test
    fun rosterFailuresAreSeparateFromAdmissionAndText() {
        controller.synchronizeGroupRoster(peer)
        val selected = selections.last()
        controller.selected(selected)
        controller.rosterFailed(selected, IosGroupRosterFailure.MISSING_PARTICIPANTS)
        assertEquals(IosGroupRosterFailure.MISSING_PARTICIPANTS, controller.rosterSnapshot().failure)
        assertSame(lantern.domain.GroupAdmissionState.Idle, controller.admissionState.value)
        assertSame(lantern.domain.GroupTextState.Idle, controller.groupTextState.value)
    }

    private val peer = Peer("a".repeat(64), "iPhone", "", 0)
    private val selections = mutableListOf<IosGroupAdmissionSelection>()
    private val clicks = mutableListOf<IosGroupAdmissionDisplayTicket>()
    private var cancels = 0
    private val controller = IosGroupAdmissionController(selections::add, clicks::add, { cancels++ })

    @Test
    fun textSelectionFreezesBodyRejectsOldResultAndKeepsDurableCompletionAfterCleanupFailure() {
        controller.sendText(peer.id, peer.name, "primo")
        val old = selections.last()
        assertEquals(IosGroupSelectionMode.TEXT, old.mode)
        assertEquals("primo", old.text)
        controller.selected(old)
        controller.receiveGroupText(peer)
        val next = selections.last()
        assertNull(next.text)
        controller.selected(next)
        controller.textTransferring(old)
        controller.textFailed(old, IosGroupTextFailure.FAILED, "old")
        assertEquals(IosGroupTextPhase.WAITING, controller.textSnapshot().phase)
        val message = lantern.domain.SignedGroupText(lantern.domain.GroupTextContent(
            "12345678-1234-1234-1234-123456789abc", "b".repeat(64), "c".repeat(64), peer.id,
            1, 1, listOf(peer.id), "ricevuto"), "signature")
        controller.textCompleted(next, message) // Not before native transfer admission.
        assertEquals(IosGroupTextPhase.WAITING, controller.textSnapshot().phase)
        controller.textTransferring(next)
        controller.textCompleted(next, message)
        controller.failed(next, IosGroupServiceFailure.FAILED)
        controller.textFailed(next, IosGroupTextFailure.FAILED, message.content.id)
        assertEquals(IosGroupTextPhase.RECEIVED, controller.textSnapshot().phase)
        assertEquals("ricevuto", controller.textSnapshot().body)
        controller.cancelled()
        controller.textCompleted(next, message)
        assertEquals(IosGroupTextPhase.IDLE, controller.textSnapshot().phase)
        assertSame(lantern.domain.GroupTextState.Idle, controller.groupTextState.value)
    }

    @Test
    fun textFailureIsSeparateFromAdmissionAndInvalidBodyNeverDispatches() {
        controller.sendText(peer.id, peer.name, "")
        assertEquals(0, selections.size)
        controller.sendText(peer.id, peer.name, "valido")
        val current = selections.single()
        controller.selected(current)
        controller.textTransferring(current)
        controller.textFailed(current, IosGroupTextFailure.ROSTER_REQUIRED, "potential-copy")
        assertEquals(IosGroupTextFailure.ROSTER_REQUIRED, controller.textSnapshot().failure)
        assertEquals("potential-copy", controller.textSnapshot().messageId)
        assertSame(GroupAdmissionState.Idle, controller.admissionState.value)
        assertEquals(0L, controller.membershipRevision.value)
    }

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
    fun membershipModeDoesNotExposeComparisonCommitOrWakeMembershipReload() {
        controller.verifyGroupPeer(peer)
        val selection = selections.single()
        assertEquals(IosGroupSelectionMode.MEMBERSHIP_CHECK, selection.mode)
        controller.selected(selection)
        assertIs<GroupMembershipCheckState.Checking>(controller.membershipCheckState.value)
        assertSame(GroupAdmissionState.Idle, controller.admissionState.value)
        assertNull(controller.comparing(selection, true, "b".repeat(64), "c".repeat(64)))
        controller.completed(selection, "b".repeat(64), true)
        assertSame(GroupAdmissionState.Idle, controller.admissionState.value)
        controller.membershipVerified(selection, "b".repeat(64))
        controller.failed(selection, IosGroupServiceFailure.FAILED)
        assertEquals(IosGroupMembershipPhase.VERIFIED, controller.membershipSnapshot().phase)
        assertEquals(0L, controller.membershipRevision.value)
        assertEquals(emptyList(), clicks)
    }

    @Test
    fun cancelledOrReplacedMembershipCallbacksCannotPublishLateSuccess() {
        controller.verifyGroupPeer(peer)
        val old = selections.last()
        controller.selected(old)
        controller.cancelled()
        controller.membershipVerified(old, "b".repeat(64))
        assertEquals(IosGroupMembershipPhase.IDLE, controller.membershipSnapshot().phase)
        controller.verifyPeer(peer.id, peer.name)
        val next = selections.last()
        controller.selected(next)
        controller.membershipVerified(old, "b".repeat(64))
        controller.failed(next, IosGroupServiceFailure.UNAVAILABLE)
        controller.membershipVerified(next, "b".repeat(64))
        assertEquals(IosGroupMembershipPhase.FAILED, controller.membershipSnapshot().phase)
        controller.selectGroupPeer(peer)
        controller.selected(selections.last())
        controller.membershipVerified(next, "b".repeat(64))
        assertEquals(IosGroupMembershipPhase.IDLE, controller.membershipSnapshot().phase)
        assertIs<GroupAdmissionState.Selecting>(controller.admissionState.value)
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

    @Test
    fun sessionModePublishesOnlyOneDecisionWithoutComparisonOrMembershipAuthority() {
        controller.negotiateGroupSession(peer)
        val selected = selections.single()
        assertEquals(IosGroupSelectionMode.SESSION, selected.mode)
        controller.selected(selected)
        assertIs<GroupSessionState.Negotiating>(controller.groupSessionState.value)
        assertNull(controller.comparing(selected, true, "b".repeat(64), "c".repeat(64)))
        controller.membershipVerified(selected, "b".repeat(64))
        controller.completed(selected, "b".repeat(64), true)
        val session = SessionCandidate("b".repeat(64), "c".repeat(64), false)
        controller.sessionSelected(selected, IosGroupSessionResult(SessionSelection.Join(session)))
        controller.failed(selected, IosGroupServiceFailure.FAILED)
        controller.sessionSelected(selected, IosGroupSessionResult(SessionSelection.Create))
        assertEquals(session, assertIs<GroupSessionState.Selected>(controller.groupSessionState.value).session)
        assertEquals(session.sessionId, controller.sessionSnapshot().sessionId)
        assertEquals(0L, controller.membershipRevision.value)
        assertEquals(IosGroupMembershipPhase.IDLE, controller.membershipSnapshot().phase)
        assertSame(GroupAdmissionState.Idle, controller.admissionState.value)
    }

    @Test
    fun exactSessionSelectionRejectsOldSamePeerCallbackAndFailedOrCancelledSuccess() {
        controller.negotiateSession(peer.id, peer.name)
        val old = selections.last()
        controller.selected(old)
        controller.cancelled()
        controller.negotiateSession(peer.id, peer.name)
        val next = selections.last()
        controller.selected(next)
        val result = IosGroupSessionResult(SessionSelection.Join(SessionCandidate("b".repeat(64), "c".repeat(64), false)))
        controller.sessionSelected(old, result)
        controller.failed(old, IosGroupServiceFailure.FAILED)
        assertEquals(IosGroupSessionPhase.NEGOTIATING, controller.sessionSnapshot().phase)
        controller.failed(next, IosGroupServiceFailure.FAILED)
        controller.sessionSelected(next, result)
        assertEquals(IosGroupSessionPhase.FAILED, controller.sessionSnapshot().phase)
        controller.cancelled()
        controller.sessionSelected(next, result)
        assertEquals(IosGroupSessionPhase.IDLE, controller.sessionSnapshot().phase)
    }

    @Test
    fun usedSessionsNeedChoiceAndAdmissionCannotConsumeSessionResult() {
        val sessions = listOf(SessionCandidate("b".repeat(64), "c".repeat(64), true),
            SessionCandidate("b".repeat(64), "d".repeat(64), true))
        controller.negotiateGroupSession(peer)
        val selected = selections.last()
        controller.selected(selected)
        controller.sessionSelected(selected, IosGroupSessionResult(SessionSelection.Choose(sessions)))
        controller.failed(selected, IosGroupServiceFailure.FAILED)
        assertEquals(sessions, assertIs<GroupSessionState.NeedsChoice>(controller.groupSessionState.value).sessions)
        controller.selectGroupPeer(peer)
        val admission = selections.last()
        controller.selected(admission)
        controller.sessionSelected(admission, IosGroupSessionResult(SessionSelection.Join(sessions.first())))
        assertSame(GroupSessionState.Idle, controller.groupSessionState.value)
    }
}
