package lantern.domain

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class SessionSelectionTest {
    private fun session(id: String, used: Boolean = false, group: String = "group") =
        SessionCandidate(group, id, used)

    @Test
    fun noActiveSessionRequiresFreshCreation() {
        assertEquals(SessionSelection.Create, SessionSelector.select("group", emptyList()))
    }

    @Test
    fun otherGroupsDoNotInfluenceSelection() {
        assertEquals(SessionSelection.Create, SessionSelector.select("group", listOf(session("a", true, "other"))))
        val own = session("z")
        assertEquals(SessionSelection.Join(own), SessionSelector.select("group", listOf(session("a", true, "other"), own)))
    }

    @Test
    fun simultaneousEmptySessionsConvergeRegardlessOfOrder() {
        val candidates = listOf(session("c"), session("a"), session("b"))
        val expected = SessionSelection.Join(session("a"))
        for (order in listOf(candidates, candidates.reversed(), candidates.drop(1) + candidates.first())) {
            assertEquals(expected, SessionSelector.select("group", order))
        }
    }

    @Test
    fun emptySessionJoinsTheOnlyUsedSession() {
        val used = session("z", true)
        assertEquals(SessionSelection.Join(used), SessionSelector.select("group", listOf(session("a"), used)))
    }

    @Test
    fun usedSessionsNeverMergeAutomatically() {
        val candidates = listOf(session("z", true), session("a"), session("b", true))
        val decision = assertIs<SessionSelection.Choose>(SessionSelector.select("group", candidates))
        assertEquals(listOf(session("b", true), session("z", true)), decision.sessions)
        assertEquals(decision, SessionSelector.select("group", candidates.reversed()))
    }

    @Test
    fun duplicateAdvertisementsDoNotCreateAChoice() {
        val used = session("a", true)
        assertEquals(SessionSelection.Join(used), SessionSelector.select("group", listOf(used, used)))
    }

    @Test
    fun conflictingObservationsAreRejectedInEitherOrder() {
        val observations = listOf(session("a"), session("a", true))
        for (order in listOf(observations, observations.reversed())) {
            assertFailsWith<IllegalArgumentException> { SessionSelector.select("group", order) }
        }
    }

    @Test
    fun blankIdentifiersAreRejectedRatherThanNormalized() {
        assertFailsWith<IllegalArgumentException> { session(" ") }
        assertFailsWith<IllegalArgumentException> { session("a", group = "") }
        assertFailsWith<IllegalArgumentException> { SessionSelector.select("\t", emptyList()) }
    }
}
