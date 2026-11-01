package lantern.domain

/** An active session observed on the current LAN, not an archived history entry. */
data class SessionCandidate(val groupId: String, val sessionId: String, val used: Boolean) {
    init {
        require(groupId.isNotBlank()) { "Group ID must not be blank" }
        require(sessionId.isNotBlank()) { "Session ID must not be blank" }
    }
}

sealed interface SessionSelection {
    /** The caller must generate a fresh random ID; it must not revive an archived session. */
    data object Create : SessionSelection
    data class Join(val session: SessionCandidate) : SessionSelection
    data class Choose(val sessions: List<SessionCandidate>) : SessionSelection
}

/**
 * Pure selection policy, not an admission or authorization check.
 * The caller supplies a current, authenticated snapshot, including its own active session.
 * History, stale discovery entries and sessions from a previous LAN must not be supplied.
 * `used` is monotonic for a session: removing local history does not make it empty again.
 */
/** Local effect of an explicit choice among used sessions (ADR 022). */
sealed interface SessionChoiceEffect {
    /** The chosen session is already the held one: nothing changes. */
    data object Keep : SessionChoiceEffect
    /** The held session is abandoned for the peer's. Scope is unknown until a signed roster restores it. */
    data class Adopt(val session: SessionCandidate) : SessionChoiceEffect
}

object SessionChoice {
    /**
     * [offered] is the `Choose` list, [held] this device's own session. Both must be in it and [chosen]
     * must be one of them: a stale or foreign choice is refused, never guessed. Never merges sessions.
     */
    fun apply(offered: List<SessionCandidate>, held: SessionCandidate, chosen: SessionCandidate): SessionChoiceEffect {
        require(offered.any { it.sessionId == held.sessionId }) { "Held session is not among the offered ones" }
        val match = requireNotNull(offered.firstOrNull { it.sessionId == chosen.sessionId && it.groupId == chosen.groupId }) {
            "Chosen session was not offered"
        }
        return if (match.sessionId == held.sessionId) SessionChoiceEffect.Keep
        else SessionChoiceEffect.Adopt(match.copy(used = true))
    }
}

object SessionSelector {
    fun select(groupId: String, candidates: List<SessionCandidate>): SessionSelection {
        require(groupId.isNotBlank()) { "Group ID must not be blank" }
        val sessions = candidates.filter { it.groupId == groupId }
            .groupBy { it.sessionId }
            .map { (_, observations) ->
                // Only `used` can differ (ADR 021): an interrupted delivery leaves the author used and the
                // receiver empty. Join the monotonic flag, independent of arrival order, never downgrading.
                observations.first().copy(used = observations.any { it.used })
            }
            .sortedBy { it.sessionId }
        if (sessions.isEmpty()) return SessionSelection.Create

        val used = sessions.filter { it.used }
        return when (used.size) {
            0 -> SessionSelection.Join(sessions.first())
            1 -> SessionSelection.Join(used.single())
            else -> SessionSelection.Choose(used)
        }
    }
}
