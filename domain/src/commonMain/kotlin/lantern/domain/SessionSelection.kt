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
object SessionSelector {
    fun select(groupId: String, candidates: List<SessionCandidate>): SessionSelection {
        require(groupId.isNotBlank()) { "Group ID must not be blank" }
        val sessions = candidates.filter { it.groupId == groupId }
            .groupBy { it.sessionId }
            .map { (_, observations) ->
                // Do not resolve contradictory observations by arrival order or guesswork.
                require(observations.all { it == observations.first() }) {
                    "Conflicting observations for the same session"
                }
                observations.first()
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
