package lantern.domain

import kotlinx.coroutines.flow.StateFlow

enum class LocalGroupFailure { STORAGE, INVALID_ROOT, IDENTITY_MISMATCH }

/** Local durable group only: none of these states grants peer trust or chat permission. */
sealed interface LocalGroupState {
    data object Loading : LocalGroupState
    data object Empty : LocalGroupState
    data object Creating : LocalGroupState
    data class Founded(val anchor: GroupTrustAnchor) : LocalGroupState
    data class Adopted(val anchor: GroupTrustAnchor) : LocalGroupState
    data class Failed(val reason: LocalGroupFailure) : LocalGroupState
    data object Closed : LocalGroupState
}

interface LocalGroupController {
    val state: StateFlow<LocalGroupState>
    /** Explicit user action; ignored unless the authoritative local state is Empty. */
    fun create()
    /** Explicit read-only recovery after an error; never generates an identity or a group. */
    fun reload()
    /** Read-only refresh after a separate admission owner may have committed membership. */
    fun refreshMembership() = reload()
}
