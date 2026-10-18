package lantern.domain

/** Durable local root, whether founded or adopted; not session state or peer authorization. */
interface LocalGroupRepository {
    /** Null means neither foundation nor adoption. Corrupt/unreadable storage must fail. */
    fun localGroup(): GroupTrustAnchor?

    /**
     * Atomically insert only if absent; never replace an existing origin, even an identical one.
     * The anchor must come from an explicit local foundation and match the current OS identity.
     * The caller serializes identity changes/cancellation with this synchronous operation.
     * True acknowledges a committed insert, false means a group already exists; I/O errors throw.
     * This does not authorize peers or prove that a distributed admission completed.
     */
    fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean
}
