package lantern.domain

/**
 * Independently established group origin, not a self-signed admission or an admin role.
 * Constructing this value does not establish trust: callers must obtain it from local founding
 * or an explicitly confirmed admission, never adopt the anchor advertised by an unknown peer.
 * IDs remain opaque in domain; protocol validates their canonical representation.
 */
data class GroupTrustAnchor(val groupId: String, val founderId: String) {
    init {
        require(groupId.isNotBlank()) { "Group ID must not be blank" }
        require(founderId.isNotBlank()) { "Founder ID must not be blank" }
    }
}
