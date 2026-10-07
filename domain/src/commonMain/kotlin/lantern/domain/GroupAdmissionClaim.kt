package lantern.domain

/**
 * Unsigned admission statement, not proof of membership.
 * IDs are opaque here; canonical wire encoding and cryptographic checks belong to protocol/adapters.
 * Membership is group-bound, not LAN/session-bound. Founding a group is a separate operation.
 */
data class GroupAdmissionClaim(val groupId: String, val issuerId: String, val memberId: String) {
    init {
        require(groupId.isNotBlank()) { "Group ID must not be blank" }
        require(issuerId.isNotBlank()) { "Issuer ID must not be blank" }
        require(memberId.isNotBlank()) { "Member ID must not be blank" }
        require(issuerId != memberId) { "An admission needs two distinct devices" }
    }

    /**
     * Binds the statement to an independently established admission context.
     * MATCHED is necessary but not sufficient: issuer membership, signature and explicit
     * confirmation must still be verified before persisting or granting authorization.
     */
    fun bindingTo(groupId: String, issuerId: String, memberId: String): GroupAdmissionBinding {
        require(groupId.isNotBlank() && issuerId.isNotBlank() && memberId.isNotBlank()) {
            "Admission context IDs must not be blank"
        }
        require(issuerId != memberId) { "Admission context needs two distinct devices" }
        return when {
            this.groupId != groupId -> GroupAdmissionBinding.GROUP_MISMATCH
            this.issuerId != issuerId -> GroupAdmissionBinding.ISSUER_MISMATCH
            this.memberId != memberId -> GroupAdmissionBinding.MEMBER_MISMATCH
            else -> GroupAdmissionBinding.MATCHED
        }
    }
}

/** Structural binding only; none of these results grants trust. */
enum class GroupAdmissionBinding {
    MATCHED,
    GROUP_MISMATCH,
    ISSUER_MISMATCH,
    MEMBER_MISMATCH,
}
