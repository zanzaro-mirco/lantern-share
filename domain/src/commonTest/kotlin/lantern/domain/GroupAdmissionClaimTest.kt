package lantern.domain

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class GroupAdmissionClaimTest {
    private val claim = GroupAdmissionClaim("group", "issuer", "member")

    @Test
    fun bindsToExactlyTheExpectedGroupAndDevices() {
        assertEquals(GroupAdmissionBinding.MATCHED, claim.bindingTo("group", "issuer", "member"))
    }

    @Test
    fun anotherGroupCannotReuseTheStatement() {
        assertEquals(GroupAdmissionBinding.GROUP_MISMATCH, claim.bindingTo("other", "issuer", "member"))
    }

    @Test
    fun anotherIssuerCannotReuseTheStatement() {
        assertEquals(GroupAdmissionBinding.ISSUER_MISMATCH, claim.bindingTo("group", "other", "member"))
    }

    @Test
    fun anotherRecipientCannotReuseTheStatement() {
        assertEquals(GroupAdmissionBinding.MEMBER_MISMATCH, claim.bindingTo("group", "issuer", "other"))
    }

    @Test
    fun rolesAreDirectionalAndCannotBeReflected() {
        assertNotEquals(GroupAdmissionBinding.MATCHED, claim.bindingTo("group", "member", "issuer"))
        assertNotEquals(claim, GroupAdmissionClaim("group", "member", "issuer"))
    }

    @Test
    fun selfAdmissionIsNotGroupCreation() {
        assertFailsWith<IllegalArgumentException> { GroupAdmissionClaim("group", "issuer", "issuer") }
        assertFailsWith<IllegalArgumentException> { claim.bindingTo("group", "issuer", "issuer") }
    }

    @Test
    fun blankClaimFieldsAreRejected() {
        for (blank in listOf("", " ", "\t\n")) {
            assertFailsWith<IllegalArgumentException> { GroupAdmissionClaim(blank, "issuer", "member") }
            assertFailsWith<IllegalArgumentException> { GroupAdmissionClaim("group", blank, "member") }
            assertFailsWith<IllegalArgumentException> { GroupAdmissionClaim("group", "issuer", blank) }
        }
    }

    @Test
    fun blankContextFieldsAreRejected() {
        assertFailsWith<IllegalArgumentException> { claim.bindingTo("", "issuer", "member") }
        assertFailsWith<IllegalArgumentException> { claim.bindingTo("group", " ", "member") }
        assertFailsWith<IllegalArgumentException> { claim.bindingTo("group", "issuer", "\n") }
    }

    @Test
    fun identifiersAreNeverNormalizedIntoAMatch() {
        assertEquals(GroupAdmissionBinding.GROUP_MISMATCH, claim.bindingTo("group ", "issuer", "member"))
        assertEquals(GroupAdmissionBinding.ISSUER_MISMATCH, claim.bindingTo("group", "ISSUER", "member"))
        assertEquals(GroupAdmissionBinding.MEMBER_MISMATCH, claim.bindingTo("group", "issuer", " member"))
    }
}
