package lantern.connectivity

import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupFoundationFailure
import lantern.protocol.GroupFoundationState
import lantern.protocol.Wire
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LocalGroupFoundationTest {
    @Test
    fun osRandomOriginsReuseTheExistingIdentityWithoutRotatingItsKey() {
        val identity = createDesktopIdentity().identity()
        val id = identity.id
        val first = prepareLocalGroupFoundation(identity, null)
        val second = prepareLocalGroupFoundation(identity, null)
        assertTrue(Wire.isFingerprint(first.anchor.groupId))
        assertTrue(Wire.isFingerprint(second.anchor.groupId))
        assertNotEquals(first.anchor.groupId, second.anchor.groupId)
        assertEquals(id, first.anchor.founderId)
        assertEquals(id, second.anchor.founderId)
        val challenge = first.anchor.groupId.encodeToByteArray()
        assertTrue(Identity.verify(identity.certificate, challenge, identity.sign(challenge)))
        assertEquals(id, identity.id)
    }

    @Test
    fun existingMembershipCannotBeSilentlyReplaced() {
        val identity = createDesktopIdentity().identity()
        val existing = GroupTrustAnchor(randomNonce(), identity.id)
        assertFailsWith<IllegalArgumentException> { prepareLocalGroupFoundation(identity, existing) }
        assertEquals(identity.id, existing.founderId)
    }

    @Test
    fun osOwnerReleasesFreshOriginsOnceWithoutRotatingTheIdentity() {
        val identity = createDesktopIdentity().identity()
        val origins = List(2) {
            val owner = LocalGroupFoundation(identity)
            val ticket = assertNotNull(owner.prepare(null))
            assertEquals(GroupFoundationState.AwaitingCommit, owner.state())
            assertNull(owner.prepare(null))
            val draft = assertNotNull(owner.releaseForCommit(ticket, identity, null))
            assertEquals(GroupFoundationState.ReleasedForCommit, owner.state())
            assertNull(owner.releaseForCommit(ticket, identity, null))
            assertFalse(owner.cancel())
            assertFalse(owner.leaveGroup())
            assertEquals(identity.id, draft.anchor.founderId)
            assertTrue(Wire.isFingerprint(draft.anchor.groupId))
            val challenge = draft.anchor.groupId.encodeToByteArray()
            assertTrue(Identity.verify(identity.certificate, challenge, identity.sign(challenge)))
            draft.anchor.groupId
        }
        assertNotEquals(origins[0], origins[1])
    }

    @Test
    fun osOwnerRejectsAnotherRealIdentityAtHandoff() {
        val identity = createDesktopIdentity().identity()
        val replacement = createDesktopIdentity().identity()
        assertNotEquals(identity.id, replacement.id)
        val owner = LocalGroupFoundation(identity)
        val ticket = assertNotNull(owner.prepare(null))
        assertNull(owner.releaseForCommit(ticket, replacement, null))
        assertEquals(GroupFoundationState.Closed(GroupFoundationFailure.IdentityChanged), owner.state())
        assertNull(owner.releaseForCommit(ticket, identity, null))
    }

    @Test
    fun osOwnerRejectsMembershipBeforePreparationAndAfterIt() {
        val identity = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), identity.id)
        val alreadyMember = LocalGroupFoundation(identity)
        assertNull(alreadyMember.prepare(anchor))
        assertEquals(GroupFoundationState.Closed(GroupFoundationFailure.AlreadyInGroup), alreadyMember.state())

        val pending = LocalGroupFoundation(identity)
        val ticket = assertNotNull(pending.prepare(null))
        assertNull(pending.releaseForCommit(ticket, identity, anchor))
        assertEquals(GroupFoundationState.Closed(GroupFoundationFailure.AlreadyInGroup), pending.state())
    }

    @Test
    fun osOwnerCancellationAndLeaveRevokeOutstandingRequests() {
        val identity = createDesktopIdentity().identity()
        val cancelled = LocalGroupFoundation(identity)
        val cancelledTicket = assertNotNull(cancelled.prepare(null))
        assertTrue(cancelled.cancel())
        assertFalse(cancelled.leaveGroup())
        assertNull(cancelled.releaseForCommit(cancelledTicket, identity, null))
        assertEquals(GroupFoundationState.Closed(GroupFoundationFailure.Cancelled), cancelled.state())

        val left = LocalGroupFoundation(identity)
        val leftTicket = assertNotNull(left.prepare(null))
        assertTrue(left.leaveGroup())
        assertFalse(left.cancel())
        assertNull(left.releaseForCommit(leftTicket, identity, null))
        assertNull(left.prepare(null))
        assertEquals(GroupFoundationState.Closed(GroupFoundationFailure.LeftGroup), left.state())
    }

    @Test
    fun anotherOsOwnersTicketCannotAdvanceOrInvalidateThisRequest() {
        val identity = createDesktopIdentity().identity()
        val first = LocalGroupFoundation(identity)
        val second = LocalGroupFoundation(identity)
        val firstTicket = assertNotNull(first.prepare(null))
        val secondTicket = assertNotNull(second.prepare(null))
        val conflictingMembership = GroupTrustAnchor(randomNonce(), identity.id)
        assertNull(second.releaseForCommit(firstTicket, identity, conflictingMembership))
        assertEquals(GroupFoundationState.AwaitingCommit, second.state())
        assertNotNull(second.releaseForCommit(secondTicket, identity, null))
        assertTrue(first.cancel())
    }
}
