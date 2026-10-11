package lantern.protocol

import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertSame

/** Repository doubles only exercise common ownership boundaries; SQLite is tested separately. */
class GroupFoundationCommitTest {
    private val identity = "a".repeat(64)
    private val group = "b".repeat(64)

    @Test
    fun acknowledgementFollowsWriteAndConsumedTicketNeverReadsAgain() {
        val owner = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(owner.prepare(null) { group })
        val store = Store()
        store.onWrite = {
            assertEquals(GroupFoundationState.ReleasedForCommit, owner.state())
            assertEquals(GroupTrustAnchor(group, identity), it)
        }
        assertEquals(GroupFoundationCommit.Committed, owner.commit(ticket, identity, store))
        assertEquals(1, store.reads)
        assertEquals(1, store.writes)
        assertEquals(GroupFoundationCommit.Invalidated, owner.commit(ticket, identity, store))
        assertEquals(1, store.reads)
        assertFalse(owner.cancel())
    }

    @Test
    fun preliminaryReadFailureHasNotConsumedTheTicket() {
        val owner = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(owner.prepare(null) { group })
        val store = Store()
        val failure = IllegalStateException("read failed")
        store.onRead = { throw failure }
        assertSame(failure, assertFailsWith<IllegalStateException> { owner.commit(ticket, identity, store) })
        assertEquals(GroupFoundationState.AwaitingCommit, owner.state())
        assertEquals(0, store.writes)
        store.onRead = {}
        assertEquals(GroupFoundationCommit.Committed, owner.commit(ticket, identity, store))
    }

    @Test
    fun failureAfterHandoffPropagatesWithoutReplay() {
        val owner = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(owner.prepare(null) { group })
        val store = Store()
        val failure = IllegalStateException("write failed")
        store.onWrite = { throw failure }
        assertSame(failure, assertFailsWith<IllegalStateException> { owner.commit(ticket, identity, store) })
        assertEquals(GroupFoundationState.ReleasedForCommit, owner.state())
        assertEquals(GroupFoundationCommit.Invalidated, owner.commit(ticket, identity, store))
        assertEquals(1, store.reads)
        assertEquals(1, store.writes)
    }

    @Test
    fun cancellationDuringSnapshotReadPreventsWrite() {
        val owner = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(owner.prepare(null) { group })
        val store = Store().apply { onRead = { owner.cancel() } }
        assertEquals(GroupFoundationCommit.Invalidated, owner.commit(ticket, identity, store))
        assertEquals(0, store.writes)
        assertEquals(GroupFoundationState.Closed(GroupFoundationFailure.Cancelled), owner.state())
    }

    @Test
    fun cancellationAndLeaveBeforeCommitAvoidStorageEntirely() {
        for (leave in listOf(false, true)) {
            val owner = GroupFoundationAttempt(identity)
            val ticket = assertNotNull(owner.prepare(null) { group })
            if (leave) owner.leaveGroup() else owner.cancel()
            val store = Store().apply { onRead = { error("closed request must not read") } }
            assertEquals(GroupFoundationCommit.Invalidated, owner.commit(ticket, identity, store))
            assertEquals(0, store.reads)
            assertEquals(0, store.writes)
        }
    }

    @Test
    fun identityChangeRejectsBeforeWrite() {
        val owner = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(owner.prepare(null) { group })
        val store = Store()
        assertEquals(GroupFoundationCommit.Invalidated, owner.commit(ticket, "c".repeat(64), store))
        assertEquals(0, store.writes)
        assertEquals(GroupFoundationState.Closed(GroupFoundationFailure.IdentityChanged), owner.state())
    }

    @Test
    fun existingRootIsNotOverwrittenEvenWhenIdentical() {
        val owner = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(owner.prepare(null) { group })
        val store = Store().apply { root = GroupTrustAnchor(group, identity) }
        assertEquals(GroupFoundationCommit.AlreadyInGroup, owner.commit(ticket, identity, store))
        assertEquals(0, store.writes)
        assertEquals(GroupFoundationState.Closed(GroupFoundationFailure.AlreadyInGroup), owner.state())
    }

    @Test
    fun competingInsertConsumesTicketWithoutClaimingSuccess() {
        val owner = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(owner.prepare(null) { group })
        val winner = GroupTrustAnchor("c".repeat(64), identity)
        val store = Store().apply { onWrite = { root = winner } }
        assertEquals(GroupFoundationCommit.AlreadyInGroup, owner.commit(ticket, identity, store))
        assertEquals(winner, store.root)
        assertEquals(GroupFoundationCommit.Invalidated, owner.commit(ticket, identity, store))
        assertEquals(1, store.writes)
    }

    @Test
    fun foreignTicketDoesNotInvalidateTheLegitimateCommit() {
        val first = GroupFoundationAttempt(identity)
        val next = GroupFoundationAttempt(identity)
        val old = assertNotNull(first.prepare(null) { group })
        val ticket = assertNotNull(next.prepare(null) { group })
        val store = Store()
        assertEquals(GroupFoundationCommit.Invalidated, next.commit(old, identity, store))
        assertEquals(0, store.writes)
        assertEquals(GroupFoundationState.AwaitingCommit, next.state())
        assertEquals(GroupFoundationCommit.Committed, next.commit(ticket, identity, store))
    }

    @Test
    fun uncertainAcknowledgementRecoversFromDurableStateNotOldTicket() {
        val owner = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(owner.prepare(null) { group })
        val store = Store().apply {
            onWrite = {
                root = it
                error("acknowledgement failed after persistence")
            }
        }
        assertFailsWith<IllegalStateException> { owner.commit(ticket, identity, store) }
        assertEquals(GroupTrustAnchor(group, identity), store.localGroup())
        assertEquals(GroupFoundationCommit.Invalidated, owner.commit(ticket, identity, store))
        val fresh = GroupFoundationAttempt(identity)
        kotlin.test.assertNull(fresh.prepare(store.localGroup()) { error("must not generate another group") })
        assertEquals(GroupFoundationState.Closed(GroupFoundationFailure.AlreadyInGroup), fresh.state())
        assertEquals(1, store.writes)
    }

    @Test
    fun cancellationAfterHandoffCannotUndoTheReceivingOwnersWrite() {
        val owner = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(owner.prepare(null) { group })
        val store = Store().apply {
            onWrite = {
                assertFalse(owner.cancel())
                assertFalse(owner.leaveGroup())
            }
        }
        assertEquals(GroupFoundationCommit.Committed, owner.commit(ticket, identity, store))
        assertEquals(GroupTrustAnchor(group, identity), store.root)
    }

    private class Store : LocalGroupRepository {
        var root: GroupTrustAnchor? = null
        var reads = 0
        var writes = 0
        var onRead: () -> Unit = {}
        var onWrite: (GroupTrustAnchor) -> Unit = {}
        override fun localGroup(): GroupTrustAnchor? {
            reads++
            onRead()
            return root
        }
        override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean {
            writes++
            require(anchor.founderId == currentIdentityId)
            onWrite(anchor)
            if (root != null) return false
            root = anchor
            return true
        }
    }
}
