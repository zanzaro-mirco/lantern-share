package lantern.protocol

import lantern.domain.GroupTrustAnchor
import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class GroupFoundationAttemptTest {
    private val identity = "a".repeat(64)
    private val group = "b".repeat(64)

    @Test
    fun oneRequestReleasesExactlyOnceWithoutClaimingPersistence() {
        val attempt = GroupFoundationAttempt(identity)
        assertEquals(GroupFoundationState.AwaitingPreparation, attempt.state())
        val ticket = assertNotNull(attempt.prepare(null) { group })
        assertEquals(GroupFoundationState.AwaitingCommit, attempt.state())
        assertNull(attempt.prepare(null) { error("must not generate twice") })
        assertEquals(GroupTrustAnchor(group, identity), attempt.releaseForCommit(ticket, identity, null)?.anchor)
        assertEquals(GroupFoundationState.ReleasedForCommit, attempt.state())
        assertNull(attempt.releaseForCommit(ticket, identity, null))
        assertFalse(attempt.cancel())
        assertFalse(attempt.leaveGroup())
    }

    @Test
    fun cancelBeforePreparationDoesNotInvokeRandomness() {
        val attempt = GroupFoundationAttempt(identity)
        assertTrue(attempt.cancel())
        assertNull(attempt.prepare(null) { error("must not generate") })
        assertClosed(attempt, GroupFoundationFailure.Cancelled)
        assertFalse(attempt.leaveGroup())
    }

    @Test
    fun cancelInvalidatesTheOutstandingTicket() {
        val attempt = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(attempt.prepare(null) { group })
        assertTrue(attempt.cancel())
        assertNull(attempt.releaseForCommit(ticket, identity, null))
        assertFalse(attempt.cancel())
        assertClosed(attempt, GroupFoundationFailure.Cancelled)
    }

    @Test
    fun leaveInvalidatesTheOutstandingTicketAndPreservesItsReason() {
        val attempt = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(attempt.prepare(null) { group })
        assertTrue(attempt.leaveGroup())
        assertFalse(attempt.cancel())
        assertNull(attempt.releaseForCommit(ticket, identity, null))
        assertClosed(attempt, GroupFoundationFailure.LeftGroup)
    }

    @Test
    fun callbackCancellationCannotPublishAPreparedDraft() {
        val attempt = GroupFoundationAttempt(identity)
        assertNull(attempt.prepare(null) {
            assertEquals(GroupFoundationState.Preparing, attempt.state())
            assertTrue(attempt.cancel())
            group
        })
        assertClosed(attempt, GroupFoundationFailure.Cancelled)
    }

    @Test
    fun callbackLeaveThenFailurePreservesFirstReasonAndRethrows() {
        val attempt = GroupFoundationAttempt(identity)
        val failure = IllegalStateException("OS unavailable")
        assertSame(failure, assertFailsWith<IllegalStateException> {
            attempt.prepare(null) {
                attempt.leaveGroup()
                throw failure
            }
        })
        assertClosed(attempt, GroupFoundationFailure.LeftGroup)
    }

    @Test
    fun randomFailureIsTerminalWithNoRetry() {
        val attempt = GroupFoundationAttempt(identity)
        val failure = IllegalStateException("OS unavailable")
        assertSame(failure, assertFailsWith<IllegalStateException> { attempt.prepare(null) { throw failure } })
        assertClosed(attempt, GroupFoundationFailure.PreparationFailed)
        assertNull(attempt.prepare(null) { error("must not retry") })
    }

    @Test
    fun coroutineCancellationIsRethrownAndNotReportedAsOsFailure() {
        val attempt = GroupFoundationAttempt(identity)
        val cancelled = CancellationException("create-group request cancelled")
        assertSame(cancelled, assertFailsWith<CancellationException> {
            attempt.prepare(null) { throw cancelled }
        })
        assertClosed(attempt, GroupFoundationFailure.Cancelled)
        assertFalse(attempt.cancel())
        assertNull(attempt.prepare(null) { error("must not retry cancelled request") })
    }

    @Test
    fun cancellationAfterReentrantLeavePreservesTheFirstReason() {
        val attempt = GroupFoundationAttempt(identity)
        val cancelled = CancellationException("owner cancelled")
        assertSame(cancelled, assertFailsWith<CancellationException> {
            attempt.prepare(null) {
                attempt.leaveGroup()
                throw cancelled
            }
        })
        assertClosed(attempt, GroupFoundationFailure.LeftGroup)
    }

    @Test
    fun malformedRandomOutputClosesInsteadOfOfferingATicket() {
        val attempt = GroupFoundationAttempt(identity)
        assertFailsWith<IllegalArgumentException> { attempt.prepare(null) { "bad" } }
        assertClosed(attempt, GroupFoundationFailure.PreparationFailed)
    }

    @Test
    fun existingGroupRejectsBeforeTheOsCallback() {
        val attempt = GroupFoundationAttempt(identity)
        assertNull(attempt.prepare(GroupTrustAnchor(group, identity)) { error("must not generate") })
        assertClosed(attempt, GroupFoundationFailure.AlreadyInGroup)
    }

    @Test
    fun membershipChangedAfterPreparationPreventsReleaseEvenForTheSameAnchor() {
        val attempt = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(attempt.prepare(null) { group })
        assertNull(attempt.releaseForCommit(ticket, identity, GroupTrustAnchor(group, identity)))
        assertClosed(attempt, GroupFoundationFailure.AlreadyInGroup)
    }

    @Test
    fun changedOrMissingIdentityPreventsReleaseWithoutNormalization() {
        for (changed in listOf("c".repeat(64), "", identity.uppercase(), " $identity")) {
            val attempt = GroupFoundationAttempt(identity)
            val ticket = assertNotNull(attempt.prepare(null) { group })
            assertNull(attempt.releaseForCommit(ticket, changed, null))
            assertClosed(attempt, GroupFoundationFailure.IdentityChanged)
        }
    }

    @Test
    fun foreignTicketCannotReleaseOrInvalidateAnIdenticalDraft() {
        val first = GroupFoundationAttempt(identity)
        val second = GroupFoundationAttempt(identity)
        val firstTicket = assertNotNull(first.prepare(null) { group })
        val secondTicket = assertNotNull(second.prepare(null) { group })
        assertNull(second.releaseForCommit(firstTicket, "changed", GroupTrustAnchor(group, identity)))
        assertEquals(GroupFoundationState.AwaitingCommit, second.state())
        assertNotNull(second.releaseForCommit(secondTicket, identity, null))
        first.cancel()
    }

    @Test
    fun reentrantPrepareCannotReplaceTheCurrentRequest() {
        val attempt = GroupFoundationAttempt(identity)
        val ticket = assertNotNull(attempt.prepare(null) {
            assertNull(attempt.prepare(null) { error("nested randomness") })
            group
        })
        assertEquals(group, attempt.releaseForCommit(ticket, identity, null)?.anchor?.groupId)
    }

    private fun assertClosed(attempt: GroupFoundationAttempt, reason: GroupFoundationFailure) {
        assertEquals(GroupFoundationState.Closed(reason), attempt.state())
    }
}
