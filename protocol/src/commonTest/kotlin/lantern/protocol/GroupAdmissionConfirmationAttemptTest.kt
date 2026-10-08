package lantern.protocol

import kotlinx.coroutines.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor

/** Lifecycle tests use callback doubles, not fake production signatures or clocks. */
class GroupAdmissionConfirmationAttemptTest {
    private val group = "a".repeat(64)
    private val issuer = "b".repeat(64)
    private val member = "c".repeat(64)
    private val other = "d".repeat(64)
    private val caps = ProtocolCapabilities(1, setOf("text", "receipts"))
    private val issuerOffer = ProtocolHandshakeParticipant(issuer, "e".repeat(64), caps)
    private val memberOffer = ProtocolHandshakeParticipant(member, "f".repeat(64), caps)
    private val anchor = GroupTrustAnchor(group, issuer)
    private val admission = SignedGroupAdmission(GroupAdmissionClaim(group, issuer, member), "cHJvb2Y=")
    private val context = GroupAdmissionConfirmationContext(issuerOffer, memberOffer, anchor,
        GroupAdmissionProof(anchor, listOf(admission)))
    private var now = 100L

    @Test
    fun malformedPathFailsBeforeCryptoAndCannotExposeAComparison() {
        val brokenContext = GroupAdmissionConfirmationContext(issuerOffer, memberOffer, anchor,
            GroupAdmissionProof(anchor, listOf(admission, admission)))
        val owner = GroupAdmissionConfirmationAttempt(brokenContext, member, issuer, issuer, 100, { now },
            { _, _, _ -> error("Broken chain must fail before OS verification") }, { _, _ -> true })
        assertFalse(owner.prepare())
        assertNull(owner.comparison())
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.InvalidProof(
            GroupAdmissionChainResult.BrokenChain)), owner.state)
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionConfirmationFailure.InvalidProof(GroupAdmissionChainResult.VerifiedChain)
        }
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation(GroupAdmissionConfirmationResult.VerifiedRemoteConfirmation)
        }
    }

    @Test
    fun clockFailureAndOverflowCannotLeaveAnAttemptActive() {
        val failure = IllegalStateException("Test clock failure")
        val owner = GroupAdmissionConfirmationAttempt(context, member, issuer, issuer, 100, { throw failure },
            { _, _, _ -> true }, { _, _ -> true })
        assertSame(failure, assertFailsWith<IllegalStateException> { owner.prepare() })
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.AdapterFailed), owner.state)
        val overflow = GroupAdmissionConfirmationAttempt(context, member, issuer, issuer, Long.MIN_VALUE, { Long.MAX_VALUE },
            { _, _, _ -> error("Expired") }, { _, _ -> true })
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.Expired), overflow.state)
    }

    @Test
    fun proofMustVerifyBeforeComparisonAndConfirmationAreAvailable() {
        var proofCalls = 0
        val attempt = attempt(proofVerifier = { signer, bytes, signature ->
            proofCalls++
            assertEquals(issuer, signer)
            assertContentEquals(GroupAdmissionCodec.signedBytes(admission.claim), bytes)
            assertEquals(admission.signature, signature)
            true
        })
        assertEquals(GroupAdmissionConfirmationState.AwaitingProof, attempt.state)
        assertNull(attempt.comparison())
        assertTrue(attempt.prepare())
        assertEquals(1, proofCalls)
        assertContentEquals(context.comparisonBytes(), assertNotNull(attempt.comparison()).bytes)
        assertFalse(attempt.prepare())
        assertEquals(1, proofCalls)
        val invalid = attempt(proofVerifier = { _, _, _ -> false })
        assertFalse(invalid.prepare())
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.InvalidProof(
            GroupAdmissionChainResult.InvalidSignature(0))), invalid.state)
        assertNull(invalid.comparison())
    }

    @Test
    fun bothConfirmationOrdersRequireSuccessfulLocalWrite() {
        // Remote confirmation before local confirm, during signing, during sending, or after sent.
        for (remoteAt in 0..3) {
            val attempt = attempt()
            assertTrue(attempt.prepare())
            val comparison = assertNotNull(attempt.comparison())
            if (remoteAt == 0) assertTrue(receive(attempt))
            val sign = assertNotNull(attempt.confirm(comparison))
            assertContentEquals(context.approvalBytes(member), sign.bytes)
            if (remoteAt == 1) assertTrue(receive(attempt))
            val send = assertNotNull(attempt.signed(sign, "cHJvb2Y="))
            assertEquals(member, send.sender)
            assertEquals(issuer, send.recipient)
            if (remoteAt == 2) assertTrue(receive(attempt))
            assertTrue(attempt.state is GroupAdmissionConfirmationState.Sending)
            assertTrue(attempt.sent(send))
            if (remoteAt == 3) {
                assertEquals(GroupAdmissionConfirmationState.AwaitingRemoteConfirmation, attempt.state)
                assertTrue(receive(attempt))
            }
            assertEquals(GroupAdmissionConfirmationState.Confirmed, attempt.state)
            assertFalse(attempt.sent(send))
            assertNull(attempt.confirm(comparison))
        }
    }

    @Test
    fun foreignTicketsAndBuffersCannotAuthorizeAnotherAttempt() {
        val first = prepared()
        val second = prepared()
        val ticket = assertNotNull(first.comparison())
        ticket.bytes.fill(0)
        assertContentEquals(context.comparisonBytes(), ticket.bytes)
        assertNull(second.confirm(ticket))
        val sign = assertNotNull(first.confirm(ticket))
        sign.bytes.fill(0)
        assertContentEquals(context.approvalBytes(member), sign.bytes)
        assertNull(second.signed(sign, "cHJvb2Y="))
        val send = assertNotNull(first.signed(sign, "cHJvb2Y="))
        assertFalse(second.sent(send))
        assertFalse(second.operationFailed(send))
        assertEquals(GroupAdmissionConfirmationState.AwaitingConfirmation(false), second.state)
    }

    @Test
    fun everyLifecycleClosureInvalidatesEvenConfirmedAndAllOldTickets() {
        val events: List<Pair<(GroupAdmissionConfirmationAttempt) -> Unit, GroupAdmissionConfirmationFailure>> = listOf(
            { attempt: GroupAdmissionConfirmationAttempt -> attempt.cancel() } to GroupAdmissionConfirmationFailure.Cancelled,
            { attempt: GroupAdmissionConfirmationAttempt -> attempt.block() } to GroupAdmissionConfirmationFailure.Blocked,
            { attempt: GroupAdmissionConfirmationAttempt -> attempt.leaveGroup() } to GroupAdmissionConfirmationFailure.LeftGroup,
            { attempt: GroupAdmissionConfirmationAttempt -> attempt.transportClosed() } to GroupAdmissionConfirmationFailure.TransportClosed,
        )
        for ((close, reason) in events) {
            for (confirmed in listOf(false, true)) {
                val attempt = prepared()
                val ticket = assertNotNull(attempt.comparison())
                val sign = assertNotNull(attempt.confirm(ticket))
                val send = assertNotNull(attempt.signed(sign, "cHJvb2Y="))
                if (confirmed) {
                    assertTrue(attempt.sent(send))
                    assertTrue(receive(attempt))
                }
                close(attempt)
                attempt.cancel() // First closure reason is retained.
                assertEquals(GroupAdmissionConfirmationState.Closed(reason), attempt.state)
                assertNull(attempt.comparison())
                assertNull(attempt.remainingMillis)
                assertFalse(attempt.prepare())
                assertNull(attempt.confirm(ticket))
                assertNull(attempt.signed(sign, "cHJvb2Y="))
                assertFalse(attempt.sent(send))
                assertFalse(receive(attempt))
            }
        }
    }

    @Test
    fun selectedAndTlsPinsCannotBeSubstituted() {
        for (attempt in listOf(attempt(selected = other), attempt(tlsPeer = other))) {
            assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.IdentityMismatch), attempt.state)
            assertFalse(attempt.prepare())
        }
        assertFailsWith<IllegalArgumentException> { attempt(selected = member) }
    }

    @Test
    fun earlyDuplicateOrInvalidRemoteConfirmationClosesTheAttempt() {
        val early = attempt()
        assertFalse(receive(early))
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.UnexpectedConfirmation), early.state)
        val duplicate = prepared()
        assertTrue(receive(duplicate))
        assertFalse(receive(duplicate))
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.UnexpectedConfirmation), duplicate.state)
        val invalid = attempt(remoteVerifier = { _, _ -> false })
        assertTrue(invalid.prepare())
        assertFalse(receive(invalid))
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation(
            GroupAdmissionConfirmationResult.InvalidSignature)), invalid.state)
        val reflected = prepared()
        assertFalse(reflected.receive(member, issuer, "cHJvb2Y="))
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation(
            GroupAdmissionConfirmationResult.AddressMismatch)), reflected.state)
    }

    @Test
    fun failedSigningOrWritingCannotComplete() {
        val attempt = prepared()
        val sign = assertNotNull(attempt.confirm(assertNotNull(attempt.comparison())))
        assertNull(attempt.signed(sign, "invalid"))
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.LocalOperationFailed), attempt.state)
        for (failWhileSigning in listOf(false, true)) {
            val owner = prepared()
            val signing = assertNotNull(owner.confirm(assertNotNull(owner.comparison())))
            val operation = if (failWhileSigning) signing else assertNotNull(owner.signed(signing, "cHJvb2Y="))
            assertTrue(owner.operationFailed(operation))
            assertFalse(owner.operationFailed(operation))
            assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.LocalOperationFailed), owner.state)
        }
    }

    @Test
    fun cancellationOrExpiryInsideProofAndRemoteVerifierCannotRestoreProgress() {
        lateinit var proofCancelled: GroupAdmissionConfirmationAttempt
        proofCancelled = attempt(proofVerifier = { _, _, _ -> proofCancelled.cancel(); true })
        assertFalse(proofCancelled.prepare())
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.Cancelled), proofCancelled.state)
        lateinit var remoteBlocked: GroupAdmissionConfirmationAttempt
        remoteBlocked = attempt(remoteVerifier = { _, _ -> remoteBlocked.block(); true })
        assertTrue(remoteBlocked.prepare())
        assertFalse(receive(remoteBlocked))
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.Blocked), remoteBlocked.state)
        for (expireInProof in listOf(false, true)) {
            now = 100
            val expired = attempt(
                proofVerifier = { _, _, _ -> if (expireInProof) now += GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS; true },
                remoteVerifier = { _, _ -> now += GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS; true },
            )
            if (expireInProof) assertFalse(expired.prepare()) else {
                assertTrue(expired.prepare())
                assertFalse(receive(expired))
            }
            assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.Expired), expired.state)
        }
    }

    @Test
    fun reentrantRemoteConfirmationCannotBeAcceptedTwice() {
        lateinit var attempt: GroupAdmissionConfirmationAttempt
        attempt = attempt(remoteVerifier = { _, _ ->
            assertFalse(receive(attempt))
            true
        })
        assertTrue(attempt.prepare())
        assertFalse(receive(attempt))
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.UnexpectedConfirmation), attempt.state)
    }

    @Test
    fun monotonicDeadlineIsSharedWithSelectionAndAppliesToConfirmed() {
        val attempt = prepared()
        val sign = assertNotNull(attempt.confirm(assertNotNull(attempt.comparison())))
        val send = assertNotNull(attempt.signed(sign, "cHJvb2Y="))
        assertTrue(attempt.sent(send))
        assertTrue(receive(attempt))
        now = 100 + GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS - 1
        assertEquals(1L, attempt.remainingMillis)
        assertEquals(GroupAdmissionConfirmationState.Confirmed, attempt.state)
        now++
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.Expired), attempt.state)
        now = 99
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.ClockMovedBackwards), attempt().state)
        now = 100
        val backwards = prepared()
        now = 101
        assertNotNull(backwards.remainingMillis)
        now = 100
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.ClockMovedBackwards), backwards.state)
    }

    @Test
    fun unexpectedErrorsAndCancellationCloseThenPropagate() {
        for (failure in listOf(IllegalStateException("Test OS failure"), CancellationException("Cancelled"))) {
            val proofFailure = attempt(proofVerifier = { _, _, _ -> throw failure })
            assertSame(failure, assertFailsWith<Exception> { proofFailure.prepare() })
            assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.AdapterFailed), proofFailure.state)
            val remoteFailure = attempt(remoteVerifier = { _, _ -> throw failure })
            assertTrue(remoteFailure.prepare())
            assertSame(failure, assertFailsWith<Exception> { receive(remoteFailure) })
            assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.AdapterFailed), remoteFailure.state)
        }
    }

    private fun prepared() = attempt().also { assertTrue(it.prepare()) }
    private fun receive(attempt: GroupAdmissionConfirmationAttempt) = attempt.receive(issuer, member, "cHJvb2Y=")
    private fun attempt(
        selected: String = issuer,
        tlsPeer: String = issuer,
        proofVerifier: (String, ByteArray, String) -> Boolean = { _, _, _ -> true },
        remoteVerifier: (ByteArray, String) -> Boolean = { _, _ -> true },
    ) = GroupAdmissionConfirmationAttempt(context, member, selected, tlsPeer, 100, { now }, proofVerifier, remoteVerifier)
}
