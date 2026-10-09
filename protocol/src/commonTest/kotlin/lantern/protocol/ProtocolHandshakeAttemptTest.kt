package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ProtocolHandshakeAttemptTest {
    private val local = participant("a", "1")
    private val remote = participant("b", "2")
    private val signature = "cHJvb2Y=" // Test-only verifier fixture, not an ECDSA signature.
    private val approval = ProtocolHandshakeFrame.Approve(ProtocolHandshakeApproval(remote.identity, local.identity, signature))

    private class Clock(var now: Long = 1000)

    @Test
    fun groupOffersRequireCompatibleHelloAndNoBootstrapApproval() {
        val attempt = attempt(local = participant("a", "1", setOf("text", "receipts")))
        assertNull(attempt.offersForGroupAdmission())
        assertTrue(attempt.receive(ProtocolHandshakeFrame.Hello(remote)))
        val offers = assertNotNull(attempt.offersForGroupAdmission())
        assertEquals(local.identity, offers.local.identity)
        assertEquals(local.nonce, offers.local.nonce)
        assertEquals(remote.identity, offers.remote.identity)
        assertEquals(remote.nonce, offers.remote.nonce)
        mutate(offers.local.capabilities.supportedFeatures)
        assertEquals(setOf("text", "receipts"), offers.local.capabilities.supportedFeatures)
        assertEquals(setOf("text", "receipts"), assertNotNull(attempt.offersForGroupAdmission()).local.capabilities.supportedFeatures)
        assertNotNull(attempt.confirm(assertNotNull(attempt.comparison())))
        assertNull(attempt.offersForGroupAdmission())
        attempt.cancel()
        assertNull(attempt.offersForGroupAdmission())
        // Snapshots are data, not a live authorization; they survive cancellation without reviving it.
        assertEquals(remote.nonce, offers.remote.nonce)
    }

    @Test
    fun remoteApprovalAndExpiryPreventGroupOfferExport() {
        val approved = attempt()
        assertTrue(approved.receive(ProtocolHandshakeFrame.Hello(remote)))
        assertTrue(approved.receive(approval))
        assertNull(approved.offersForGroupAdmission())
        val signing = assertNotNull(approved.confirm(assertNotNull(approved.comparison())))
        val sending = assertNotNull(approved.signed(signing, signature))
        assertTrue(approved.sent(sending))
        assertEquals(ready(), approved.state)
        assertNull(approved.offersForGroupAdmission())
        val wrongPin = attempt(tls = "c".repeat(64))
        assertNull(wrongPin.offersForGroupAdmission())
        assertClosed(wrongPin, ProtocolHandshakeFailure.IdentityMismatch)
        val clock = Clock()
        val expired = attempt(clock = clock)
        assertTrue(expired.receive(ProtocolHandshakeFrame.Hello(remote)))
        clock.now += ProtocolHandshakeAttempt.TIMEOUT_MILLIS
        assertNull(expired.offersForGroupAdmission())
        assertClosed(expired, ProtocolHandshakeFailure.Expired)
    }

    @Test
    fun remainingReadBudgetUsesSelectionDeadlineAndInvalidatesOnExpiry() {
        val clock = Clock()
        val attempt = attempt(clock = clock)
        assertEquals(120_000L, attempt.remainingMillis)
        clock.now += 119_999
        assertEquals(1L, attempt.remainingMillis)
        clock.now++
        assertNull(attempt.remainingMillis)
        assertEquals(ProtocolHandshakeState.Closed(ProtocolHandshakeFailure.Expired), attempt.state)
        clock.now = 1000
        assertNull(attempt.remainingMillis)
    }

    @Test
    fun readinessRequiresExplicitConfirmationSignatureAndSuccessfulWriteInEitherOrder() {
        // Remote approval may arrive before confirmation, during signing, during writing or last.
        for (remoteStep in 0..3) {
            val attempt = attempt()
            assertEquals(ProtocolHandshakeState.AwaitingHello, attempt.state)
            assertNull(attempt.comparison())
            assertNotNull(attempt.localHello)
            assertTrue(attempt.receive(ProtocolHandshakeFrame.Hello(remote)))
            val comparison = assertNotNull(attempt.comparison())
            assertContentEquals(ProtocolHandshakeTranscript.bytes(local, remote), comparison.bytes)
            if (remoteStep == 0) assertTrue(attempt.receive(approval))
            assertEquals(ProtocolHandshakeState.AwaitingConfirmation(remoteStep == 0), attempt.state)
            val sign = assertNotNull(attempt.confirm(comparison))
            assertNull(attempt.confirm(comparison))
            assertContentEquals(ProtocolHandshakeTranscript.approvalBytes(local, remote), sign.bytes)
            if (remoteStep == 1) assertTrue(attempt.receive(approval))
            assertEquals(ProtocolHandshakeState.SigningApproval(remoteStep <= 1), attempt.state)
            val send = assertNotNull(attempt.signed(sign, signature))
            assertEquals(ProtocolHandshakeApproval(local.identity, remote.identity, signature), send.approval)
            assertNull(attempt.signed(sign, signature))
            if (remoteStep == 2) assertTrue(attempt.receive(approval))
            assertEquals(ProtocolHandshakeState.SendingApproval(remoteStep <= 2), attempt.state)
            assertTrue(attempt.sent(send))
            assertFalse(attempt.sent(send))
            if (remoteStep == 3) {
                assertEquals(ProtocolHandshakeState.AwaitingRemoteApproval, attempt.state)
                assertTrue(attempt.receive(approval))
            }
            assertEquals(ready(), attempt.state)
        }
    }

    @Test
    fun approvalWithoutLocalConfirmationNeverBecomesReady() {
        val attempt = attempt()
        assertTrue(attempt.receive(ProtocolHandshakeFrame.Hello(remote)))
        assertTrue(attempt.receive(approval))
        assertEquals(ProtocolHandshakeState.AwaitingConfirmation(true), attempt.state)
    }

    @Test
    fun unexpectedOrRepeatedFramesCloseWithoutReplacingTheOffer() {
        val beforeHello = attempt { _, _ -> error("Out-of-order frame reached verifier") }
        assertFalse(beforeHello.receive(approval))
        assertClosed(beforeHello, ProtocolHandshakeFailure.UnexpectedMessage)
        for (changed in listOf(remote, participant("b", "3"), participant("b", "2", setOf("text", "future")))) {
            val attempt = attempt()
            attempt.receive(ProtocolHandshakeFrame.Hello(remote))
            assertFalse(attempt.receive(ProtocolHandshakeFrame.Hello(changed)))
            assertClosed(attempt, ProtocolHandshakeFailure.UnexpectedMessage)
            assertNull(attempt.comparison())
        }
        val duplicate = attempt()
        duplicate.receive(ProtocolHandshakeFrame.Hello(remote))
        duplicate.receive(approval)
        assertFalse(duplicate.receive(approval))
        assertClosed(duplicate, ProtocolHandshakeFailure.UnexpectedMessage)
    }

    @Test
    fun selectionAndTlsIdentityMustMatchBeforeAnOfferOrComparisonIsAccepted() {
        assertFailsWith<IllegalArgumentException> { attempt(selected = "invalid") }
        assertFailsWith<IllegalArgumentException> { attempt(selected = local.identity) }
        for (tls in listOf("", local.identity, "c".repeat(64))) {
            val attempt = attempt(tls = tls) { _, _ -> error("Unexpected verification") }
            assertClosed(attempt, ProtocolHandshakeFailure.IdentityMismatch)
            assertFalse(attempt.receive(ProtocolHandshakeFrame.Hello(remote)))
            assertNull(attempt.comparison())
            assertNull(attempt.localHello)
        }
        val mismatch = attempt()
        assertFalse(mismatch.receive(ProtocolHandshakeFrame.Hello(participant("c", "2"))))
        assertClosed(mismatch, ProtocolHandshakeFailure.IdentityMismatch)
    }

    @Test
    fun incompatibleHelloClosesBeforeConfirmationWithoutV0Fallback() {
        val offers = listOf(
            participant("b", "2", version = 2) to ProtocolIncompatibility.UNSUPPORTED_VERSION,
            participant("b", "2", setOf("future"), setOf("future")) to ProtocolIncompatibility.REQUIRED_FEATURE_MISSING,
        )
        for ((offer, reason) in offers) {
            val attempt = attempt { _, _ -> error("Incompatible peer reached verifier") }
            assertFalse(attempt.receive(ProtocolHandshakeFrame.Hello(offer)))
            assertClosed(attempt, ProtocolHandshakeFailure.Incompatible(reason))
            assertNull(attempt.comparison())
        }
    }

    @Test
    fun invalidProofOrAddressClosesAndInvalidatesPendingLocalOperations() {
        for (wrongAddress in listOf(
            approval.approval.copy(sender = "c".repeat(64)),
            approval.approval.copy(recipient = "c".repeat(64)),
        )) {
            val attempt = attempt { _, _ -> error("Wrong address reached verifier") }
            attempt.receive(ProtocolHandshakeFrame.Hello(remote))
            val sign = assertNotNull(attempt.confirm(assertNotNull(attempt.comparison())))
            assertFalse(attempt.receive(ProtocolHandshakeFrame.Approve(wrongAddress)))
            assertClosed(attempt, ProtocolHandshakeFailure.AddressMismatch)
            assertNull(attempt.signed(sign, signature))
        }
        val invalid = attempt { bytes, value ->
            assertContentEquals(ProtocolHandshakeTranscript.approvalBytes(remote, local), bytes)
            assertEquals(signature, value)
            false
        }
        invalid.receive(ProtocolHandshakeFrame.Hello(remote))
        assertFalse(invalid.receive(approval))
        assertClosed(invalid, ProtocolHandshakeFailure.InvalidSignature)
    }

    @Test
    fun comparisonAndOperationTicketsCannotAdvanceAnotherAttemptWithTheSamePeer() {
        val old = attempt()
        old.receive(ProtocolHandshakeFrame.Hello(remote))
        val oldComparison = assertNotNull(old.comparison())
        val oldSign = assertNotNull(old.confirm(oldComparison))
        val oldSend = assertNotNull(old.signed(oldSign, signature))
        old.cancel()
        val fresh = attempt()
        fresh.receive(ProtocolHandshakeFrame.Hello(remote))
        assertNull(fresh.confirm(oldComparison))
        val sign = assertNotNull(fresh.confirm(assertNotNull(fresh.comparison())))
        assertNull(fresh.signed(oldSign, signature))
        assertFalse(fresh.operationFailed(oldSign))
        assertFalse(fresh.sent(oldSend))
        assertEquals(ProtocolHandshakeState.SigningApproval(false), fresh.state)
        val send = assertNotNull(fresh.signed(sign, signature))
        assertFalse(fresh.operationFailed(oldSend))
        assertTrue(fresh.sent(send))
        assertEquals(ProtocolHandshakeState.AwaitingRemoteApproval, fresh.state)
        assertNull(old.signed(oldSign, signature))
        assertFalse(old.sent(oldSend))
        assertClosed(old, ProtocolHandshakeFailure.Cancelled)
    }

    @Test
    fun cancellationIsTerminalAtEveryStageIncludingReady() {
        val awaitingHello = attempt()
        awaitingHello.cancel()
        assertFalse(awaitingHello.receive(ProtocolHandshakeFrame.Hello(remote)))
        assertNull(awaitingHello.localHello)
        assertClosed(awaitingHello, ProtocolHandshakeFailure.Cancelled)
        for (stage in 0..4) {
            val attempt = attempt()
            attempt.receive(ProtocolHandshakeFrame.Hello(remote))
            val comparison = assertNotNull(attempt.comparison())
            val sign = if (stage >= 1) assertNotNull(attempt.confirm(comparison)) else null
            val send = if (stage >= 2) assertNotNull(attempt.signed(assertNotNull(sign), signature)) else null
            if (stage >= 3) attempt.sent(assertNotNull(send))
            if (stage == 4) attempt.receive(approval)
            attempt.cancel()
            attempt.cancel()
            assertClosed(attempt, ProtocolHandshakeFailure.Cancelled)
            assertNull(attempt.confirm(comparison))
            assertNull(attempt.comparison())
            assertFalse(attempt.receive(ProtocolHandshakeFrame.Hello(remote)))
            assertFalse(attempt.receive(approval))
            if (sign != null) assertNull(attempt.signed(sign, signature))
            if (send != null) assertFalse(attempt.sent(send))
        }
    }

    @Test
    fun readingEachStageAtTheDeadlineClosesWithoutATimerOrAnyOtherCallback() {
        for (stage in 0..5) {
            val clock = Clock()
            val attempt = attempt(clock = clock)
            if (stage >= 1) attempt.receive(ProtocolHandshakeFrame.Hello(remote))
            val sign = if (stage >= 2) assertNotNull(attempt.confirm(assertNotNull(attempt.comparison()))) else null
            val send = if (stage >= 3) assertNotNull(attempt.signed(assertNotNull(sign), signature)) else null
            if (stage >= 4) attempt.sent(assertNotNull(send))
            if (stage == 5) attempt.receive(approval)
            clock.now += ProtocolHandshakeAttempt.TIMEOUT_MILLIS
            assertClosed(attempt, ProtocolHandshakeFailure.Expired)
            assertNull(attempt.localHello)
            assertFalse(attempt.receive(approval))
        }
    }

    @Test
    fun expirationUsesSelectionTimeAndExactBoundaryWithoutDependingOnATimer() {
        val clock = Clock(120_999)
        val attempt = attempt(clock = clock, selectedAt = 1000)
        assertTrue(attempt.receive(ProtocolHandshakeFrame.Hello(remote)))
        val comparison = assertNotNull(attempt.comparison())
        val sign = assertNotNull(attempt.confirm(comparison))
        clock.now = 121_000
        assertNull(attempt.signed(sign, signature))
        assertClosed(attempt, ProtocolHandshakeFailure.Expired)
        attempt.cancel()
        assertClosed(attempt, ProtocolHandshakeFailure.Expired)
        val alreadyExpired = attempt(clock = Clock(121_000), selectedAt = 1000)
        assertFalse(alreadyExpired.receive(ProtocolHandshakeFrame.Hello(remote)))
        assertClosed(alreadyExpired, ProtocolHandshakeFailure.Expired)
    }

    @Test
    fun aPreparedWriteAndReadyResultAlsoExpire() {
        for (readyBeforeExpiry in listOf(false, true)) {
            val clock = Clock()
            val attempt = attempt(clock = clock)
            attempt.receive(ProtocolHandshakeFrame.Hello(remote))
            val sign = assertNotNull(attempt.confirm(assertNotNull(attempt.comparison())))
            val send = assertNotNull(attempt.signed(sign, signature))
            attempt.receive(approval)
            if (readyBeforeExpiry) {
                attempt.sent(send)
                assertEquals(ready(), attempt.state)
            }
            clock.now += ProtocolHandshakeAttempt.TIMEOUT_MILLIS
            assertFalse(attempt.sent(send))
            assertClosed(attempt, ProtocolHandshakeFailure.Expired)
            assertNull(attempt.comparison())
        }
    }

    @Test
    fun verifierCannotResurrectCancelledOrExpiredAttemptAndExceptionsDoNotCacheSuccess() {
        for (cancel in listOf(false, true)) {
            val clock = Clock()
            lateinit var attempt: ProtocolHandshakeAttempt
            attempt = attempt(clock = clock) { _, _ ->
                if (cancel) attempt.cancel() else clock.now += ProtocolHandshakeAttempt.TIMEOUT_MILLIS
                true
            }
            attempt.receive(ProtocolHandshakeFrame.Hello(remote))
            assertFalse(attempt.receive(approval))
            assertClosed(attempt, if (cancel) ProtocolHandshakeFailure.Cancelled else ProtocolHandshakeFailure.Expired)
        }
        val failed = attempt { _, _ -> error("OS verifier failed") }
        failed.receive(ProtocolHandshakeFrame.Hello(remote))
        val failure = assertFailsWith<IllegalStateException> { failed.receive(approval) }
        assertEquals("OS verifier failed", failure.message)
        assertClosed(failed, ProtocolHandshakeFailure.LocalOperationFailed)
        assertFalse(failed.receive(approval))
    }

    @Test
    fun reentrantFrameDuringVerificationFailsClosed() {
        lateinit var attempt: ProtocolHandshakeAttempt
        attempt = attempt { _, _ ->
            assertFalse(attempt.receive(approval))
            true
        }
        attempt.receive(ProtocolHandshakeFrame.Hello(remote))
        assertFalse(attempt.receive(approval))
        assertClosed(attempt, ProtocolHandshakeFailure.UnexpectedMessage)
    }

    @Test
    fun badLocalSignatureAndReportedOperationFailuresAreTerminal() {
        for (value in listOf("", "bad-base64", "AB==")) {
            val attempt = attempt()
            attempt.receive(ProtocolHandshakeFrame.Hello(remote))
            val sign = assertNotNull(attempt.confirm(assertNotNull(attempt.comparison())))
            assertNull(attempt.signed(sign, value))
            assertClosed(attempt, ProtocolHandshakeFailure.LocalOperationFailed)
        }
        for (duringWrite in listOf(false, true)) {
            val attempt = attempt()
            attempt.receive(ProtocolHandshakeFrame.Hello(remote))
            val sign = assertNotNull(attempt.confirm(assertNotNull(attempt.comparison())))
            val operation = if (duringWrite) assertNotNull(attempt.signed(sign, signature)) else sign
            assertTrue(attempt.operationFailed(operation))
            assertFalse(attempt.operationFailed(operation))
            assertClosed(attempt, ProtocolHandshakeFailure.LocalOperationFailed)
        }
    }

    @Test
    fun terminalErrorsArePropagatedWithoutLeavingReusableState() {
        val adapterFailure = AssertionError("Verifier failed unexpectedly")
        val attempt = attempt { _, _ -> throw adapterFailure }
        attempt.receive(ProtocolHandshakeFrame.Hello(remote))
        assertSame(adapterFailure, assertFailsWith<AssertionError> { attempt.receive(approval) })
        assertClosed(attempt, ProtocolHandshakeFailure.LocalOperationFailed)

        var failClock = false
        val clockFailure = IllegalStateException("Clock unavailable")
        val clockAttempt = ProtocolHandshakeAttempt(local, remote.identity, remote.identity, 0, {
            if (failClock) throw clockFailure else 0
        }) { _, _ -> true }
        clockAttempt.receive(ProtocolHandshakeFrame.Hello(remote))
        failClock = true
        assertSame(clockFailure, assertFailsWith<IllegalStateException> { clockAttempt.comparison() })
        // Closed state must remain readable even while the adapter clock is failing.
        assertClosed(clockAttempt, ProtocolHandshakeFailure.LocalOperationFailed)
    }

    @Test
    fun completionRejectsAdditionalBootstrapMessagesInsteadOfOpeningApplicationTraffic() {
        for (extra in listOf(ProtocolHandshakeFrame.Hello(remote), approval)) {
            val attempt = attempt()
            attempt.receive(ProtocolHandshakeFrame.Hello(remote))
            val sign = assertNotNull(attempt.confirm(assertNotNull(attempt.comparison())))
            attempt.sent(assertNotNull(attempt.signed(sign, signature)))
            attempt.receive(approval)
            assertEquals(ready(), attempt.state)
            assertFalse(attempt.receive(extra))
            assertClosed(attempt, ProtocolHandshakeFailure.UnexpectedMessage)
        }
    }

    @Test
    fun decreasingClockAndOverflowCannotExtendTheAttempt() {
        val clock = Clock()
        val attempt = attempt(clock = clock)
        clock.now--
        assertClosed(attempt, ProtocolHandshakeFailure.ClockMovedBackwards)
        val overflow = attempt(clock = Clock(Long.MAX_VALUE), selectedAt = Long.MIN_VALUE)
        assertClosed(overflow, ProtocolHandshakeFailure.Expired)
        val negativeOrigin = attempt(clock = Clock(-2), selectedAt = -1000)
        assertEquals(ProtocolHandshakeState.AwaitingHello, negativeOrigin.state)
    }

    @Test
    fun offersAndExposedArraysAreDefensiveSnapshots() {
        val offered = participant("a", "1", setOf("text", "receipts"))
        val peer = participant("b", "2", setOf("text", "receipts"))
        val attempt = attempt(local = offered)
        mutate(offered.capabilities.supportedFeatures)
        val hello = assertNotNull(attempt.localHello)
        mutate(hello.participant.capabilities.supportedFeatures)
        assertEquals(setOf("text", "receipts"), assertNotNull(attempt.localHello).participant.capabilities.supportedFeatures)
        assertTrue(attempt.receive(ProtocolHandshakeFrame.Hello(peer)))
        mutate(peer.capabilities.supportedFeatures)
        val expectedLocal = participant("a", "1", setOf("text", "receipts"))
        val expectedRemote = participant("b", "2", setOf("text", "receipts"))
        val comparison = assertNotNull(attempt.comparison())
        comparison.bytes.fill(0)
        assertContentEquals(ProtocolHandshakeTranscript.bytes(expectedLocal, expectedRemote), comparison.bytes)
        val sign = assertNotNull(attempt.confirm(comparison))
        sign.bytes.fill(0)
        assertContentEquals(ProtocolHandshakeTranscript.approvalBytes(expectedLocal, expectedRemote), sign.bytes)
        val send = assertNotNull(attempt.signed(sign, signature))
        attempt.sent(send)
        attempt.receive(approval)
        val ready = assertIs<ProtocolHandshakeState.Ready>(attempt.state)
        mutate(ready.capabilities.features)
        assertEquals(setOf("receipts", "text"), assertIs<ProtocolHandshakeState.Ready>(attempt.state).capabilities.features)
    }

    private fun mutate(values: Set<String>) {
        // Kotlin read-only Set is not necessarily immutable. Mutate only when supported on the target.
        if (values is MutableSet<String>) values.clear()
    }

    private fun attempt(
        local: ProtocolHandshakeParticipant = this.local,
        selected: String = remote.identity,
        tls: String = remote.identity,
        clock: Clock = Clock(),
        selectedAt: Long = clock.now,
        verifier: (ByteArray, String) -> Boolean = { _, _ -> true },
    ) = ProtocolHandshakeAttempt(local, selected, tls, selectedAt, { clock.now }, verifier)

    private fun ready() = ProtocolHandshakeState.Ready(ProtocolNegotiationResult.Compatible(1, setOf("text")))

    private fun assertClosed(attempt: ProtocolHandshakeAttempt, reason: ProtocolHandshakeFailure) {
        assertEquals(ProtocolHandshakeState.Closed(reason), attempt.state)
    }

    private fun participant(
        identity: String,
        nonce: String,
        supported: Set<String> = setOf("text"),
        required: Set<String> = emptySet(),
        version: Int = 1,
    ) = ProtocolHandshakeParticipant(identity.repeat(64), nonce.repeat(64), ProtocolCapabilities(version, supported, required))
}
