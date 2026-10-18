package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository
import lantern.domain.PendingGroupAdoption
import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Lifecycle/binding doubles only; OS signature and SQLite integration are separate tests. */
class GroupRootAdoptionAttemptTest {
    private val founder = "a".repeat(64)
    private val member = "b".repeat(64)
    private val other = "c".repeat(64)
    private val anchor = GroupTrustAnchor("d".repeat(64), founder)
    private val caps = ProtocolCapabilities(1, setOf("text", "receipts"))
    private val issuerOffer = ProtocolHandshakeParticipant(founder, "e".repeat(64), caps)
    private val memberOffer = ProtocolHandshakeParticipant(member, "f".repeat(64), caps)
    private val proof = GroupAdmissionProof(anchor, listOf(
        SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, founder, member), "cHJvb2Y="),
    ))
    private val context = GroupAdmissionConfirmationContext(issuerOffer, memberOffer, anchor, proof)
    private var now = 200L

    @Test
    fun candidateCannotReleaseBeforeProofExplicitConfirmRemoteSignatureAndLocalWrite() {
        for (remoteFirst in listOf(false, true)) {
            val owner = owner()
            val repository = repository()
            assertNull(owner.comparison())
            assertNull(owner.releaseForCommit(member, repository))
            assertTrue(owner.prepare(member, repository))
            assertNull(owner.releaseForCommit(member, repository))
            val ticket = assertNotNull(owner.comparison())
            assertContentEquals(context.comparisonBytes(), ticket.bytes)
            if (remoteFirst) assertTrue(receive(owner))
            assertNull(owner.releaseForCommit(member, repository))
            val signing = assertNotNull(owner.confirm(ticket))
            assertContentEquals(context.approvalBytes(member), signing.bytes)
            assertNull(owner.releaseForCommit(member, repository))
            val send = assertNotNull(owner.signed(signing, "cHJvb2Y="))
            assertNull(owner.releaseForCommit(member, repository))
            assertTrue(owner.sent(send))
            if (!remoteFirst) {
                assertNull(owner.releaseForCommit(member, repository))
                assertTrue(receive(owner))
            }
            val draft = assertNotNull(owner.releaseForCommit(member, repository))
            assertEquals(anchor, draft.anchor)
            assertEquals(member, draft.memberIdentity)
            assertSame(proof, draft.proof)
            assertEquals(GroupAdmissionConfirmation(member, founder, "cHJvb2Y="), draft.confirmations.local)
            assertEquals(GroupAdmissionConfirmation(founder, member, "cHJvb2Y="), draft.confirmations.remote)
            assertContentEquals(context.comparisonBytes(), draft.comparisonBytes())
            draft.comparisonBytes().fill(0)
            assertContentEquals(context.comparisonBytes(), draft.comparisonBytes())
            assertEquals(GroupRootAdoptionState.ReleasedForCommit, owner.state())
            assertNull(owner.releaseForCommit(member, repository))
            assertFalse(owner.prepare(member, repository))
            assertNull(owner.comparison())
            assertNull(owner.remainingMillis())
            owner.cancel() // Cancellation after handoff belongs to the receiving commit owner.
            assertEquals(GroupRootAdoptionState.ReleasedForCommit, owner.state())
        }
    }

    @Test
    fun existingGroupAndChangedIdentityRefuseBeforeReadingOrCrypto() {
        var crypto = 0
        val existing = owner(proofVerifier = { _, _, _ -> crypto++; true })
        assertFalse(existing.prepare(member, repository { anchor }))
        assertEquals(closed(GroupRootAdoptionFailure.AlreadyInGroup), existing.state())
        val changed = owner(proofVerifier = { _, _, _ -> crypto++; true })
        assertFalse(changed.prepare(other, repository { error("Identity refused before read") }))
        assertEquals(closed(GroupRootAdoptionFailure.IdentityChanged), changed.state())
        assertEquals(0, crypto)
        assertNull(existing.comparison())
    }

    @Test
    fun changedIdentityOrNewGroupAfterBothConfirmationsCannotRelease() {
        val changed = confirmed()
        assertNull(changed.releaseForCommit(other, repository { error("No read with wrong identity") }))
        assertEquals(closed(GroupRootAdoptionFailure.IdentityChanged), changed.state())
        // Even the exact same root is an existing membership, never silently overwritten.
        for (saved in listOf(anchor, GroupTrustAnchor(other, founder))) {
            val owner = confirmed()
            assertNull(owner.releaseForCommit(member, repository { saved }))
            assertEquals(closed(GroupRootAdoptionFailure.AlreadyInGroup), owner.state())
        }
    }

    @Test
    fun readFailureNeverLooksEmptyRetriesOrWrites() {
        for (afterConfirmation in listOf(false, true)) {
            var reads = 0
            val failure = IllegalStateException("Test unavailable database")
            val owner = if (afterConfirmation) confirmed() else owner()
            val repository = repository { reads++; throw failure }
            val thrown = assertFailsWith<IllegalStateException> {
                if (afterConfirmation) owner.releaseForCommit(member, repository)
                else owner.prepare(member, repository)
            }
            assertSame(failure, thrown)
            assertEquals(closed(GroupRootAdoptionFailure.StorageFailed), owner.state())
            assertFalse(owner.prepare(member, repository))
            assertNull(owner.releaseForCommit(member, repository))
            assertEquals(1, reads)
        }
    }

    @Test
    fun cancellationFromDatabaseKeepsOriginalExceptionAndFirstReason() {
        for (blockFirst in listOf(false, true)) {
            val owner = confirmed()
            val failure = CancellationException("Test cancel")
            assertSame(failure, assertFailsWith<CancellationException> {
                owner.releaseForCommit(member, repository {
                    if (blockFirst) owner.block()
                    throw failure
                })
            })
            assertEquals(confirmationClosed(if (blockFirst) GroupAdmissionConfirmationFailure.Blocked
                else GroupAdmissionConfirmationFailure.Cancelled), owner.state())
        }
    }

    @Test
    fun lifecycleDuringReadCannotReleaseOrOverwriteTheFirstFailure() {
        val events: List<Pair<(GroupRootAdoptionAttempt) -> Unit, GroupAdmissionConfirmationFailure>> = listOf(
            { owner: GroupRootAdoptionAttempt -> owner.cancel() } to GroupAdmissionConfirmationFailure.Cancelled,
            { owner: GroupRootAdoptionAttempt -> owner.block() } to GroupAdmissionConfirmationFailure.Blocked,
            { owner: GroupRootAdoptionAttempt -> owner.leaveGroup() } to GroupAdmissionConfirmationFailure.LeftGroup,
            { owner: GroupRootAdoptionAttempt -> owner.transportClosed() } to GroupAdmissionConfirmationFailure.TransportClosed,
        )
        for ((event, reason) in events) {
            for (readThrows in listOf(false, true)) {
                val owner = confirmed()
                val failure = IllegalStateException("Read failed after lifecycle")
                val repository = repository {
                    event(owner)
                    if (readThrows) throw failure
                    null
                }
                if (readThrows) assertSame(failure, assertFailsWith<IllegalStateException> {
                    owner.releaseForCommit(member, repository)
                }) else assertNull(owner.releaseForCommit(member, repository))
                owner.cancel()
                assertEquals(confirmationClosed(reason), owner.state())
            }
        }
    }

    @Test
    fun nestedPreparationAndReleaseCannotStartAnotherReadOrConsumeTwoDrafts() {
        val owner = owner()
        var reads = 0
        val empty = repository { error("Nested read must not start") }
        assertTrue(owner.prepare(member, repository {
            reads++
            assertFalse(owner.prepare(member, empty))
            assertNull(owner.releaseForCommit(member, empty))
            null
        }))
        complete(owner)
        assertNotNull(owner.releaseForCommit(member, repository {
            reads++
            assertFalse(owner.prepare(member, empty))
            assertNull(owner.releaseForCommit(member, empty))
            null
        }))
        assertEquals(2, reads)
    }

    @Test
    fun inheritedWatermarkAndOriginalDeadlineAreNotResetForRootAdoption() {
        now = 199
        val backwards = owner()
        assertFalse(backwards.prepare(member, repository { error("No read after backwards clock") }))
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.ClockMovedBackwards), backwards.state())
        now = 200
        val owner = owner()
        assertEquals(GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS - 100, owner.remainingMillis())
        assertTrue(owner.prepare(member, repository()))
        complete(owner)
        now = 100 + GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS
        assertNull(owner.releaseForCommit(member, repository { error("No read after expiration") }))
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.Expired), owner.state())
    }

    @Test
    fun expiryDuringFinalReadInvalidatesBothConfirmedProgress() {
        val owner = confirmed()
        assertNull(owner.releaseForCommit(member, repository {
            now = 100 + GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS
            null
        }))
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.Expired), owner.state())
    }

    @Test
    fun foreignComparisonAndCallbacksCannotConfirmAnotherCandidate() {
        val first = prepared()
        val second = prepared()
        val ticket = assertNotNull(first.comparison())
        assertNull(second.confirm(ticket))
        val sign = assertNotNull(first.confirm(ticket))
        assertNull(second.signed(sign, "cHJvb2Y="))
        val send = assertNotNull(first.signed(sign, "cHJvb2Y="))
        assertFalse(second.sent(send))
        assertFalse(second.operationFailed(send))
        assertNull(second.releaseForCommit(member, repository()))
    }

    @Test
    fun invalidChainAndTlsSelectionCannotExposeAComparison() {
        val invalid = owner(proofVerifier = { _, _, _ -> false })
        assertFalse(invalid.prepare(member, repository()))
        assertNull(invalid.comparison())
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.InvalidProof(
            GroupAdmissionChainResult.InvalidSignature(0))), invalid.state())
        for (owner in listOf(owner(selected = other), owner(tlsPeer = other))) {
            assertFalse(owner.prepare(member, repository { error("No read on pin mismatch") }))
            assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.IdentityMismatch), owner.state())
        }
    }

    @Test
    fun unexpectedRemoteOrFailedWriteCannotRelease() {
        val early = owner()
        assertFalse(receive(early))
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.UnexpectedConfirmation), early.state())
        val failedWrite = prepared()
        val sign = assertNotNull(failedWrite.confirm(assertNotNull(failedWrite.comparison())))
        val send = assertNotNull(failedWrite.signed(sign, "cHJvb2Y="))
        assertTrue(receive(failedWrite))
        assertTrue(failedWrite.operationFailed(send))
        assertNull(failedWrite.releaseForCommit(member, repository { error("Must not read") }))
    }

    @Test
    fun invalidRoleAndSelectionWatermarkAreRejectedAtConstruction() {
        assertFailsWith<IllegalArgumentException> {
            GroupRootAdoptionAttempt(ProtocolHandshakeOffers(issuerOffer, memberOffer, 200), founder,
                member, member, proof, 100, { now }, { _, _, _ -> true }, { _, _ -> true })
        }
        assertFailsWith<IllegalArgumentException> {
            GroupRootAdoptionAttempt(ProtocolHandshakeOffers(memberOffer, issuerOffer, 99), member,
                founder, founder, proof, 100, { now }, { _, _, _ -> true }, { _, _ -> true })
        }
    }

    @Test
    fun cancellationFromProofAndRemoteVerifierCannotReviveCandidate() {
        lateinit var first: GroupRootAdoptionAttempt
        first = owner(proofVerifier = { _, _, _ -> first.cancel(); true })
        assertFalse(first.prepare(member, repository()))
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.Cancelled), first.state())
        lateinit var second: GroupRootAdoptionAttempt
        second = owner(remoteVerifier = { _, _ -> second.block(); true })
        assertTrue(second.prepare(member, repository()))
        completeLocal(second)
        assertFalse(receive(second))
        assertNull(second.releaseForCommit(member, repository()))
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.Blocked), second.state())
    }

    @Test
    fun unexpectedCryptoFailurePropagatesAndCannotRetryTheCandidate() {
        val failure = IllegalStateException("Test OS failure")
        val owner = owner(proofVerifier = { _, _, _ -> throw failure })
        assertSame(failure, assertFailsWith<IllegalStateException> { owner.prepare(member, repository()) })
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.AdapterFailed), owner.state())
        assertFalse(owner.prepare(member, repository { error("Closed owner cannot read") }))
    }

    @Test
    fun delegatedIssuerDoesNotReplaceTheCandidateFounderAndAllSignaturesAreChecked() {
        val path = listOf(
            SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, founder, other), "cHJvb2Y="),
            SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, other, member), "cHJvb2Y="),
        )
        val delegatedProof = GroupAdmissionProof(anchor, path)
        val delegatedOffer = ProtocolHandshakeParticipant(other, issuerOffer.nonce, caps)
        val checked = mutableListOf<String>()
        val owner = GroupRootAdoptionAttempt(ProtocolHandshakeOffers(memberOffer, delegatedOffer, 200),
            member, other, other, delegatedProof, 100, { now },
            { issuer, _, _ -> checked.add(issuer); true }, { _, _ -> true })
        assertTrue(owner.prepare(member, repository()))
        assertEquals(listOf(founder, other), checked)
        val expected = GroupAdmissionConfirmationContext(delegatedOffer, memberOffer, anchor, delegatedProof)
        assertContentEquals(expected.comparisonBytes(), assertNotNull(owner.comparison()).bytes)
        completeLocal(owner)
        assertTrue(owner.receive(other, member, "cHJvb2Y="))
        val draft = assertNotNull(owner.releaseForCommit(member, repository()))
        assertEquals(anchor, draft.anchor)
        assertEquals(2, draft.proof.admissions.size)
    }

    @Test
    fun brokenPathIsRefusedWithoutInvokingAnyIssuerCertificateVerifier() {
        val brokenProof = GroupAdmissionProof(anchor, listOf(proof.admissions.single(), proof.admissions.single()))
        val owner = GroupRootAdoptionAttempt(ProtocolHandshakeOffers(memberOffer, issuerOffer, 200),
            member, founder, founder, brokenProof, 100, { now },
            { _, _, _ -> error("Broken path must fail before crypto") }, { _, _ -> true })
        assertFalse(owner.prepare(member, repository()))
        assertNull(owner.comparison())
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.InvalidProof(
            GroupAdmissionChainResult.BrokenChain)), owner.state())
    }

    @Test
    fun clockFailureAndOverflowCannotReturnADraftAfterConfirmation() {
        var failClock = false
        val failure = IllegalStateException("Test clock failed")
        val owner = GroupRootAdoptionAttempt(ProtocolHandshakeOffers(memberOffer, issuerOffer, 200),
            member, founder, founder, proof, 100, { if (failClock) throw failure else now },
            { _, _, _ -> true }, { _, _ -> true })
        assertTrue(owner.prepare(member, repository()))
        complete(owner)
        failClock = true
        assertSame(failure, assertFailsWith<IllegalStateException> {
            owner.releaseForCommit(member, repository { error("Clock failure must refuse before storage") })
        })
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.AdapterFailed), owner.state())
        val overflow = GroupRootAdoptionAttempt(ProtocolHandshakeOffers(memberOffer, issuerOffer, Long.MIN_VALUE),
            member, founder, founder, proof, Long.MIN_VALUE, { Long.MAX_VALUE },
            { _, _, _ -> error("Overflow must expire") }, { _, _ -> true })
        assertFalse(overflow.prepare(member, repository { error("No read on expiration") }))
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.Expired), overflow.state())
    }

    @Test
    fun duplicateRemoteConfirmationDuringFinalReadInvalidatesTheRelease() {
        val owner = confirmed()
        assertNull(owner.releaseForCommit(member, repository {
            assertFalse(receive(owner))
            null
        }))
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.UnexpectedConfirmation), owner.state())
    }

    @Test
    fun clockCallbackCancellationCannotPublishAnActiveSnapshot() {
        var cancelFromClock = false
        lateinit var owner: GroupRootAdoptionAttempt
        owner = GroupRootAdoptionAttempt(ProtocolHandshakeOffers(memberOffer, issuerOffer, 200),
            member, founder, founder, proof, 100, {
                if (cancelFromClock) owner.cancel()
                now
            }, { _, _, _ -> true }, { _, _ -> true })
        assertTrue(owner.prepare(member, repository()))
        complete(owner)
        cancelFromClock = true
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.Cancelled), owner.state())
        assertNull(owner.releaseForCommit(member, repository { error("Closed request cannot read") }))
    }

    @Test
    fun handoverIsMonouseAndKeepsTheOriginalDeadlineAndRecord() {
        val owner = confirmed()
        val record = stagedRecord()
        now = 1_000
        val next = assertNotNull(handover(owner, record))
        assertSame(record, next.record)
        assertTrue(next.matchesRecord(stagedRecord()))
        assertContentEquals(context.comparisonBytes(), next.draft.comparisonBytes())
        assertEquals(GroupRootAdoptionState.ReleasedForCommit, owner.state())
        assertNull(handover(owner, record))
        assertNull(owner.releaseForCommit(member, repository()))
        owner.cancel() // Lifecycle routing has moved to the receiving owner.
        assertFalse(receive(owner)) // Retired transport callbacks cannot mutate the new owner.
        assertEquals(GroupAdmissionConfirmationState.Confirmed, next.state())
        assertEquals(GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS - 900, next.remainingMillis())
        now = 100 + GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.Expired), next.state())
        assertFalse(next.matchesRecord(record))
        assertNull(next.remainingMillis())
    }

    @Test
    fun handoverRevocationIsTerminalAndPreservesFirstReason() {
        val events: List<Pair<(GroupRootAdoptionHandover) -> Unit, GroupAdmissionConfirmationFailure>> = listOf(
            { next: GroupRootAdoptionHandover -> next.cancel() } to GroupAdmissionConfirmationFailure.Cancelled,
            { next: GroupRootAdoptionHandover -> next.block() } to GroupAdmissionConfirmationFailure.Blocked,
            { next: GroupRootAdoptionHandover -> next.leaveGroup() } to GroupAdmissionConfirmationFailure.LeftGroup,
            { next: GroupRootAdoptionHandover -> next.transportClosed() } to GroupAdmissionConfirmationFailure.TransportClosed,
        )
        for ((event, reason) in events) {
            val next = assertNotNull(handover(confirmed(), stagedRecord()))
            event(next)
            next.cancel()
            next.block()
            assertEquals(GroupAdmissionConfirmationState.Closed(reason), next.state())
            assertFalse(next.matchesRecord(stagedRecord()))
            assertNull(next.remainingMillis())
        }
    }

    @Test
    fun mismatchedJournalDoesNotConsumeTheLiveAttempt() {
        val variants = listOf(
            stagedRecord(local = other), stagedRecord(peer = other),
            stagedRecord(root = GroupTrustAnchor(other, founder)), stagedRecord(payload = byteArrayOf(1)),
            stagedRecord(payload = GroupRootAdoptionJournalCodec.encode(journal(localSignature = "b3RoZXI="))),
        )
        for (record in variants) {
            val owner = confirmed()
            assertFailsWith<IllegalArgumentException> { handover(owner, record) }
            val next = assertNotNull(handover(owner, stagedRecord()))
            assertFalse(next.matchesRecord(record))
            assertFalse(next.matchesRecord(stagedRecord(attemptId = other)))
        }
    }

    @Test
    fun handoverRequiresLiveConfirmationsAndFreshEmptyLocalContext() {
        assertNull(handover(owner(), stagedRecord()))
        val changed = confirmed()
        assertNull(handover(changed, stagedRecord(), identity = other))
        assertEquals(closed(GroupRootAdoptionFailure.IdentityChanged), changed.state())
        val grouped = confirmed()
        assertNull(handover(grouped, stagedRecord(), store = repository { anchor }))
        assertEquals(closed(GroupRootAdoptionFailure.AlreadyInGroup), grouped.state())
        val revoked = confirmed()
        assertNull(handover(revoked, stagedRecord(), store = repository {
            revoked.block()
            null
        }))
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.Blocked), revoked.state())
    }

    @Test
    fun handoverRetainsWatermarkAndPropagatesClockFailureWithoutResurrection() {
        val next = assertNotNull(handover(confirmed(), stagedRecord()))
        now = 199
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.ClockMovedBackwards), next.state())
        now = 200
        assertFalse(next.matchesRecord(stagedRecord()))

        var fail = false
        val failure = IllegalStateException("Test clock unavailable")
        val owner = GroupRootAdoptionAttempt(ProtocolHandshakeOffers(memberOffer, issuerOffer, 200),
            member, founder, founder, proof, 100, { if (fail) throw failure else now },
            { _, _, _ -> true }, { _, _ -> true })
        assertTrue(owner.prepare(member, repository()))
        complete(owner)
        val transferred = assertNotNull(handover(owner, stagedRecord()))
        fail = true
        assertSame(failure, assertFailsWith<IllegalStateException> { transferred.state() })
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.AdapterFailed), transferred.state())
    }

    @Test
    fun handoverReadFailureAndReentryCannotLeakOrDuplicateAContinuation() {
        val owner = confirmed()
        val record = stagedRecord()
        val failure = IllegalStateException("Test read failure")
        assertSame(failure, assertFailsWith<IllegalStateException> {
            handover(owner, record, store = repository {
                assertNull(handover(owner, record))
                throw failure
            })
        })
        assertEquals(closed(GroupRootAdoptionFailure.StorageFailed), owner.state())
        assertNull(handover(owner, record))

        val expired = confirmed()
        assertNull(handover(expired, record, store = repository {
            now = 100 + GroupAdmissionConfirmationAttempt.TIMEOUT_MILLIS
            null
        }))
        assertEquals(confirmationClosed(GroupAdmissionConfirmationFailure.Expired), expired.state())
    }

    @Test
    fun substitutedEvidenceOrMemberCertificateCannotBindTheOriginalRecord() {
        val owner = confirmed()
        val record = stagedRecord()
        val alteredEvidence = GroupAdmissionEvidence(proof, listOf(GroupAdmissionCertificate(founder, "AQ==")))
        assertFailsWith<IllegalArgumentException> {
            owner.handover(member, repository(), record, alteredEvidence, memberCertificate)
        }
        assertFailsWith<IllegalArgumentException> {
            owner.handover(member, repository(), record, evidence, GroupAdmissionCertificate(member, "AQ=="))
        }
        assertNotNull(handover(owner, record))
    }

    private val evidence get() = GroupAdmissionEvidence(proof, listOf(GroupAdmissionCertificate(founder, "AA==")))
    private val memberCertificate get() = GroupAdmissionCertificate(member, "AA==")
    private fun journal(localSignature: String = "cHJvb2Y=") = GroupRootAdoptionJournal(
        evidence, memberOffer, issuerOffer, memberCertificate,
        GroupAdmissionConfirmation(member, founder, localSignature),
        GroupAdmissionConfirmation(founder, member, "cHJvb2Y="),
    )
    private fun stagedRecord(
        attemptId: String = "1".repeat(64), local: String = member, peer: String = founder,
        root: GroupTrustAnchor = anchor, payload: ByteArray = GroupRootAdoptionJournalCodec.encode(journal()),
    ) = PendingGroupAdoption(attemptId, local, peer, root, payload)
    private fun handover(
        owner: GroupRootAdoptionAttempt, record: PendingGroupAdoption,
        identity: String = member, store: LocalGroupRepository = repository(),
    ) = owner.handover(identity, store, record, evidence, memberCertificate)

    private fun owner(
        selected: String = founder,
        tlsPeer: String = founder,
        proofVerifier: (String, ByteArray, String) -> Boolean = { _, _, _ -> true },
        remoteVerifier: (ByteArray, String) -> Boolean = { _, _ -> true },
    ) = GroupRootAdoptionAttempt(ProtocolHandshakeOffers(memberOffer, issuerOffer, 200), member,
        selected, tlsPeer, proof, 100, { now }, proofVerifier, remoteVerifier)

    private fun prepared() = owner().also { assertTrue(it.prepare(member, repository())) }
    private fun confirmed() = prepared().also(::complete)
    private fun complete(owner: GroupRootAdoptionAttempt) {
        completeLocal(owner)
        assertTrue(receive(owner))
    }
    private fun completeLocal(owner: GroupRootAdoptionAttempt) {
        val sign = assertNotNull(owner.confirm(assertNotNull(owner.comparison())))
        assertTrue(owner.sent(assertNotNull(owner.signed(sign, "cHJvb2Y="))))
    }
    private fun receive(owner: GroupRootAdoptionAttempt) = owner.receive(founder, member, "cHJvb2Y=")
    private fun closed(reason: GroupRootAdoptionFailure) = GroupRootAdoptionState.Closed(reason)
    private fun confirmationClosed(reason: GroupAdmissionConfirmationFailure) =
        closed(GroupRootAdoptionFailure.Confirmation(reason))
    private fun repository(read: () -> GroupTrustAnchor? = { null }) = object : LocalGroupRepository {
        override fun localGroup() = read()
        override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean =
            error("Root adoption preparation must never write a local foundation")
    }
}
