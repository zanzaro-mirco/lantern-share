package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption
import lantern.domain.LocalGroupState
import lantern.domain.LocalGroupFailure
import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Shared rule tests. Callback success is a fixture, not OS certificate/signature verification. */
class GroupRootAdoptionJournalInspectionTest {
    private val founder = "a".repeat(64)
    private val issuer = "b".repeat(64)
    private val member = "c".repeat(64)
    private val anchor = GroupTrustAnchor("d".repeat(64), founder)
    private val capabilities = ProtocolCapabilities(1, setOf("text"))
    private val proof = GroupAdmissionProof(anchor, listOf(
        SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, founder, issuer), "AAAA"),
        SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, issuer, member), "AAAB"),
    ))
    private val journal = journal(proof)

    @Test
    fun committedPresentationRequiresMatchingRootIdentityAndEverySignature() {
        val committed = record()
        var calls = 0
        assertEquals(LocalGroupState.Adopted(anchor), localGroupPresentation(anchor, member, committed) { _, _, _ ->
            calls++
            true
        })
        assertEquals(4, calls)
        for (index in 0..3) {
            calls = 0
            assertEquals(LocalGroupState.Failed(LocalGroupFailure.INVALID_ROOT),
                localGroupPresentation(anchor, member, committed) { _, _, _ -> calls++ != index })
        }
        for (root in listOf(null, anchor.copy(groupId = "f".repeat(64)))) {
            assertEquals(LocalGroupState.Failed(LocalGroupFailure.INVALID_ROOT),
                localGroupPresentation(root, member, committed) { _, _, _ -> error("No verification") })
        }
        assertEquals(LocalGroupState.Failed(LocalGroupFailure.IDENTITY_MISMATCH),
            localGroupPresentation(anchor, founder, committed) { _, _, _ -> error("No verification") })
        assertEquals(LocalGroupState.Failed(LocalGroupFailure.INVALID_ROOT),
            localGroupPresentation(anchor, member, record(payload = byteArrayOf(1))) { _, _, _ -> error("No verification") })
    }

    @Test
    fun presentationNeverInfersAdoptionWithoutCommittedMarkerOrSwallowsProviderFailure() {
        assertEquals(LocalGroupState.Empty, localGroupPresentation(null, member, null) { _, _, _ -> error("No verification") })
        assertEquals(LocalGroupState.Failed(LocalGroupFailure.IDENTITY_MISMATCH),
            localGroupPresentation(anchor, member, null) { _, _, _ -> error("No verification") })
        val failure = CancellationException("Test provider cancellation")
        assertSame(failure, assertFailsWith<CancellationException> {
            localGroupPresentation(anchor, member, record()) { _, _, _ -> throw failure }
        })
        val providerFailure = IllegalArgumentException("Test provider error")
        assertSame(providerFailure, assertFailsWith<IllegalArgumentException> {
            localGroupPresentation(anchor, member, record()) { _, _, _ -> throw providerFailure }
        })
    }

    @Test
    fun checksEveryDelegationAndBothDirectionsOnReconstructedBytes() {
        val calls = mutableListOf<String>()
        val context = journal.comparisonContext()
        val before = record().payload()
        assertEquals(GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid,
            GroupRootAdoptionJournalInspection.inspect(record(), member) { certificate, bytes, signature ->
                when (calls.size) {
                    0, 1 -> assertContentEquals(GroupAdmissionCodec.signedBytes(proof.admissions[calls.size].claim), bytes)
                    2 -> assertContentEquals(context.approvalBytes(member), bytes)
                    3 -> assertContentEquals(context.approvalBytes(issuer), bytes)
                }
                calls += certificate.identity
                assertEquals(listOf("AAAA", "AAAB", "AAAC", "AAAD")[calls.lastIndex], signature)
                true
            })
        assertEquals(listOf(founder, issuer, member, issuer), calls)
        assertContentEquals(before, record().payload())
    }

    @Test
    fun metadataAndCurrentOsIdentityAreCheckedBeforeCryptography() {
        assertEquals(GroupRootAdoptionJournalInspectionResult.LocalIdentityMismatch,
            inspectWithoutCrypto(record(), founder))
        val mismatches = listOf(
            record(local = "e".repeat(64)), record(peer = founder),
            record(anchor = anchor.copy(groupId = "e".repeat(64))),
            record(anchor = anchor.copy(founderId = issuer)),
        )
        for (record in mismatches) {
            assertEquals(GroupRootAdoptionJournalInspectionResult.MetadataMismatch, inspectWithoutCrypto(record, record.localIdentity))
        }
        assertFailsWith<IllegalArgumentException> { inspectWithoutCrypto(record(), "alias") }
    }

    @Test
    fun malformedAndUnknownPayloadsPropagateEvenWhenIdentityDiffers() {
        val invalidUtf8 = record().payload()
        val memberDerOffset = 5 + 4 * 4 + GroupAdmissionEvidenceCodec.encode(journal.evidence).size +
            ProtocolHandshakeHelloCodec.encode(journal.localOffer).size + ProtocolHandshakeHelloCodec.encode(journal.remoteOffer).size
        invalidUtf8[memberDerOffset] = 0xc0.toByte()
        for (bytes in listOf(byteArrayOf(76, 71, 82, 74, 2), byteArrayOf(1),
            record().payload().dropLast(1).toByteArray(), invalidUtf8)) {
            val record = record(payload = bytes)
            assertFailsWith<InvalidGroupRootAdoptionJournalException> { inspectWithoutCrypto(record, member) }
            assertFailsWith<InvalidGroupRootAdoptionJournalException> { inspectWithoutCrypto(record, founder) }
            assertContentEquals(bytes, record.payload())
        }
    }

    @Test
    fun syntaxDiagnosticsNeverExportUntrustedParserContents() {
        val valid = record().payload()
        val fieldLength = GroupAdmissionEvidenceCodec.encode(journal.evidence).size
        val secret = "{\"peer-secret-do-not-log\":true,".encodeToByteArray()
        val evidence = secret + valid.copyOfRange(10, 9 + fieldLength)
        val length = ByteArray(4) { index -> (evidence.size ushr (24 - index * 8)).toByte() }
        val malformed = valid.copyOfRange(0, 5) + length + evidence + valid.copyOfRange(9 + fieldLength, valid.size)
        val failure = assertFailsWith<InvalidGroupRootAdoptionJournalException> { inspectWithoutCrypto(record(payload = malformed), member) }
        assertEquals("Invalid stored group adoption payload", failure.message)
        assertNull(failure.cause)
        assertTrue(failure.suppressedExceptions.isEmpty())
    }

    @Test
    fun brokenChainStopsBeforeAnyCertificateWork() {
        val broken = GroupAdmissionProof(anchor, listOf(proof.admissions.last()))
        val record = record(payload = GroupRootAdoptionJournalCodec.encode(journal(broken)))
        assertEquals(GroupRootAdoptionJournalInspectionResult.InvalidChain(GroupAdmissionChainResult.BrokenChain),
            inspectWithoutCrypto(record, member))
    }

    @Test
    fun eachSignatureFailureStopsAtItsOwnBoundary() {
        val expected = listOf(
            GroupRootAdoptionJournalInspectionResult.InvalidChain(GroupAdmissionChainResult.InvalidSignature(0)),
            GroupRootAdoptionJournalInspectionResult.InvalidChain(GroupAdmissionChainResult.InvalidSignature(1)),
            GroupRootAdoptionJournalInspectionResult.InvalidLocalConfirmation,
            GroupRootAdoptionJournalInspectionResult.InvalidRemoteConfirmation,
        )
        for (index in expected.indices) {
            var calls = 0
            assertEquals(expected[index], GroupRootAdoptionJournalInspection.inspect(record(), member) { _, _, _ -> calls++ != index })
            assertEquals(index + 1, calls)
        }
    }

    @Test
    fun unexpectedCallbackErrorsPropagateAtEverySignatureWithoutChangingTheSnapshot() {
        val failures = listOf(IllegalStateException("OS unavailable"), IllegalArgumentException("Provider argument failure"))
        for (failure in failures) {
            for (index in 0..3) {
                val record = record()
                val before = record.payload()
                var calls = 0
                assertSame(failure, assertFailsWith<Exception> {
                    GroupRootAdoptionJournalInspection.inspect(record, member) { _, _, _ ->
                        if (calls++ == index) throw failure
                        true
                    }
                })
                assertContentEquals(before, record.payload())
            }
        }
    }

    @Test
    fun attemptIdDoesNotClaimAuthenticationAndNoConsentTokenIsReturned() {
        val first = record()
        val second = PendingGroupAdoption("f".repeat(64), member, issuer, anchor, first.payload())
        for (record in listOf(first, second)) {
            assertEquals(GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid,
                GroupRootAdoptionJournalInspection.inspect(record, member) { _, _, _ -> true })
        }
        assertTrue(first.attemptId != second.attemptId)
    }

    @Test
    fun cancellationIsNeverMappedToInvalidMaterialOrSuccess() {
        val cancellation = CancellationException("Inspection cancelled")
        for (index in 0..3) {
            var calls = 0
            assertSame(cancellation, assertFailsWith<CancellationException> {
                GroupRootAdoptionJournalInspection.inspect(record(), member) { _, _, _ ->
                    if (calls++ == index) throw cancellation
                    true
                }
            })
            assertEquals(index + 1, calls)
        }
    }

    @Test
    fun maximumDelegationPathStillRequiresEveryIssuerAndBothEndpoints() {
        val nodes = listOf(founder) + (1..31).map { it.toString(16).padStart(64, '0') } + member
        val path = nodes.zipWithNext { from, to ->
            SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, from, to), "AAAA")
        }
        val finalIssuer = nodes[nodes.lastIndex - 1]
        val proof = GroupAdmissionProof(anchor, path)
        val journal = GroupRootAdoptionJournal(
            GroupAdmissionEvidence(proof, nodes.dropLast(1).map { GroupAdmissionCertificate(it, "AA==") }),
            this.journal.localOffer, ProtocolHandshakeParticipant(finalIssuer, "f".repeat(64), capabilities),
            this.journal.memberCertificate,
            GroupAdmissionConfirmation(member, finalIssuer, "AAAC"), GroupAdmissionConfirmation(finalIssuer, member, "AAAD"),
        )
        val record = record(peer = finalIssuer, payload = GroupRootAdoptionJournalCodec.encode(journal))
        val checked = mutableListOf<String>()
        assertEquals(GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid,
            GroupRootAdoptionJournalInspection.inspect(record, member) { cert, _, _ ->
                checked.add(cert.identity)
                true
            })
        assertEquals(nodes.dropLast(1) + member + finalIssuer, checked)
        assertEquals(GroupAdmissionChainVerification.MAX_ADMISSIONS + 2, checked.size)
    }

    private fun inspectWithoutCrypto(record: PendingGroupAdoption, currentIdentity: String) =
        GroupRootAdoptionJournalInspection.inspect(record, currentIdentity) { _, _, _ -> error("No cryptography expected") }

    private fun record(
        local: String = member,
        peer: String = issuer,
        anchor: GroupTrustAnchor = this.anchor,
        payload: ByteArray = GroupRootAdoptionJournalCodec.encode(journal),
    ) = PendingGroupAdoption("e".repeat(64), local, peer, anchor, payload)

    private fun journal(proof: GroupAdmissionProof): GroupRootAdoptionJournal = GroupRootAdoptionJournal(
        GroupAdmissionEvidence(proof, proof.admissions.map { it.claim.issuerId }.distinct().map { GroupAdmissionCertificate(it, "AA==") }),
        ProtocolHandshakeParticipant(member, "e".repeat(64), capabilities),
        ProtocolHandshakeParticipant(issuer, "f".repeat(64), capabilities),
        GroupAdmissionCertificate(member, "AAA="),
        GroupAdmissionConfirmation(member, issuer, "AAAC"), GroupAdmissionConfirmation(issuer, member, "AAAD"),
    )
}
