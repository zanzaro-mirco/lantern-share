package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupAdoptionRepository
import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption
import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

/** Shared rules only; signature callbacks are fixtures, not OS cryptography. */
class LocalGroupAdmissionTest {
    private val founder = "a".repeat(64)
    private val issuer = "b".repeat(64)
    private val member = "c".repeat(64)
    private val anchor = GroupTrustAnchor("d".repeat(64), founder)
    private val certificate = GroupAdmissionCertificate(issuer, "AA==")
    private val capabilities = ProtocolCapabilities(1, emptySet(), emptySet())

    @Test
    fun extendsVerifiedCommittedPathAndChecksAllHistoricalSignaturesBeforeSigning() {
        val store = Store(record())
        val before = store.committed!!.payload()
        val calls = mutableListOf<String>()
        val evidence = prepare(store, sign = { bytes ->
            assertEquals(listOf(founder, issuer, founder), calls)
            assertContentEquals(GroupAdmissionCodec.signedBytes(GroupAdmissionClaim(anchor.groupId, issuer, member)), bytes)
            bytes.fill(0) // Signer cannot change the verifier's canonical bytes.
            "AAAD"
        }, verify = { cert, bytes, signature ->
            if (signature == "AAAD") assertContentEquals(
                GroupAdmissionCodec.signedBytes(GroupAdmissionClaim(anchor.groupId, issuer, member)), bytes)
            calls += cert.identity
            true
        })
        assertEquals(listOf(founder, issuer, founder, issuer), calls)
        assertEquals(listOf(founder, issuer), evidence.certificates.map { it.identity })
        assertEquals(listOf(issuer, member), evidence.proof.admissions.map { it.claim.memberId })
        assertContentEquals(before, store.committed!!.payload())
        assertEquals(GroupAdmissionChainResult.VerifiedChain,
            GroupAdmissionChainVerification.verify(evidence.proof, anchor, member) { _, _, _ -> true })
    }

    @Test
    fun founderUsesSameProducerWithoutInventingAnAdmissionToItself() {
        val evidence = LocalGroupAdmission.prepareSigned(Store(null), founder, member,
            GroupAdmissionCertificate(founder, "AA=="), { "AAAA" }, { cert, _, _ -> cert.identity == founder })
        assertEquals(listOf(GroupAdmissionClaim(anchor.groupId, founder, member)), evidence.proof.admissions.map { it.claim })
    }

    @Test
    fun noCommittedMarkerNeverTreatsPendingMaterialOrAnchorAloneAsMembership() {
        val store = Store(null)
        assertFailsWith<IllegalArgumentException> { prepare(store, sign = { error("No signing") }) }
        store.root = null
        assertFailsWith<IllegalArgumentException> { prepare(store, sign = { error("No signing") }) }
    }

    @Test
    fun wrongIdentityRootCertificateOrAnyHistoricalSignaturePreventsNewSigning() {
        for (index in 0..2) {
            var calls = 0
            assertFailsWith<IllegalStateException> {
                prepare(Store(record()), sign = { error("No signing") }, verify = { _, _, _ -> calls++ != index })
            }
        }
        assertFailsWith<IllegalStateException> {
            prepare(Store(record()).apply { root = anchor.copy(groupId = "e".repeat(64)) }, sign = { error("No signing") })
        }
        assertFailsWith<IllegalStateException> {
            LocalGroupAdmission.prepareSigned(Store(record()), member, issuer, GroupAdmissionCertificate(member, "AA=="),
                { error("No signing") }, { _, _, _ -> true })
        }
        assertFailsWith<IllegalStateException> {
            LocalGroupAdmission.prepareSigned(Store(record()), issuer, member, certificate.copy(der = "AAA="),
                { error("No signing") }, { _, _, _ -> true })
        }
    }

    @Test
    fun cyclesSelfAdmissionAndFullPathsAreRejectedWithoutSigningOrTruncation() {
        for (target in listOf(founder, issuer, "alias")) {
            assertFailsWith<IllegalArgumentException> { prepare(Store(record()), target, sign = { error("No signing") }) }
        }
        val nodes = listOf(founder) + (1..31).map { it.toString(16).padStart(64, '0') } + issuer
        val full = nodes.zipWithNext().map { (from, to) -> SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, from, to), "AAAA") }
        assertFailsWith<IllegalArgumentException> { prepare(Store(record(full)), sign = { error("No signing") }) }
    }

    @Test
    fun changedGroupOrExactMarkerDuringSigningCannotEscapeAsEvidence() {
        for (changeRoot in listOf(false, true)) {
            val store = Store(record())
            assertFailsWith<IllegalStateException> {
                prepare(store, sign = {
                    if (changeRoot) store.root = anchor.copy(groupId = "e".repeat(64))
                    else store.committed = record(attempt = "f".repeat(64))
                    "AAAD"
                })
            }
        }
    }

    @Test
    fun osErrorsCancellationAndBadNewSignaturePropagateWithoutRetry() {
        val failure = CancellationException("Test OS cancelled")
        assertSame(failure, assertFailsWith<CancellationException> {
            prepare(Store(record()), verify = { _, _, _ -> throw failure })
        })
        val signing = IllegalStateException("Test signing failure")
        assertSame(signing, assertFailsWith<IllegalStateException> { prepare(Store(record()), sign = { throw signing }) })
        assertFailsWith<IllegalStateException> {
            prepare(Store(record()), verify = { _, _, signature -> signature != "AAAD" })
        }
    }

    private fun prepare(store: Store, target: String = member, sign: (ByteArray) -> String = { "AAAD" },
        verify: (GroupAdmissionCertificate, ByteArray, String) -> Boolean = { _, _, _ -> true }) =
        LocalGroupAdmission.prepareSigned(store, issuer, target, certificate, sign, verify)

    private fun record(path: List<SignedGroupAdmission> = listOf(
        SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, founder, issuer), "AAAA")),
        attempt: String = "e".repeat(64)): PendingGroupAdoption {
        val remote = path.last().claim.issuerId
        val journal = GroupRootAdoptionJournal(
            GroupAdmissionEvidence(GroupAdmissionProof(anchor, path), path.map { GroupAdmissionCertificate(it.claim.issuerId, "AA==") }),
            ProtocolHandshakeParticipant(issuer, "e".repeat(64), capabilities),
            ProtocolHandshakeParticipant(remote, "f".repeat(64), capabilities), certificate,
            GroupAdmissionConfirmation(issuer, remote, "AAAB"), GroupAdmissionConfirmation(remote, issuer, "AAAC"))
        return PendingGroupAdoption(attempt, issuer, remote, anchor, GroupRootAdoptionJournalCodec.encode(journal))
    }

    private inner class Store(var committed: PendingGroupAdoption?) : GroupAdoptionRepository {
        var root: GroupTrustAnchor? = anchor
        override fun localGroup() = root
        override fun committedGroupAdoption() = committed
        override fun pendingGroupAdoption(): PendingGroupAdoption? = error("Pending journal must never be read")
        override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean = error("No writes")
        override fun stageGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean = error("No writes")
        override fun commitGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean = error("No writes")
        override fun removeGroupAdoption(record: PendingGroupAdoption): Boolean = error("No writes")
    }
}
