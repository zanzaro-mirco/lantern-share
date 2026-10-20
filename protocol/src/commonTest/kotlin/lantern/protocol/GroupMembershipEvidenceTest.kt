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
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Shared rules and bounded format; callback success is not OS crypto/TLS evidence. */
class GroupMembershipEvidenceTest {
    private val founder = "a".repeat(64)
    private val member = "b".repeat(64)
    private val anchor = GroupTrustAnchor("c".repeat(64), founder)
    private val certificate = GroupAdmissionCertificate(member, "AA==")
    private val path = GroupAdmissionEvidence(GroupAdmissionProof(anchor, listOf(
        SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, founder, member), "AAAA"))),
        listOf(GroupAdmissionCertificate(founder, "AA==")))
    private val membership = GroupMembershipEvidence(anchor, member, path)

    @Test
    fun founderAndDelegatedProofsRoundTripWithoutInventedSelfAdmission() {
        for (evidence in listOf(GroupMembershipEvidence(anchor, founder, null), membership)) {
            val bytes = GroupMembershipEvidenceCodec.encode(evidence)
            assertEquals(anchor.groupId, bytes.copyOfRange(4, 68).decodeToString())
            assertEquals(anchor.founderId, bytes.copyOfRange(68, 132).decodeToString())
            assertEquals(evidence.memberIdentity, bytes.copyOfRange(132, 196).decodeToString())
            val decoded = GroupMembershipEvidenceCodec.decode(bytes)
            assertEquals(evidence.anchor, decoded.anchor)
            assertEquals(evidence.memberIdentity, decoded.memberIdentity)
            assertContentEquals(bytes, GroupMembershipEvidenceCodec.encode(decoded))
            assertTrue(decoded.verify(anchor, evidence.memberIdentity) { cert, _, _ -> cert.identity == founder })
        }
        assertNull(GroupMembershipEvidenceCodec.decode(GroupMembershipEvidenceCodec.encode(
            GroupMembershipEvidence(anchor, founder, null))).admission)
    }

    @Test
    fun receivedRootAndIdentityCannotOverrideIndependentLocalGroupOrTlsPeer() {
        assertFalse(membership.verify(anchor.copy(groupId = "d".repeat(64)), member) { _, _, _ -> error("No OS call") })
        assertFalse(membership.verify(anchor.copy(founderId = member), member) { _, _, _ -> error("No OS call") })
        assertFalse(membership.verify(anchor, founder) { _, _, _ -> error("No OS call") })
        assertFalse(GroupMembershipEvidence(anchor, founder, null).verify(anchor, member) { _, _, _ -> error("No OS call") })
        assertFailsWith<IllegalArgumentException> { GroupMembershipEvidence(anchor, member, null) }
        assertFailsWith<IllegalArgumentException> { GroupMembershipEvidence(anchor, founder, path) }
    }

    @Test
    fun sharedExchangeOrderRequiresBothOffersToRequireTheModeAndMatchLocalIdentity() {
        val feature = GroupMembershipEvidenceCodec.FEATURE
        val agreed = ProtocolCapabilities(1, setOf(feature), setOf(feature))
        val optional = ProtocolCapabilities(1, setOf(feature), emptySet())
        fun offers(local: String, remote: String, localCaps: ProtocolCapabilities = agreed, remoteCaps: ProtocolCapabilities = agreed) =
            ProtocolHandshakeOffers(ProtocolHandshakeParticipant(local, "e".repeat(64), localCaps),
                ProtocolHandshakeParticipant(remote, "f".repeat(64), remoteCaps), 0)
        assertFalse(membership.sendsFirst(offers(member, founder)))
        assertTrue(GroupMembershipEvidence(anchor, founder, null).sendsFirst(offers(founder, member)))
        assertFailsWith<IllegalStateException> { membership.sendsFirst(offers(founder, member)) }
        assertFailsWith<IllegalStateException> { membership.sendsFirst(offers(member, founder, localCaps = optional)) }
        assertFailsWith<IllegalStateException> { membership.sendsFirst(offers(member, founder, remoteCaps = optional)) }
    }

    @Test
    fun fullChainVerificationAndProviderErrorsAreNotBooleansFromDiscovery() {
        assertFalse(membership.verify(anchor, member) { cert, bytes, signature ->
            assertEquals(founder, cert.identity)
            assertContentEquals(GroupAdmissionCodec.signedBytes(path.proof.admissions.single().claim), bytes)
            assertEquals("AAAA", signature)
            false
        })
        val failure = CancellationException("Test certificate provider cancellation")
        assertSame(failure, assertFailsWith<CancellationException> {
            membership.verify(anchor, member) { _, _, _ -> throw failure }
        })
    }

    @Test
    fun malformedTruncatedOversizedOrOtherProtocolInputIsRejected() {
        val encoded = GroupMembershipEvidenceCodec.encode(membership)
        for (length in 0 until encoded.size) assertFailsWith<IllegalArgumentException> {
            GroupMembershipEvidenceCodec.decode(encoded.copyOf(length))
        }
        for (offset in listOf(0, 3, 196)) {
            val invalid = encoded.copyOf().also { it[offset] = 127 }
            assertFailsWith<IllegalArgumentException> { GroupMembershipEvidenceCodec.decode(invalid) }
        }
        assertFailsWith<IllegalArgumentException> {
            GroupMembershipEvidenceCodec.decode(ByteArray(GroupMembershipEvidenceCodec.MAX_BYTES + 1))
        }
        assertFailsWith<IllegalArgumentException> { GroupMembershipEvidenceCodec.decode(GroupAdmissionEvidenceCodec.encode(path)) }
        val founderBytes = GroupMembershipEvidenceCodec.encode(GroupMembershipEvidence(anchor, founder, null))
        assertFailsWith<IllegalArgumentException> { GroupMembershipEvidenceCodec.decode(founderBytes + byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> {
            GroupMembershipEvidenceCodec.decode(founderBytes.copyOf().also { it[4] = 'G'.code.toByte() })
        }
        assertFailsWith<CharacterCodingException> {
            GroupMembershipEvidenceCodec.decode(founderBytes.copyOf().also { it[4] = 0xc0.toByte() })
        }
    }

    @Test
    fun framingRejectsZeroUnsignedOverflowAndOversizeBeforePayloadAllocation() {
        for (bytes in listOf(byteArrayOf(0, 0, 0, 0), byteArrayOf(0, 0, 0, 1), byteArrayOf(0, 4, 0, -58),
            byteArrayOf(-1, -1, -1, -1), byteArrayOf(127, -1, -1, -1))) {
            assertFailsWith<IllegalArgumentException> { GroupMembershipEvidenceCodec.payloadBytes(bytes) }
        }
        assertFailsWith<IllegalArgumentException> { GroupMembershipEvidenceCodec.header(GroupMembershipEvidenceCodec.MAX_BYTES + 1) }
        assertEquals(GroupMembershipEvidenceCodec.MAX_BYTES,
            GroupMembershipEvidenceCodec.payloadBytes(GroupMembershipEvidenceCodec.header(GroupMembershipEvidenceCodec.MAX_BYTES)))
    }

    @Test
    fun localProducerChecksHistoricalMaterialAndExactOsCertificateWithoutReadingPendingOrWriting() {
        val store = Store(record())
        var calls = 0
        val prepared = LocalGroupMembership.prepare(store, member, certificate) { _, _, _ -> calls++; true }
        assertEquals(3, calls) // Delegation and both historical confirmations.
        assertEquals(member, prepared.memberIdentity)
        assertEquals(anchor, prepared.anchor)
        assertFailsWith<IllegalStateException> {
            LocalGroupMembership.prepare(store, member, certificate.copy(der = "AAA=")) { _, _, _ -> true }
        }
        assertFailsWith<IllegalStateException> { LocalGroupMembership.prepare(store, member, certificate) { _, _, _ -> false } }
        store.committed = null
        assertFailsWith<IllegalArgumentException> { LocalGroupMembership.prepare(store, member, certificate) { _, _, _ -> true } }
        assertEquals(founder, LocalGroupMembership.prepare(store, founder, certificate.copy(identity = founder)) { _, _, _ ->
            error("Founder has no self-admission") }.memberIdentity)
    }

    @Test
    fun changedExactMarkerAndOsFailureDuringVerificationCannotProduceLocalEvidence() {
        val store = Store(record())
        assertFailsWith<IllegalStateException> {
            LocalGroupMembership.prepare(store, member, certificate) { _, _, _ ->
                store.committed = record("e".repeat(64))
                true
            }
        }
        val failure = IllegalStateException("Test OS provider failure")
        assertSame(failure, assertFailsWith<IllegalStateException> {
            LocalGroupMembership.prepare(Store(record()), member, certificate) { _, _, _ -> throw failure }
        })
    }

    private fun record(attempt: String = "d".repeat(64)): PendingGroupAdoption {
        val capabilities = ProtocolCapabilities(1, emptySet(), emptySet())
        val journal = GroupRootAdoptionJournal(path,
            ProtocolHandshakeParticipant(member, "e".repeat(64), capabilities),
            ProtocolHandshakeParticipant(founder, "f".repeat(64), capabilities), certificate,
            GroupAdmissionConfirmation(member, founder, "AAAB"), GroupAdmissionConfirmation(founder, member, "AAAC"))
        return PendingGroupAdoption(attempt, member, founder, anchor, GroupRootAdoptionJournalCodec.encode(journal))
    }

    private inner class Store(var committed: PendingGroupAdoption?) : GroupAdoptionRepository {
        override fun localGroup() = anchor
        override fun committedGroupAdoption() = committed
        override fun pendingGroupAdoption(): PendingGroupAdoption? = error("Must not read pending material")
        override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean = error("No writes")
        override fun stageGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean = error("No writes")
        override fun commitGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean = error("No writes")
        override fun removeGroupAdoption(record: PendingGroupAdoption): Boolean = error("No writes")
    }
}
