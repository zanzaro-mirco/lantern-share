package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import kotlin.test.*

/** Syntax/pure merge only. Real DER, signatures and transport are covered by Node integration. */
class GroupSessionRosterTest {
    private val founder = "a".repeat(64)
    private val member = "b".repeat(64)
    private val anchor = GroupTrustAnchor("c".repeat(64), founder)
    private val session = "d".repeat(64)
    private val certificate = GroupAdmissionCertificate(founder, "AA==")
    private fun join(id: String = founder, signature: String = "AQ==", sessionId: String = session): GroupSessionJoin {
        val evidence = if (id == founder) null else GroupAdmissionEvidence(
            GroupAdmissionProof(anchor, listOf(SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, founder, id), "AAAA"))),
            listOf(certificate))
        return GroupSessionJoin(sessionId, GroupMembershipEvidence(anchor, id, evidence), GroupAdmissionCertificate(id, "AA=="), signature)
    }

    @Test
    fun canonicalRoundTripRetainsOfflineParticipantsAndAllJoinMaterial() {
        val roster = GroupSessionRoster(anchor, session, listOf(join(member), join()), true)
        val bytes = GroupSessionRosterCodec.encode(roster)
        val decoded = GroupSessionRosterCodec.decode(bytes)
        assertTrue(decoded.retainedSnapshot)
        assertEquals(setOf(founder, member), decoded.participants)
        assertContentEquals(bytes, GroupSessionRosterCodec.encode(decoded))
        for (entry in decoded.entries) {
            val encoded = GroupSessionRosterCodec.encodeJoin(entry)
            assertContentEquals(encoded, GroupSessionRosterCodec.encodeJoin(GroupSessionRosterCodec.decodeJoin(encoded)))
        }
        val exposed = decoded.entries.toMutableList()
        exposed.clear()
        assertEquals(2, decoded.entries.size)
    }

    @Test
    fun mergeIsGrowOnlyIdempotentCommutativeAndDeterministicForRepeatedSignatures() {
        val a = GroupSessionRoster(anchor, session, listOf(join(signature = "Ag=="), join(member)), true)
        val b = GroupSessionRoster(anchor, session, listOf(join(signature = "AQ==")))
        val ab = a.merge(b)
        assertEquals(setOf(founder, member), ab.participants)
        assertTrue(ab.retainedSnapshot)
        assertContentEquals(GroupSessionRosterCodec.encode(ab), GroupSessionRosterCodec.encode(b.merge(a)))
        assertContentEquals(GroupSessionRosterCodec.encode(ab), GroupSessionRosterCodec.encode(ab.merge(ab)))
        val third = GroupSessionRoster(anchor, session, listOf(join("e".repeat(64))))
        assertEquals(3, ab.merge(third).participants.size)
        assertFails { a.merge(GroupSessionRoster(anchor, "e".repeat(64), listOf(join(sessionId = "e".repeat(64))))) }
        assertFails { GroupSessionRoster(anchor, session, listOf(join(), join())) }
    }

    @Test
    fun joinVerificationRequiresIndependentRootSessionOwnSignatureAndMembershipChain() {
        val adopted = join(member)
        var calls = 0
        assertTrue(adopted.verify(anchor, session) { cert, bytes, signature ->
            calls++
            if (cert.identity == founder) signature == "AAAA"
            else {
                assertEquals(member, cert.identity)
                assertContentEquals(GroupSessionRosterCodec.signingBytes(session, adopted.membership, adopted.certificate), bytes)
                signature == adopted.signature
            }
        })
        assertEquals(2, calls)
        assertFalse(adopted.verify(anchor, "e".repeat(64)) { _, _, _ -> error("Wrong session before OS") })
        assertFalse(adopted.verify(anchor.copy(groupId = "e".repeat(64)), session) { _, _, _ -> error("Wrong root before OS") })
        assertFalse(adopted.verify(anchor, session) { cert, _, _ -> cert.identity == founder })
        assertFalse(adopted.verify(anchor, session) { cert, _, _ -> cert.identity == member })
        assertFailsWith<IllegalStateException> { adopted.verify(anchor, session) { _, _, _ -> error("Provider failure") } }
    }

    @Test
    fun requiredFeaturesPrecedeIoAndAgreementBindsFullSnapshotDigest() {
        val features = setOf(GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE, GroupSessionRosterCodec.FEATURE)
        fun participant(id: String, required: Set<String> = features) = ProtocolHandshakeParticipant(id, "e".repeat(64), ProtocolCapabilities(1, features, required))
        assertTrue(GroupSessionRosterCodec.sendsFirst(ProtocolHandshakeOffers(participant(founder), participant(member), 0)))
        assertFalse(GroupSessionRosterCodec.sendsFirst(ProtocolHandshakeOffers(participant(member), participant(founder), 0)))
        for (missing in features) {
            assertFails { GroupSessionRosterCodec.sendsFirst(ProtocolHandshakeOffers(participant(founder, features - missing), participant(member), 0)) }
            assertFails { GroupSessionRosterCodec.sendsFirst(ProtocolHandshakeOffers(participant(founder), participant(member, features - missing), 0)) }
        }
        val roster = GroupSessionRoster(anchor, session, listOf(join()))
        val agreement = GroupSessionRosterCodec.agreement(roster, "f".repeat(64))
        assertEquals(GroupSessionRosterCodec.AGREEMENT_BYTES, agreement.size)
        assertContentEquals(byteArrayOf(76, 82, 65, 1) + (anchor.groupId + session + "f".repeat(64)).encodeToByteArray(), agreement)
    }

    @Test
    fun malformedLengthsCountsFlagsDuplicateIdentitiesTrailingBytesAndTruncationsFailClosed() {
        val bytes = GroupSessionRosterCodec.encode(GroupSessionRoster(anchor, session, listOf(join())))
        for (end in bytes.indices) assertFails { GroupSessionRosterCodec.decode(bytes.copyOf(end)) }
        for (offset in listOf(0, 3, 4, 196, 197, 198, 199, 200, 201, 202, 203, 204)) {
            val bad = bytes.copyOf().also { it[offset] = 127 }
            assertFails { GroupSessionRosterCodec.decode(bad) }
        }
        assertFails { GroupSessionRosterCodec.decode(bytes + byteArrayOf(1)) }
        val record = GroupSessionRosterCodec.encodeJoin(join())
        val duplicate = bytes.copyOfRange(0, GroupSessionRosterCodec.PREFIX_BYTES).also { it[200] = 2 } +
            integer(record.size) + record + integer(record.size) + record
        assertFails { GroupSessionRosterCodec.decode(duplicate) }
        for (size in listOf(0, -1, GroupSessionRosterCodec.MAX_BYTES + 1)) assertFails { GroupSessionRosterCodec.payloadBytes(integer(size)) }
        assertFails { GroupSessionRosterCodec.payloadBytes(integer(GroupSessionRosterCodec.AGREEMENT_BYTES)) }
        assertFails { GroupSessionRosterCodec.payloadBytes(integer(GroupSessionRosterCodec.PREFIX_BYTES), true) }
        assertEquals(GroupSessionRosterCodec.AGREEMENT_BYTES, GroupSessionRosterCodec.payloadBytes(integer(GroupSessionRosterCodec.AGREEMENT_BYTES), true))
    }

    @Test
    fun outboundBudgetRejectsWholeSnapshotWithoutTruncatingItsParticipants() {
        val largeCertificate = "A".repeat(GroupAdmissionCertificate.MAX_ENCODED_LENGTH - 2) + "=="
        val entries = List(400) { index ->
            val memberId = index.toString(16).padStart(64, '0')
            val proof = GroupAdmissionEvidence(
                GroupAdmissionProof(anchor, listOf(SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, founder, memberId), "AAAA"))),
                listOf(GroupAdmissionCertificate(founder, largeCertificate)))
            GroupSessionJoin(session, GroupMembershipEvidence(anchor, memberId, proof),
                GroupAdmissionCertificate(memberId, largeCertificate), "AQ==")
        }
        val roster = GroupSessionRoster(anchor, session, entries)
        assertFailsWith<IllegalArgumentException> { GroupSessionRosterCodec.encode(roster) }
        assertEquals(400, roster.participants.size)
        assertEquals(entries.map { it.memberId }.toSet(), roster.participants)
    }

    private fun integer(value: Int) = ByteArray(4) { (value ushr ((3 - it) * 8)).toByte() }
}
