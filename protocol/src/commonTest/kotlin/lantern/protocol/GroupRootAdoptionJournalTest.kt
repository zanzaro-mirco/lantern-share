package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository
import lantern.domain.PendingGroupAdoption
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Syntax/binding fixtures only; deliberately invalid X.509 and non-cryptographic signatures. */
class GroupRootAdoptionJournalTest {
    private val issuer = "a".repeat(64)
    private val member = "b".repeat(64)
    private val anchor = GroupTrustAnchor("c".repeat(64), issuer)
    private val capabilities = ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text"))
    private val local = ProtocolHandshakeParticipant(member, "d".repeat(64), capabilities)
    private val remote = ProtocolHandshakeParticipant(issuer, "e".repeat(64), capabilities)
    private val proof = GroupAdmissionProof(anchor, listOf(
        SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, issuer, member), "cHJvb2Y="),
    ))
    private val evidence = GroupAdmissionEvidence(proof, listOf(GroupAdmissionCertificate(issuer, "AA==")))
    private val certificate = GroupAdmissionCertificate(member, "AAA=")
    private val localConfirmation = GroupAdmissionConfirmation(member, issuer, "bG9jYWw=")
    private val remoteConfirmation = GroupAdmissionConfirmation(issuer, member, "cmVtb3Rl")

    @Test
    fun roundTripPreservesAllSignedMaterialWithoutAuthorizingIt() {
        val journal = record()
        val encoded = GroupRootAdoptionJournalCodec.encode(journal)
        assertContentEquals(byteArrayOf(76, 71, 82, 74, 1), encoded.copyOfRange(0, 5))
        assertContentEquals(pack(listOf(
            GroupAdmissionEvidenceCodec.encode(evidence), ProtocolHandshakeHelloCodec.encode(local),
            ProtocolHandshakeHelloCodec.encode(remote), certificate.der.encodeToByteArray(),
            GroupAdmissionConfirmationCodec.encode(localConfirmation), GroupAdmissionConfirmationCodec.encode(remoteConfirmation),
        )), encoded)
        val decoded = GroupRootAdoptionJournalCodec.decode(encoded)
        assertContentEquals(encoded, GroupRootAdoptionJournalCodec.encode(decoded))
        assertContentEquals(GroupAdmissionEvidenceCodec.encode(evidence), GroupAdmissionEvidenceCodec.encode(decoded.evidence))
        assertContentEquals(ProtocolHandshakeHelloCodec.encode(local), ProtocolHandshakeHelloCodec.encode(decoded.localOffer))
        assertContentEquals(ProtocolHandshakeHelloCodec.encode(remote), ProtocolHandshakeHelloCodec.encode(decoded.remoteOffer))
        assertEquals(certificate, decoded.memberCertificate)
        assertEquals(localConfirmation, decoded.localConfirmation)
        assertEquals(remoteConfirmation, decoded.remoteConfirmation)
        assertContentEquals(journal.comparisonContext().comparisonBytes(), decoded.comparisonContext().comparisonBytes())
        // Decode accepts syntax, not signatures, DER, pin or chain validity.
        assertEquals(GroupAdmissionConfirmationResult.InvalidSignature,
            GroupAdmissionConfirmationVerification.verifyRemote(decoded.comparisonContext(), member, issuer,
                issuer, member, decoded.remoteConfirmation.signature) { _, _ -> false })
    }

    @Test
    fun payloadAndExposedOfferMutationsDoNotChangeTheFrozenRecord() {
        val supported = mutableSetOf("text", "receipts")
        val source = ProtocolHandshakeParticipant(member, local.nonce, ProtocolCapabilities(1, supported))
        val journal = record(local = source)
        val before = GroupRootAdoptionJournalCodec.encode(journal)
        supported.clear()
        (source.capabilities.supportedFeatures as? MutableSet<String>)?.clear()
        (journal.localOffer.capabilities.supportedFeatures as? MutableSet<String>)?.clear()
        val bytes = GroupRootAdoptionJournalCodec.encode(journal)
        val decoded = GroupRootAdoptionJournalCodec.decode(bytes)
        bytes.fill(0)
        journal.comparisonContext().comparisonBytes().fill(0)
        assertContentEquals(before, GroupRootAdoptionJournalCodec.encode(journal))
        assertContentEquals(before, GroupRootAdoptionJournalCodec.encode(decoded))
    }

    @Test
    fun captureRequiresReleasedProofAndExactOfferContext() {
        val offers = ProtocolHandshakeOffers(local, remote, 200)
        val repository = object : LocalGroupRepository {
            override fun localGroup(): GroupTrustAnchor? = null
            override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean = error("No writes")
        }
        val attempt = GroupRootAdoptionAttempt(offers, member, issuer, issuer, proof, 100, { 200 },
            { _, _, _ -> true }, { _, _ -> true })
        assertTrue(attempt.prepare(member, repository))
        val signing = assertNotNull(attempt.confirm(assertNotNull(attempt.comparison())))
        assertTrue(attempt.sent(assertNotNull(attempt.signed(signing, localConfirmation.signature))))
        assertTrue(attempt.receive(issuer, member, remoteConfirmation.signature))
        val draft = assertNotNull(attempt.releaseForCommit(member, repository))
        val captured = GroupRootAdoptionJournal.fromDraft(draft, evidence, offers, certificate)
        assertContentEquals(draft.comparisonBytes(), captured.comparisonContext().comparisonBytes())
        val changedProof = GroupAdmissionProof(anchor, listOf(proof.admissions.single().copy(signature = "AAAA")))
        assertFailsWith<IllegalArgumentException> {
            GroupRootAdoptionJournal.fromDraft(draft, GroupAdmissionEvidence(changedProof, evidence.certificates), offers, certificate)
        }
        for (replacement in listOf(
            ProtocolHandshakeParticipant(member, "f".repeat(64), capabilities),
            ProtocolHandshakeParticipant(member, local.nonce, ProtocolCapabilities(1, setOf("text"), setOf("text"))),
            ProtocolHandshakeParticipant(member, local.nonce, ProtocolCapabilities(1, setOf("text", "receipts"))),
        )) {
            assertFailsWith<IllegalArgumentException> {
                GroupRootAdoptionJournal.fromDraft(draft, evidence, ProtocolHandshakeOffers(replacement, remote, 200), certificate)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            GroupRootAdoptionJournal.fromDraft(draft, evidence, ProtocolHandshakeOffers(remote, local, 200), certificate)
        }
    }

    @Test
    fun roleCertificateAndConfirmationMismatchesAreRejected() {
        assertFailsWith<IllegalArgumentException> { record(local = remote, remote = local) }
        assertFailsWith<IllegalArgumentException> { record(certificate = GroupAdmissionCertificate(issuer, "AAA=")) }
        assertFailsWith<IllegalArgumentException> { record(localConfirmation = remoteConfirmation) }
        assertFailsWith<IllegalArgumentException> { record(remoteConfirmation = localConfirmation) }
        assertFailsWith<IllegalArgumentException> {
            record(remote = ProtocolHandshakeParticipant(issuer, remote.nonce, ProtocolCapabilities(2, setOf("text"))))
        }
    }

    @Test
    fun everyTruncationAndTrailingDataIsRejected() {
        val bytes = GroupRootAdoptionJournalCodec.encode(record())
        for (end in bytes.indices) assertFails("Truncation at $end") {
            GroupRootAdoptionJournalCodec.decode(bytes.copyOfRange(0, end))
        }
        for (tail in listOf(byteArrayOf(0), bytes)) assertFailsWith<IllegalArgumentException> {
            GroupRootAdoptionJournalCodec.decode(bytes + tail)
        }
    }

    @Test
    fun magicVersionsUnsignedLengthsAndTotalSizeAreBounded() {
        val bytes = GroupRootAdoptionJournalCodec.encode(record())
        for (index in 0..4) {
            for (value in listOf(0, 2, 127, 255)) {
                if (bytes[index].toInt() and 255 == value) continue
                assertFailsWith<IllegalArgumentException> {
                    GroupRootAdoptionJournalCodec.decode(bytes.copyOf().also { it[index] = value.toByte() })
                }
            }
        }
        val fields = split(bytes)
        for (index in fields.indices) {
            for (length in listOf(0L, 0x7fffffffL, 0x80000000L, 0xffffffffL)) {
                assertFailsWith<IllegalArgumentException> {
                    GroupRootAdoptionJournalCodec.decode(pack(fields, index, length))
                }
            }
        }
        assertFailsWith<IllegalArgumentException> { GroupRootAdoptionJournalCodec.decode(ByteArray(GroupRootAdoptionJournalCodec.MAX_BYTES + 1)) }
    }

    @Test
    fun nestedSyntaxAndContextCannotBypassExistingCodecs() {
        val fields = split(GroupRootAdoptionJournalCodec.encode(record()))
        for (index in fields.indices) {
            val text = fields[index].decodeToString()
            val invalid = if (index == 3) listOf("AB==", "", "AAAA".repeat(1366)) else listOf(
                "{}", "[]", text + "{}", text.dropLast(1) + ",\"extra\":0}",
                "[".repeat(100) + "]".repeat(100),
            )
            for (value in invalid) assertFails("Field $index: $value") {
                GroupRootAdoptionJournalCodec.decode(pack(fields.toMutableList().also { it[index] = value.encodeToByteArray() }))
            }
            assertFails {
                GroupRootAdoptionJournalCodec.decode(pack(fields.toMutableList().also { it[index] = byteArrayOf(0xc3.toByte(), 0x28) }))
            }
        }
        // Reordering whole valid subrecords must not reverse local/remote roles.
        for ((first, second) in listOf(1 to 2, 4 to 5)) assertFailsWith<IllegalArgumentException> {
            GroupRootAdoptionJournalCodec.decode(pack(fields.toMutableList().also {
                it[first] = fields[second]; it[second] = fields[first]
            }))
        }
    }

    @Test
    fun syntacticallyValidChangesRemainUntrustedAndChangeTheSignedContext() {
        val original = record()
        val changed = record(local = ProtocolHandshakeParticipant(member, "f".repeat(64), capabilities))
        val decoded = GroupRootAdoptionJournalCodec.decode(GroupRootAdoptionJournalCodec.encode(changed))
        assertFalse(original.comparisonContext().comparisonBytes().contentEquals(decoded.comparisonContext().comparisonBytes()))
        // A codec cannot detect a validly encoded signature substitution; crypto must do that.
        val altered = record(remoteConfirmation = remoteConfirmation.copy(signature = "AAAA"))
        assertEquals("AAAA", GroupRootAdoptionJournalCodec.decode(GroupRootAdoptionJournalCodec.encode(altered)).remoteConfirmation.signature)
    }

    @Test
    fun maximumDelegationPathAndPublicCertificatesRoundTripWithinTheBudget() {
        assertTrue(GroupRootAdoptionJournalCodec.MAX_BYTES <= PendingGroupAdoption.MAX_PAYLOAD_BYTES)
        fun identity(index: Int) = index.toString(16).padStart(64, '0')
        val maximumDer = "AAAA".repeat(1365) + "AA==" // Exactly 4096 decoded bytes.
        val maximumSignature = "AAAA".repeat(64) // Maximum accepted signature encoding.
        val count = GroupAdmissionChainVerification.MAX_ADMISSIONS
        val path = List(count) { index ->
            SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, identity(index + 1), identity(index + 2)), maximumSignature)
        }
        val longProof = GroupAdmissionProof(GroupTrustAnchor(anchor.groupId, identity(1)), path)
        val longEvidence = GroupAdmissionEvidence(longProof, List(count) {
            GroupAdmissionCertificate(identity(it + 1), maximumDer)
        })
        val issuer = ProtocolHandshakeParticipant(identity(count), remote.nonce, capabilities)
        val member = ProtocolHandshakeParticipant(identity(count + 1), local.nonce, capabilities)
        val journal = GroupRootAdoptionJournal(longEvidence, member, issuer,
            GroupAdmissionCertificate(member.identity, maximumDer),
            GroupAdmissionConfirmation(member.identity, issuer.identity, maximumSignature),
            GroupAdmissionConfirmation(issuer.identity, member.identity, maximumSignature))
        val bytes = GroupRootAdoptionJournalCodec.encode(journal)
        assertTrue(bytes.size < GroupRootAdoptionJournalCodec.MAX_BYTES)
        val decoded = GroupRootAdoptionJournalCodec.decode(bytes)
        assertEquals(count, decoded.evidence.proof.admissions.size)
        assertEquals(count, decoded.evidence.certificates.size)
        assertContentEquals(bytes, GroupRootAdoptionJournalCodec.encode(decoded))
        assertContentEquals(journal.comparisonContext().approvalBytes(member.identity), decoded.comparisonContext().approvalBytes(member.identity))
    }

    @Test
    fun nestedDuplicateFieldsRemainVisibleAndRejected() {
        val fields = split(GroupRootAdoptionJournalCodec.encode(record()))
        val duplicates = mapOf(
            0 to "\"ver\\u0073ion\":1",
            1 to "\"id\\u0065ntity\":\"$member\"",
            2 to "\"nonce\":\"${remote.nonce}\"",
            4 to "\"sender\":\"$member\"",
            5 to "\"signature\":\"${remoteConfirmation.signature}\"",
        )
        for ((index, duplicate) in duplicates) assertFails {
            val payload = fields[index].decodeToString().dropLast(1) + ",$duplicate}"
            GroupRootAdoptionJournalCodec.decode(pack(fields.toMutableList().also { it[index] = payload.encodeToByteArray() }))
        }
    }

    private fun record(
        local: ProtocolHandshakeParticipant = this.local,
        remote: ProtocolHandshakeParticipant = this.remote,
        certificate: GroupAdmissionCertificate = this.certificate,
        localConfirmation: GroupAdmissionConfirmation = this.localConfirmation,
        remoteConfirmation: GroupAdmissionConfirmation = this.remoteConfirmation,
    ) = GroupRootAdoptionJournal(evidence, local, remote, certificate, localConfirmation, remoteConfirmation)

    // Independent fixture writer, including intentionally invalid unsigned lengths.
    private fun pack(fields: List<ByteArray>, changedIndex: Int = -1, changedLength: Long = 0): ByteArray {
        val output = mutableListOf<Byte>(76, 71, 82, 74, 1)
        fields.forEachIndexed { index, field ->
            val length = if (index == changedIndex) changedLength else field.size.toLong()
            for (shift in 24 downTo 0 step 8) output.add((length ushr shift).toByte())
            output.addAll(field.toList())
        }
        return output.toByteArray()
    }

    private fun split(bytes: ByteArray): List<ByteArray> {
        var offset = 5
        return List(6) {
            var size = 0
            repeat(4) { size = (size shl 8) or (bytes[offset++].toInt() and 255) }
            bytes.copyOfRange(offset, offset + size).also { offset += size }
        }
    }
}
