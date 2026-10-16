package lantern.connectivity

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupAdmissionChainResult
import lantern.protocol.GroupAdmissionCodec
import lantern.protocol.GroupAdmissionConfirmation
import lantern.protocol.GroupAdmissionConfirmationContext
import lantern.protocol.GroupAdmissionEvidence
import lantern.protocol.GroupAdmissionProof
import lantern.protocol.GroupRootAdoptionJournal
import lantern.protocol.GroupRootAdoptionJournalCodec
import lantern.protocol.GroupRootAdoptionJournalInspectionResult
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeParticipant
import lantern.protocol.SignedGroupAdmission
import lantern.persistence.openDesktopRepository
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.nio.file.Files
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Real P-256, certificate DER and JCA; no live consent, TLS or durable commit is simulated here. */
class GroupRootAdoptionJournalInspectorTest {
    private val founder = createDesktopIdentity().identity()
    private val issuer = createDesktopIdentity().identity()
    private val member = createDesktopIdentity().identity()
    private val anchor = GroupTrustAnchor(randomNonce(), founder.id)
    private val capabilities = ProtocolCapabilities(1, setOf("text"))
    private val proof = GroupAdmissionProof(anchor, listOf(admission(founder, issuer), admission(issuer, member)))
    private val local = ProtocolHandshakeParticipant(member.id, randomNonce(), capabilities)
    private val remote = ProtocolHandshakeParticipant(issuer.id, randomNonce(), capabilities)

    @Test
    fun checksRealDelegatedChainAndBothSignaturesWithoutPromotingTheCandidate() {
        val record = record(journal())
        repeat(2) {
            assertEquals(GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid,
                GroupRootAdoptionJournalInspector.inspect(record, member.id))
        }
    }

    @Test
    fun wrongCurrentIdentityOrMetadataFailsBeforeParsingAnyInvalidDer() {
        val invalid = journal(memberCertificate = GroupAdmissionCertificate(member.id, "AA=="))
        assertEquals(GroupRootAdoptionJournalInspectionResult.LocalIdentityMismatch,
            GroupRootAdoptionJournalInspector.inspect(record(invalid), founder.id))
        val encoded = GroupRootAdoptionJournalCodec.encode(invalid)
        for (record in listOf(
            PendingGroupAdoption(randomNonce(), member.id, founder.id, anchor, encoded),
            PendingGroupAdoption(randomNonce(), member.id, issuer.id, anchor.copy(groupId = randomNonce()), encoded),
        )) {
            assertEquals(GroupRootAdoptionJournalInspectionResult.MetadataMismatch,
                GroupRootAdoptionJournalInspector.inspect(record, member.id))
        }
    }

    @Test
    fun eachHistoricalSignatureIsRequiredAndReflectionFails() {
        val valid = journal()
        val invalidProof = GroupAdmissionProof(anchor, listOf(proof.admissions.first(),
            proof.admissions.last().copy(signature = founder.sign(byteArrayOf(1)))))
        val cases = listOf(
            journal(proof = invalidProof) to GroupRootAdoptionJournalInspectionResult.InvalidChain(GroupAdmissionChainResult.InvalidSignature(1)),
            journal(localSignature = valid.remoteConfirmation.signature) to GroupRootAdoptionJournalInspectionResult.InvalidLocalConfirmation,
            journal(remoteSignature = valid.localConfirmation.signature) to GroupRootAdoptionJournalInspectionResult.InvalidRemoteConfirmation,
        )
        for ((journal, expected) in cases) {
            assertEquals(expected, GroupRootAdoptionJournalInspector.inspect(record(journal), member.id))
        }
    }

    @Test
    fun syntacticallyValidOfferTamperingInvalidatesTheOriginalApproval() {
        for (offer in listOf(
            ProtocolHandshakeParticipant(member.id, randomNonce(), capabilities),
            ProtocolHandshakeParticipant(member.id, local.nonce, ProtocolCapabilities(1, setOf("text", "receipts"))),
        )) {
            assertEquals(GroupRootAdoptionJournalInspectionResult.InvalidLocalConfirmation,
                GroupRootAdoptionJournalInspector.inspect(record(journal(localOffer = offer)), member.id))
        }
    }

    @Test
    fun memberAndEveryIssuerUseTheSameExactDerBoundary() {
        for (identity in listOf(founder, issuer, member)) {
            for (der in listOf(byteArrayOf(0), founder.certificate.encoded + byteArrayOf(0),
                identity.certificate.encoded + identity.certificate.encoded,
                (if (identity === member) issuer else member).certificate.encoded)) {
                val replacement = GroupAdmissionCertificate(identity.id, Base64.getEncoder().encodeToString(der))
                val evidence = GroupAdmissionEvidence(proof, listOf(founder, issuer).map {
                    if (it === identity) replacement else certificate(it)
                })
                val journal = journal(evidence = evidence, memberCertificate = if (identity === member) replacement else certificate(member))
                assertFailsWith<InvalidGroupAdmissionCertificateException> {
                    GroupRootAdoptionJournalInspector.inspect(record(journal), member.id)
                }
            }
        }
    }

    @Test
    fun expiredFutureWrongCurveAndNonSelfSignedCertificatesCannotPassAtAnyRole() {
        val now = System.currentTimeMillis()
        val invalid = listOf(
            identity(notBefore = now - 120_000, notAfter = now - 60_000),
            identity(notBefore = now + 60_000, notAfter = now + 120_000),
            identity(keys = keys("secp384r1")),
            identity(signer = keys()),
        )
        for (identity in invalid) {
            val invalidFounder = signedRecord(identity, issuer, member)
            assertEquals(GroupRootAdoptionJournalInspectionResult.InvalidChain(GroupAdmissionChainResult.InvalidSignature(0)),
                GroupRootAdoptionJournalInspector.inspect(invalidFounder, member.id))
            val invalidIssuer = signedRecord(founder, identity, member)
            assertEquals(GroupRootAdoptionJournalInspectionResult.InvalidChain(GroupAdmissionChainResult.InvalidSignature(1)),
                GroupRootAdoptionJournalInspector.inspect(invalidIssuer, member.id))
            val invalidMember = signedRecord(founder, issuer, identity)
            assertEquals(GroupRootAdoptionJournalInspectionResult.InvalidLocalConfirmation,
                GroupRootAdoptionJournalInspector.inspect(invalidMember, identity.id))
        }
    }

    @Test
    fun failedInspectionSurvivesReopenAndSuccessfulInspectionDoesNotOverrideAnExistingGroup() {
        val directory = Files.createTempDirectory("lantern-journal-inspection-")
        val path = directory.resolve("member.db")
        try {
            val invalidRecords = listOf(
                record(journal(remoteSignature = member.sign(byteArrayOf(1)))),
                record(journal(memberCertificate = GroupAdmissionCertificate(member.id, "AA=="))),
            )
            for (record in invalidRecords) {
                openDesktopRepository(path).use { assertTrue(it.stageGroupAdoption(record, member.id)) }
                openDesktopRepository(path).use { store ->
                    val snapshot = assertNotNull(store.pendingGroupAdoption())
                    if (record === invalidRecords.first()) {
                        assertEquals(GroupRootAdoptionJournalInspectionResult.InvalidRemoteConfirmation,
                            GroupRootAdoptionJournalInspector.inspect(snapshot, member.id))
                    } else {
                        assertFailsWith<InvalidGroupAdmissionCertificateException> {
                            GroupRootAdoptionJournalInspector.inspect(snapshot, member.id)
                        }
                    }
                    assertTrue(record.sameRecord(assertNotNull(store.pendingGroupAdoption())))
                    assertNull(store.localGroup())
                    assertTrue(store.trusted().isEmpty())
                    assertTrue(store.history().isEmpty())
                }
                openDesktopRepository(path).use { store ->
                    assertTrue(record.sameRecord(assertNotNull(store.pendingGroupAdoption())))
                    // Explicit test cleanup, never automatic inspection cleanup.
                    assertTrue(store.removeGroupAdoption(record))
                }
            }
            val valid = record(journal())
            val durable = GroupTrustAnchor(randomNonce(), member.id)
            openDesktopRepository(path).use {
                assertTrue(it.stageGroupAdoption(valid, member.id))
                assertTrue(it.foundLocalGroup(durable, member.id))
            }
            openDesktopRepository(path).use { store ->
                assertEquals(GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid,
                    GroupRootAdoptionJournalInspector.inspect(assertNotNull(store.pendingGroupAdoption()), member.id))
                assertEquals(durable, store.localGroup())
                assertTrue(valid.sameRecord(assertNotNull(store.pendingGroupAdoption())))
                assertTrue(store.trusted().isEmpty())
                assertTrue(store.history().isEmpty())
            }
        } finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    private fun journal(
        proof: GroupAdmissionProof = this.proof,
        evidence: GroupAdmissionEvidence = GroupAdmissionEvidence(proof, listOf(certificate(founder), certificate(issuer))),
        memberCertificate: GroupAdmissionCertificate = certificate(member),
        localOffer: ProtocolHandshakeParticipant = local,
        localSignature: String? = null,
        remoteSignature: String? = null,
    ): GroupRootAdoptionJournal {
        // Sign the ORIGINAL context: alterations must not receive fresh approvals accidentally.
        val original = GroupAdmissionConfirmationContext(remote, local, anchor, this.proof)
        return GroupRootAdoptionJournal(evidence, localOffer, remote, memberCertificate,
            GroupAdmissionConfirmation(member.id, issuer.id, localSignature ?: member.sign(original.approvalBytes(member.id))),
            GroupAdmissionConfirmation(issuer.id, member.id, remoteSignature ?: issuer.sign(original.approvalBytes(issuer.id))))
    }

    private fun record(journal: GroupRootAdoptionJournal) = PendingGroupAdoption(randomNonce(), member.id, issuer.id,
        anchor, GroupRootAdoptionJournalCodec.encode(journal))

    private fun certificate(identity: Identity) = GroupAdmissionCertificate(identity.id,
        Base64.getEncoder().encodeToString(identity.certificate.encoded))

    private fun admission(issuer: Identity, member: Identity): SignedGroupAdmission {
        val claim = GroupAdmissionClaim(anchor.groupId, issuer.id, member.id)
        return SignedGroupAdmission(claim, issuer.sign(GroupAdmissionCodec.signedBytes(claim)))
    }

    private fun signedRecord(founder: Identity, issuer: Identity, member: Identity): PendingGroupAdoption {
        val anchor = GroupTrustAnchor(randomNonce(), founder.id)
        val path = listOf(founder to issuer, issuer to member).map { (from, to) ->
            val claim = GroupAdmissionClaim(anchor.groupId, from.id, to.id)
            SignedGroupAdmission(claim, from.sign(GroupAdmissionCodec.signedBytes(claim)))
        }
        val proof = GroupAdmissionProof(anchor, path)
        val local = ProtocolHandshakeParticipant(member.id, randomNonce(), capabilities)
        val remote = ProtocolHandshakeParticipant(issuer.id, randomNonce(), capabilities)
        val context = GroupAdmissionConfirmationContext(remote, local, anchor, proof)
        val journal = GroupRootAdoptionJournal(GroupAdmissionEvidence(proof, listOf(certificate(founder), certificate(issuer))),
            local, remote, certificate(member),
            GroupAdmissionConfirmation(member.id, issuer.id, member.sign(context.approvalBytes(member.id))),
            GroupAdmissionConfirmation(issuer.id, member.id, issuer.sign(context.approvalBytes(issuer.id))))
        return PendingGroupAdoption(randomNonce(), member.id, issuer.id, anchor, GroupRootAdoptionJournalCodec.encode(journal))
    }

    private fun keys(curve: String = "secp256r1"): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec(curve))
        generateKeyPair()
    }

    private fun identity(
        keys: KeyPair = keys(),
        notBefore: Long = System.currentTimeMillis() - 60_000,
        notAfter: Long = System.currentTimeMillis() + 120_000,
        signer: KeyPair = keys,
    ): Identity {
        val name = X500Name("CN=Lantern journal inspection test")
        val certificate = JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(name, BigInteger(128, SecureRandom()), Date(notBefore), Date(notAfter), name, keys.public)
                .build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private)))
        return Identity(certificate, keys.private)
    }
}
