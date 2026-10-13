package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Real P-256 signatures. IDs/offers/UI click/clock are explicit fixtures, not TLS/OS identity. */
class GroupRootAdoptionSignatureTest {
    private val founder = "a".repeat(64)
    private val member = "b".repeat(64)
    private val caps = ProtocolCapabilities(1, setOf("text", "receipts"))
    private val issuerOffer = ProtocolHandshakeParticipant(founder, "e".repeat(64), caps)
    private val memberOffer = ProtocolHandshakeParticipant(member, "f".repeat(64), caps)
    private val issuerKey = key()
    private val memberKey = key()
    private val anchor = GroupTrustAnchor("c".repeat(64), founder)
    private val claim = GroupAdmissionClaim(anchor.groupId, founder, member)
    private val proof = GroupAdmissionProof(anchor, listOf(
        SignedGroupAdmission(claim, sign(issuerKey, GroupAdmissionCodec.signedBytes(claim))),
    ))
    private val repository = object : LocalGroupRepository {
        override fun localGroup(): GroupTrustAnchor? = null
        override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean = error("No writes")
    }

    @Test
    fun validButDifferentCandidateCannotUseTheOriginalRootConfirmation() {
        val originalContext = context(proof, memberOffer)
        val changedAnchor = GroupTrustAnchor("d".repeat(64), founder)
        val changedClaim = claim.copy(groupId = changedAnchor.groupId)
        val changedProof = GroupAdmissionProof(changedAnchor, listOf(
            SignedGroupAdmission(changedClaim, sign(issuerKey, GroupAdmissionCodec.signedBytes(changedClaim))),
        ))
        val candidate = owner(changedProof)
        assertTrue(candidate.prepare(member, repository)) // A genuine signature is not root consent.
        assertNotEquals(hash(originalContext.comparisonBytes()), hash(assertNotNull(candidate.comparison()).bytes))
        completeLocal(candidate)
        assertFalse(candidate.receive(founder, member, sign(issuerKey, originalContext.approvalBytes(founder))))
        assertNull(candidate.releaseForCommit(member, repository))
    }

    @Test
    fun aNewConnectionWithTheSameProofCannotReplayTheOldConfirmation() {
        val oldContext = context(proof, memberOffer)
        val freshMember = ProtocolHandshakeParticipant(member, "d".repeat(64), caps)
        val candidate = owner(proof, freshMember)
        assertTrue(candidate.prepare(member, repository))
        completeLocal(candidate)
        assertFalse(candidate.receive(founder, member, sign(issuerKey, oldContext.approvalBytes(founder))))
        assertNull(candidate.releaseForCommit(member, repository))
    }

    @Test
    fun wrongKeyAndBootstrapOrAdmissionSignaturesAreNotRootConfirmation() {
        val expected = context(proof, memberOffer)
        val invalid = listOf(
            sign(memberKey, expected.approvalBytes(founder)),
            sign(issuerKey, ProtocolHandshakeTranscript.approvalBytes(issuerOffer, memberOffer)),
            proof.admissions.single().signature,
        )
        for (signature in invalid) {
            val candidate = owner(proof)
            assertTrue(candidate.prepare(member, repository))
            completeLocal(candidate)
            assertFalse(candidate.receive(founder, member, signature))
            assertNull(candidate.releaseForCommit(member, repository))
        }
    }

    @Test
    fun validCandidateAndBothDirectionalSignaturesCanReleaseButNeverWrite() {
        val candidate = owner(proof)
        assertTrue(candidate.prepare(member, repository))
        val expected = context(proof, memberOffer)
        assertTrue(candidate.receive(founder, member, sign(issuerKey, expected.approvalBytes(founder))))
        assertNull(candidate.releaseForCommit(member, repository))
        completeLocal(candidate)
        val draft = assertNotNull(candidate.releaseForCommit(member, repository))
        val receipt = draft.confirmations
        assertContentEquals(expected.comparisonBytes(), receipt.comparisonBytes())
        // Existing wire codecs preserve the exact attestations for a future local journal.
        val local = GroupAdmissionConfirmationCodec.decode(GroupAdmissionConfirmationCodec.encode(receipt.local))
        val remote = GroupAdmissionConfirmationCodec.decode(GroupAdmissionConfirmationCodec.encode(receipt.remote))
        assertEquals(member, local.sender)
        assertEquals(founder, remote.sender)
        assertTrue(verify(memberKey, expected.approvalBytes(member), local.signature))
        assertTrue(verify(issuerKey, expected.approvalBytes(founder), remote.signature))
        assertFalse(verify(memberKey, expected.approvalBytes(founder), local.signature))
        assertFalse(verify(issuerKey, expected.approvalBytes(member), remote.signature))
        assertNull(candidate.releaseForCommit(member, repository))
        assertNull(repository.localGroup())
    }

    private fun owner(proof: GroupAdmissionProof, memberOffer: ProtocolHandshakeParticipant = this.memberOffer) =
        GroupRootAdoptionAttempt(ProtocolHandshakeOffers(memberOffer, issuerOffer, 200), member,
            founder, founder, proof, 100, { 200 },
            { issuer, bytes, signature -> issuer == founder && verify(issuerKey, bytes, signature) },
            { bytes, signature -> verify(issuerKey, bytes, signature) })

    private fun completeLocal(candidate: GroupRootAdoptionAttempt) {
        val request = assertNotNull(candidate.confirm(assertNotNull(candidate.comparison())))
        val signature = sign(memberKey, request.bytes)
        assertTrue(verify(memberKey, request.bytes, signature))
        val sending = assertNotNull(candidate.signed(request, signature))
        assertTrue(candidate.sent(sending)) // Successful write callback is a fixture in this test.
    }

    private fun context(proof: GroupAdmissionProof, memberOffer: ProtocolHandshakeParticipant) =
        GroupAdmissionConfirmationContext(issuerOffer, memberOffer, proof.anchor, proof)
    private fun hash(bytes: ByteArray) = java.security.MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
    private fun key() = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }
    private fun sign(key: KeyPair, bytes: ByteArray): String = Base64.getEncoder().encodeToString(
        Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private)
            update(bytes)
            sign()
        })
    private fun verify(key: KeyPair, bytes: ByteArray, signature: String) =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(key.public)
            update(bytes)
            verify(Base64.getDecoder().decode(signature))
        }
}
