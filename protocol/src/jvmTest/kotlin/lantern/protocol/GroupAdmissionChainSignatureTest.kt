package lantern.protocol

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor

/** Real ephemeral P-256 signatures. Fixture IDs are not certificates or a production resolver. */
class GroupAdmissionChainSignatureTest {
    private val group = "a".repeat(64)
    private val founder = "b".repeat(64)
    private val delegate = "c".repeat(64)
    private val member = "d".repeat(64)
    private val anchor = GroupTrustAnchor(group, founder)
    private val founderKey = keyPair()
    private val delegateKey = keyPair()
    private val keys = mapOf(founder to founderKey, delegate to delegateKey)

    @Test
    fun delegatedProofSurvivesCodecRoundTripButFailsWithEitherWrongIssuerKey() {
        val proof = proof().map { SignedGroupAdmissionCodec.decode(SignedGroupAdmissionCodec.encode(it)) }
        assertEquals(GroupAdmissionChainResult.VerifiedChain, verify(proof, keys))
        assertEquals(GroupAdmissionChainResult.InvalidSignature(0),
            verify(proof, keys + (founder to delegateKey)))
        assertEquals(GroupAdmissionChainResult.InvalidSignature(1),
            verify(proof, keys + (delegate to founderKey)))
        assertEquals(GroupAdmissionChainResult.InvalidSignature(1), verify(proof, keys - delegate))
    }

    @Test
    fun substitutedGroupOrTargetCannotReuseTheSignaturesWithAnAlternativeContext() {
        val proof = proof()
        val other = "e".repeat(64)
        val changedTarget = proof.dropLast(1) + proof.last().copy(
            claim = proof.last().claim.copy(memberId = other),
        )
        assertEquals(GroupAdmissionChainResult.InvalidSignature(1), verify(changedTarget, keys, target = other))
        val changedGroup = proof.map { it.copy(claim = it.claim.copy(groupId = other)) }
        assertEquals(GroupAdmissionChainResult.InvalidSignature(0),
            verify(changedGroup, keys, root = GroupTrustAnchor(other, founder)))
    }

    private fun proof() = listOf(
        sign(GroupAdmissionClaim(group, founder, delegate), founderKey),
        sign(GroupAdmissionClaim(group, delegate, member), delegateKey),
    )

    private fun verify(
        proof: List<SignedGroupAdmission>,
        resolver: Map<String, KeyPair>,
        root: GroupTrustAnchor = anchor,
        target: String = member,
    ) = GroupAdmissionChainVerification.verify(root, target, proof) { issuer, bytes, signature ->
        val key = resolver[issuer]
        key != null && Signature.getInstance("SHA256withECDSA").run {
            initVerify(key.public)
            update(bytes)
            verify(Base64.getDecoder().decode(signature))
        }
    }

    private fun sign(claim: GroupAdmissionClaim, key: KeyPair): SignedGroupAdmission {
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private)
            update(GroupAdmissionCodec.signedBytes(claim))
            sign()
        }
        return SignedGroupAdmission(claim, Base64.getEncoder().encodeToString(signature))
    }

    private fun keyPair() = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }
}
