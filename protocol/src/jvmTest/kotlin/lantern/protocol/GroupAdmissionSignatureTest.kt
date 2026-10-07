package lantern.protocol

import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import lantern.domain.GroupAdmissionClaim

/** Real JCA P-256 byte-binding tests, not issuer membership/TLS/Keychain verification. */
class GroupAdmissionSignatureTest {
    private val claim = GroupAdmissionClaim("c".repeat(64), "a".repeat(64), "b".repeat(64))

    @Test
    fun digestMatchesIndependentDotNetVector() {
        val digest = MessageDigest.getInstance("SHA-256").digest(GroupAdmissionCodec.signedBytes(claim))
        assertEquals(
            "3e3fcddb32360c5166a63cdfc093b17ab6043a7acf51755bae7e7ce40cb43029",
            digest.joinToString("") { "%02x".format(it) },
        )
    }

    @Test
    fun realSignatureBindsEveryIdDirectionVersionDomainAndCanonicalEncoding() {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val issuerKey = generator.generateKeyPair()
        val otherKey = generator.generateKeyPair()
        val bytes = GroupAdmissionCodec.signedBytes(claim)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(issuerKey.private)
            update(bytes)
            sign()
        }
        fun verifies(payload: ByteArray, key: PublicKey = issuerKey.public): Boolean =
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(payload)
                verify(signature)
            }
        assertTrue(verifies(bytes))
        val envelope = SignedGroupAdmission(claim, Base64.getEncoder().encodeToString(signature))
        val roundTrip = SignedGroupAdmissionCodec.decode(SignedGroupAdmissionCodec.encode(envelope))
        assertEquals(envelope, roundTrip)
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(issuerKey.public)
            update(GroupAdmissionCodec.signedBytes(roundTrip.claim))
            verify(Base64.getDecoder().decode(roundTrip.signature))
        })
        assertFalse(verifies(bytes, otherKey.public))
        for (changed in listOf(
            claim.copy(groupId = "d".repeat(64)),
            claim.copy(issuerId = "d".repeat(64)),
            claim.copy(memberId = "d".repeat(64)),
            claim.copy(issuerId = claim.memberId, memberId = claim.issuerId),
        )) {
            assertFalse(verifies(GroupAdmissionCodec.signedBytes(changed)))
        }
        assertFalse(verifies(bytes.decodeToString().replace("admission-1", "admission-2").encodeToByteArray()))
        assertFalse(verifies(bytes.decodeToString().replace("1:1", "1:2").encodeToByteArray()))
        assertFalse(verifies(GroupAdmissionCodec.encode(claim)))
        assertFalse(verifies(Wire.signedBytes(PairingWire.approval(claim.issuerId, claim.memberId, claim.groupId))))

        val capabilities = ProtocolCapabilities(1, setOf("text"), setOf("text"))
        val issuer = ProtocolHandshakeParticipant(claim.issuerId, "1".repeat(64), capabilities)
        val member = ProtocolHandshakeParticipant(claim.memberId, "2".repeat(64), capabilities)
        assertFalse(verifies(ProtocolHandshakeTranscript.bytes(issuer, member)))
        assertFalse(verifies(ProtocolHandshakeTranscript.approvalBytes(issuer, member)))

        val reordered = """ { "member": "${claim.memberId}", "issuer": "${claim.issuerId}", "group": "${claim.groupId}", "version": 1 } """
        val decoded = GroupAdmissionCodec.decode(reordered.encodeToByteArray())
        assertTrue(verifies(GroupAdmissionCodec.signedBytes(decoded)))
        assertFalse(verifies(reordered.encodeToByteArray()))
    }

    @Test
    fun sharedVerifierChecksRealP256ProofWithoutClaimingGroupAuthorization() {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val issuerKey = generator.generateKeyPair()
        val otherKey = generator.generateKeyPair()
        val proof = Base64.getEncoder().encodeToString(Signature.getInstance("SHA256withECDSA").run {
            initSign(issuerKey.private)
            update(GroupAdmissionCodec.signedBytes(claim))
            sign()
        })
        fun verify(value: GroupAdmissionClaim = claim, key: PublicKey = issuerKey.public) =
            GroupAdmissionSignatureVerification.verify(
                SignedGroupAdmission(value, proof), value.groupId, value.issuerId, value.memberId, value.issuerId,
            ) { bytes, encoded ->
                Signature.getInstance("SHA256withECDSA").run {
                    initVerify(key)
                    update(bytes)
                    verify(Base64.getDecoder().decode(encoded))
                }
            }
        assertEquals(GroupAdmissionSignatureResult.VerifiedSignature, verify())
        assertEquals(GroupAdmissionSignatureResult.InvalidSignature, verify(key = otherKey.public))
        for (changed in listOf(
            claim.copy(groupId = "d".repeat(64)),
            claim.copy(issuerId = "d".repeat(64)),
            claim.copy(memberId = "d".repeat(64)),
            claim.copy(issuerId = claim.memberId, memberId = claim.issuerId),
        )) {
            assertEquals(GroupAdmissionSignatureResult.InvalidSignature, verify(changed))
        }
        // Test IDs are explicit fixtures. This does not attest a certificate-to-key adapter,
        // a group anchor, user confirmation, admission completion or persistent trust.
    }
}
