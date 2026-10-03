package lantern.protocol

import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Real JCA signatures exercise byte binding; this does not test TLS, trust, or OS key storage. */
class ProtocolHandshakeSignatureTest {
    @Test
    fun approvalSignatureCannotBeReflectedReplayedOrDowngraded() {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val senderKey = generator.generateKeyPair()
        val recipientKey = generator.generateKeyPair()
        val sender = participant("a", "1", setOf("text", "receipts"), setOf("text"))
        val recipient = participant("b", "2", setOf("text"))
        val signed = ProtocolHandshakeTranscript.approvalBytes(sender, recipient)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(senderKey.private)
            update(signed)
            sign()
        }
        fun verifies(bytes: ByteArray, key: java.security.PublicKey = senderKey.public): Boolean =
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(bytes)
                verify(signature)
            }
        assertTrue(verifies(signed))
        assertFalse(verifies(signed, recipientKey.public))
        assertFalse(verifies(ProtocolHandshakeTranscript.approvalBytes(recipient, sender)))
        assertFalse(verifies(ProtocolHandshakeTranscript.bytes(sender, recipient)))
        assertFalse(verifies(ProtocolHandshakeTranscript.approvalBytes(sender, participant("b", "3", setOf("text")))))
        assertFalse(verifies(ProtocolHandshakeTranscript.approvalBytes(participant("a", "1", setOf("text"), setOf("text")), recipient)))
        assertFalse(verifies(ProtocolHandshakeTranscript.approvalBytes(sender, participant("b", "2", setOf("text"), version = 2))))
        assertFalse(verifies(Wire.signedBytes(PairingWire.approval(sender.identity, recipient.identity, "c".repeat(64)))))
        val altered = signed.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        assertFalse(verifies(altered))
    }

    @Test
    fun comparisonDigestMatchesIndependentVector() {
        val sender = participant("a", "1", setOf("text", "receipts"), setOf("text"))
        val recipient = participant("b", "2", setOf("text"))
        val digest = MessageDigest.getInstance("SHA-256").digest(ProtocolHandshakeTranscript.bytes(sender, recipient))
        assertEquals(EXPECTED_SHA256, digest.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun verifierChecksRealRemoteSignatureAndRejectsChangedConnectionOrOffer() {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val local = participant("a", "1", setOf("text", "receipts"), setOf("text"))
        val remote = participant("b", "2", setOf("text", "receipts"))
        val signed = ProtocolHandshakeTranscript.approvalBytes(remote, local)
        val proof = Base64.getEncoder().encodeToString(Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private)
            update(signed)
            sign()
        })
        fun verify(own: ProtocolHandshakeParticipant, peer: ProtocolHandshakeParticipant, signature: String = proof) =
            ProtocolHandshakeVerification.verifyRemoteApproval(own, peer, peer.identity, signature) { bytes, encoded ->
                runCatching {
                    Signature.getInstance("SHA256withECDSA").run {
                        initVerify(key.public)
                        update(bytes)
                        verify(Base64.getDecoder().decode(encoded))
                    }
                }.getOrDefault(false)
            }
        assertEquals(
            ProtocolHandshakeVerificationResult.Verified(ProtocolNegotiationResult.Compatible(1, setOf("receipts", "text"))),
            verify(local, remote),
        )
        val nextLocal = participant("a", "3", setOf("text", "receipts"), setOf("text"))
        val nextRemote = participant("b", "4", setOf("text", "receipts"))
        val changedOffer = participant("b", "2", setOf("text", "receipts", "future"))
        assertEquals(ProtocolHandshakeVerificationResult.InvalidSignature, verify(nextLocal, remote))
        assertEquals(ProtocolHandshakeVerificationResult.InvalidSignature, verify(local, nextRemote))
        assertEquals(ProtocolHandshakeVerificationResult.InvalidSignature, verify(local, changedOffer))
        assertEquals(ProtocolHandshakeVerificationResult.InvalidSignature, verify(remote, local))
        assertEquals(ProtocolHandshakeVerificationResult.InvalidSignature, verify(local, remote, "not-base64"))
    }

    private fun participant(
        identity: String,
        nonce: String,
        supported: Set<String>,
        required: Set<String> = emptySet(),
        version: Int = 1,
    ) = ProtocolHandshakeParticipant(identity.repeat(64), nonce.repeat(64), ProtocolCapabilities(version, supported, required))

    private companion object {
        const val EXPECTED_SHA256 = "fb8a622679fac33a9fab0be883ad13c24ff8c5bd2be409fde23765c70022f87f"
    }
}
