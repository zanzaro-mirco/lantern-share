package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ProtocolHandshakeVerificationTest {
    private val local = participant("a", "1", setOf("text", "receipts"), setOf("text"))
    private val remote = participant("b", "2", setOf("text", "receipts", "future"), setOf("receipts"))
    private val proof = "cHJvb2Y=" // Encodes a test fixture, not a real ECDSA signature.

    @Test
    fun verifiedResultRequiresTlsIdentityCompatibilityAndDirectionalProof() {
        var calls = 0
        val result = ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, proof) { bytes, signature ->
            calls++
            assertContentEquals(ProtocolHandshakeTranscript.approvalBytes(remote, local), bytes)
            assertEquals(proof, signature)
            true // Verifier simulation confined to this pure contract test.
        }
        assertEquals(1, calls)
        assertEquals(
            ProtocolHandshakeVerificationResult.Verified(ProtocolNegotiationResult.Compatible(1, setOf("receipts", "text"))),
            result,
        )
    }

    @Test
    fun identityMismatchDoesNotReachSignatureVerifier() {
        for (identity in listOf(local.identity, "c".repeat(64), "", "invalid")) {
            val result = verifyWithoutSignatureCheck(local, remote, identity)
            assertEquals(ProtocolHandshakeVerificationResult.IdentityMismatch, result)
        }
        assertEquals(ProtocolHandshakeVerificationResult.IdentityMismatch, verifyWithoutSignatureCheck(local, local, local.identity))
    }

    @Test
    fun incompatibilityDoesNotReachSignatureVerifierOrFallBackToV0() {
        val future = participant("b", "2", setOf("text"), version = 2)
        assertEquals(
            ProtocolHandshakeVerificationResult.Incompatible(ProtocolIncompatibility.UNSUPPORTED_VERSION),
            verifyWithoutSignatureCheck(local, future, future.identity),
        )
        assertEquals(
            ProtocolHandshakeVerificationResult.Incompatible(ProtocolIncompatibility.UNSUPPORTED_VERSION),
            verifyWithoutSignatureCheck(participant("a", "1", setOf("text"), version = 2), future, future.identity),
        )
        val missingLocalRequirement = participant("b", "2", setOf("receipts"))
        val missingRemoteRequirement = participant("b", "2", setOf("text", "future"), setOf("future"))
        for (offer in listOf(missingLocalRequirement, missingRemoteRequirement)) {
            assertEquals(
                ProtocolHandshakeVerificationResult.Incompatible(ProtocolIncompatibility.REQUIRED_FEATURE_MISSING),
                verifyWithoutSignatureCheck(local, offer, offer.identity),
            )
        }
    }

    @Test
    fun invalidSignatureCannotProduceVerifiedCapabilities() {
        for (signature in listOf("", " ", "x".repeat(257), "not-base64", "AB==", "AAB=")) {
            assertEquals(
                ProtocolHandshakeVerificationResult.InvalidSignature,
                ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, signature) { _, _ ->
                    error("Malformed signature reached verifier")
                },
            )
        }
        var calls = 0
        assertEquals(
            ProtocolHandshakeVerificationResult.InvalidSignature,
            ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, "aW52YWxpZA==") { _, _ ->
                calls++
                false
            },
        )
        assertEquals(1, calls)
    }

    @Test
    fun verificationHasNoCachedSuccessAndPropagatesAdapterFailure() {
        assertEquals(
            ProtocolHandshakeVerificationResult.Verified(ProtocolNegotiationResult.Compatible(1, setOf("receipts", "text"))),
            ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, proof) { _, _ -> true },
        )
        assertEquals(
            ProtocolHandshakeVerificationResult.InvalidSignature,
            ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, proof) { _, _ -> false },
        )
        assertFailsWith<IllegalStateException> {
            ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, proof) { _, _ ->
                error("Adapter failed")
            }
        }
    }

    @Test
    fun decodedApprovalMustAddressThisConnectionBeforeSignatureVerification() {
        val approval = ProtocolHandshakeApproval(remote.identity, local.identity, proof)
        val decoded = ProtocolHandshakeApprovalCodec.decode(ProtocolHandshakeApprovalCodec.encode(approval))
        assertEquals(
            ProtocolHandshakeVerificationResult.Verified(ProtocolNegotiationResult.Compatible(1, setOf("receipts", "text"))),
            ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, decoded) { bytes, signature ->
                assertContentEquals(ProtocolHandshakeTranscript.approvalBytes(remote, local), bytes)
                assertEquals(proof, signature)
                true
            },
        )
        val changed = listOf(
            approval.copy(sender = "c".repeat(64)),
            approval.copy(recipient = "c".repeat(64)),
            ProtocolHandshakeApproval(local.identity, remote.identity, proof),
        )
        for (wrongAddress in changed) {
            assertEquals(
                ProtocolHandshakeVerificationResult.AddressMismatch,
                ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, wrongAddress) { _, _ ->
                    error("Wrongly addressed approval reached verifier")
                },
            )
        }
        assertEquals(
            ProtocolHandshakeVerificationResult.IdentityMismatch,
            ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, "c".repeat(64), decoded) { _, _ ->
                error("Unbound TLS identity reached verifier")
            },
        )
    }

    private fun verifyWithoutSignatureCheck(
        own: ProtocolHandshakeParticipant,
        peer: ProtocolHandshakeParticipant,
        authenticatedIdentity: String,
    ) = ProtocolHandshakeVerification.verifyRemoteApproval(own, peer, authenticatedIdentity, proof) { _, _ ->
        error("Rejected offer reached verifier")
    }

    private fun participant(
        identity: String,
        nonce: String,
        supported: Set<String>,
        required: Set<String> = emptySet(),
        version: Int = 1,
    ) = ProtocolHandshakeParticipant(identity.repeat(64), nonce.repeat(64), ProtocolCapabilities(version, supported, required))
}
