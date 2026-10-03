package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ProtocolHandshakeVerificationTest {
    private val local = participant("a", "1", setOf("text", "receipts"), setOf("text"))
    private val remote = participant("b", "2", setOf("text", "receipts", "future"), setOf("receipts"))

    @Test
    fun verifiedResultRequiresTlsIdentityCompatibilityAndDirectionalProof() {
        var calls = 0
        val result = ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, "proof") { bytes, signature ->
            calls++
            assertContentEquals(ProtocolHandshakeTranscript.approvalBytes(remote, local), bytes)
            assertEquals("proof", signature)
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
        for (signature in listOf("", " ", "x".repeat(257))) {
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
            ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, "invalid") { _, _ ->
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
            ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, "proof") { _, _ -> true },
        )
        assertEquals(
            ProtocolHandshakeVerificationResult.InvalidSignature,
            ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, "proof") { _, _ -> false },
        )
        assertFailsWith<IllegalStateException> {
            ProtocolHandshakeVerification.verifyRemoteApproval(local, remote, remote.identity, "proof") { _, _ ->
                error("Adapter failed")
            }
        }
    }

    private fun verifyWithoutSignatureCheck(
        own: ProtocolHandshakeParticipant,
        peer: ProtocolHandshakeParticipant,
        authenticatedIdentity: String,
    ) = ProtocolHandshakeVerification.verifyRemoteApproval(own, peer, authenticatedIdentity, "proof") { _, _ ->
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
