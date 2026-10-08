package lantern.protocol

import kotlinx.coroutines.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor

/** Pure binding/ordering tests; not OS crypto, UI confirmation or cancellation of an owner. */
class GroupAdmissionConfirmationTest {
    private val group = "a".repeat(64)
    private val issuer = "b".repeat(64)
    private val member = "c".repeat(64)
    private val other = "d".repeat(64)
    private val caps = ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text", "receipts"))
    private val issuerOffer = ProtocolHandshakeParticipant(issuer, "e".repeat(64), caps)
    private val memberOffer = ProtocolHandshakeParticipant(member, "f".repeat(64), caps)
    private val anchor = GroupTrustAnchor(group, issuer)
    private val admission = SignedGroupAdmission(GroupAdmissionClaim(group, issuer, member), "cHJvb2Y=")
    private val proof = GroupAdmissionProof(anchor, listOf(admission))
    private val context = GroupAdmissionConfirmationContext(issuerOffer, memberOffer, anchor, proof)

    @Test
    fun comparisonBindsCanonicalProofAndCompleteBootstrapWithSeparateDomain() {
        val fields = listOf("lantern-group-admission-confirm-1", issuer, member,
            ProtocolHandshakeTranscript.bytes(issuerOffer, memberOffer).decodeToString(),
            GroupAdmissionProofCodec.encode(proof).decodeToString())
        val expected = fields.joinToString("") { "${it.encodeToByteArray().size}:$it" }.encodeToByteArray()
        assertContentEquals(expected, context.comparisonBytes())
        assertFalse(context.comparisonBytes().contentEquals(ProtocolHandshakeTranscript.bytes(issuerOffer, memberOffer)))
        assertFalse(context.approvalBytes(issuer).contentEquals(context.approvalBytes(member)))
        assertFalse(context.approvalBytes(issuer).contentEquals(ProtocolHandshakeTranscript.approvalBytes(issuerOffer, memberOffer)))
    }

    @Test
    fun changedNonceProofSignatureOrPathChangesConfirmationBytes() {
        val differentNonce = GroupAdmissionConfirmationContext(
            ProtocolHandshakeParticipant(issuer, other, caps), memberOffer, anchor, proof)
        val differentSignature = GroupAdmissionConfirmationContext(issuerOffer, memberOffer, anchor,
            GroupAdmissionProof(anchor, listOf(admission.copy(signature = "b3RoZXI="))))
        val differentPath = GroupAdmissionConfirmationContext(issuerOffer, memberOffer, anchor,
            GroupAdmissionProof(anchor, listOf(admission, admission)))
        val differentCapabilities = GroupAdmissionConfirmationContext(
            ProtocolHandshakeParticipant(issuer, issuerOffer.nonce,
                ProtocolCapabilities(1, caps.supportedFeatures + "files", caps.requiredFeatures)), memberOffer, anchor, proof)
        for (changed in listOf(differentNonce, differentSignature, differentPath, differentCapabilities)) {
            assertFalse(context.comparisonBytes().contentEquals(changed.comparisonBytes()))
            assertFalse(context.approvalBytes(issuer).contentEquals(changed.approvalBytes(issuer)))
        }
    }

    @Test
    fun equivalentReceivedJsonNormalizesWithoutChangingTheConfirmation() {
        val json = GroupAdmissionProofCodec.encode(proof).decodeToString()
        val normalized = GroupAdmissionProofCodec.decode((" \n" + json.replace("\"version\"", "\"ver\\u0073ion\"") + " ").encodeToByteArray())
        val equivalent = GroupAdmissionConfirmationContext(issuerOffer, memberOffer, anchor, normalized)
        assertContentEquals(context.comparisonBytes(), equivalent.comparisonBytes())
        val view = context.comparisonBytes()
        view.fill(0)
        assertContentEquals(equivalent.comparisonBytes(), context.comparisonBytes())
        val approval = context.approvalBytes(issuer)
        approval.fill(0)
        assertContentEquals(equivalent.approvalBytes(issuer), context.approvalBytes(issuer))
    }

    @Test
    fun contextRejectsSubstitutedAnchorParticipantsAndIncompatibleOffers() {
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionConfirmationContext(issuerOffer, memberOffer, GroupTrustAnchor(other, issuer), proof)
        }
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionConfirmationContext(memberOffer, issuerOffer, anchor, proof)
        }
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionConfirmationContext(issuerOffer, issuerOffer, anchor, proof)
        }
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionConfirmationContext(issuerOffer,
                ProtocolHandshakeParticipant(member, other, ProtocolCapabilities(2, emptySet(), emptySet())), anchor, proof)
        }
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionConfirmationContext(issuerOffer,
                ProtocolHandshakeParticipant(member, other, ProtocolCapabilities(1, setOf("text"))), anchor, proof)
        }
        assertFailsWith<IllegalArgumentException> { context.approvalBytes(other) }
    }

    @Test
    fun onlyExpectedDirectionAndTlsIdentityReachCryptoForEitherParticipant() {
        for ((local, remote) in listOf(issuer to member, member to issuer)) {
            var calls = 0
            assertEquals(GroupAdmissionConfirmationResult.VerifiedRemoteConfirmation,
                verify(local, remote, remote, local) { bytes, signature ->
                    calls++
                    assertContentEquals(context.approvalBytes(remote), bytes)
                    assertEquals("cHJvb2Y=", signature)
                    true
                })
            assertEquals(1, calls)
            assertEquals(GroupAdmissionConfirmationResult.AddressMismatch,
                verify(local, remote, local, remote) { _, _ -> error("Reflected confirmation") })
            assertEquals(GroupAdmissionConfirmationResult.IdentityMismatch,
                verify(local, other, remote, local) { _, _ -> error("Wrong TLS certificate") })
        }
    }

    @Test
    fun invalidEncodingAndSignatureCannotBecomeConfirmed() {
        assertEquals(GroupAdmissionConfirmationResult.InvalidSignature,
            GroupAdmissionConfirmationVerification.verifyRemote(context, member, issuer, issuer, member, "bad") { _, _ ->
                error("Invalid encoding must fail before OS verifier")
            })
        assertEquals(GroupAdmissionConfirmationResult.InvalidSignature, verify(member, issuer, issuer, member) { _, _ -> false })
        assertFailsWith<IllegalArgumentException> { verify(other, issuer, issuer, other) { _, _ -> true } }
    }

    @Test
    fun unexpectedFailuresAndCancellationAreNotSilenced() {
        for (failure in listOf(IllegalStateException("Test OS failure"), CancellationException("Cancelled"))) {
            assertSame(failure, assertFailsWith<Exception> {
                verify(member, issuer, issuer, member) { _, _ -> throw failure }
            })
        }
    }

    private fun verify(local: String, tlsPeer: String, sender: String, recipient: String,
        callback: (ByteArray, String) -> Boolean) = GroupAdmissionConfirmationVerification.verifyRemote(
        context, local, tlsPeer, sender, recipient, "cHJvb2Y=", callback)
}
