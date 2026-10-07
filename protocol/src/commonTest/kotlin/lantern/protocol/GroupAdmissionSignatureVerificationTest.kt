package lantern.protocol

import kotlinx.coroutines.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import lantern.domain.GroupAdmissionBinding
import lantern.domain.GroupAdmissionClaim

/** Substitute OS verifier tests ordering/binding/errors only; real P-256 tests live in jvmTest. */
class GroupAdmissionSignatureVerificationTest {
    private val group = "c".repeat(64)
    private val issuer = "a".repeat(64)
    private val member = "b".repeat(64)
    private val other = "d".repeat(64)
    private val admission = SignedGroupAdmission(GroupAdmissionClaim(group, issuer, member), "cHJvb2Y=")

    @Test
    fun onlyMatchedContextAndSignerReachTheVerifierWithCanonicalBytes() {
        var calls = 0
        val result = verify { bytes, encoded ->
            calls++
            assertContentEquals(GroupAdmissionCodec.signedBytes(admission.claim), bytes)
            assertEquals(admission.signature, encoded)
            true
        }
        assertEquals(1, calls)
        assertEquals(GroupAdmissionSignatureResult.VerifiedSignature, result)
    }

    @Test
    fun contextSubstitutionFailsBeforeCallingTheOsVerifier() {
        val cases = listOf(
            Triple(other, issuer, member) to GroupAdmissionBinding.GROUP_MISMATCH,
            Triple(group, other, member) to GroupAdmissionBinding.ISSUER_MISMATCH,
            Triple(group, issuer, other) to GroupAdmissionBinding.MEMBER_MISMATCH,
        )
        for ((context, expected) in cases) {
            val result = GroupAdmissionSignatureVerification.verify(
                admission, context.first, context.second, context.third, issuer,
            ) { _, _ -> error("Mismatched context must not reach the OS verifier") }
            assertEquals(GroupAdmissionSignatureResult.ContextMismatch(expected), result)
        }
    }

    @Test
    fun substitutedOrMalformedCertificateIdentityFailsBeforeSignatureVerification() {
        for (signer in listOf(other, member, "", "issuer", issuer.uppercase())) {
            val result = GroupAdmissionSignatureVerification.verify(admission, group, issuer, member, signer) { _, _ ->
                error("Unbound signer must not reach the OS verifier")
            }
            assertEquals(GroupAdmissionSignatureResult.SignerIdentityMismatch, result)
        }
    }

    @Test
    fun invalidSignatureAndOsFailureNeverBecomeVerifiedSignature() {
        assertEquals(GroupAdmissionSignatureResult.InvalidSignature, verify { _, _ -> false })
        val failure = IllegalStateException("Test OS verifier failure")
        val thrown = assertFailsWith<IllegalStateException> { verify { _, _ -> throw failure } }
        assertSame(failure, thrown)
        val cancelled = CancellationException("Test verifier cancellation")
        val propagated = assertFailsWith<CancellationException> { verify { _, _ -> throw cancelled } }
        assertSame(cancelled, propagated)
    }

    @Test
    fun malformedOrSelfAdmissionContextIsRejectedBeforeTheVerifier() {
        val contexts = listOf(
            Triple("group", issuer, member), Triple(group, "issuer", member),
            Triple(group, issuer, "member"), Triple(group, issuer, issuer),
        )
        for ((groupId, issuerId, memberId) in contexts) {
            assertFailsWith<IllegalArgumentException> {
                GroupAdmissionSignatureVerification.verify(admission, groupId, issuerId, memberId, issuer) { _, _ ->
                    error("Invalid context must not reach the OS verifier")
                }
            }
        }
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionSignatureResult.ContextMismatch(GroupAdmissionBinding.MATCHED)
        }
    }

    private fun verify(verifier: (ByteArray, String) -> Boolean) = GroupAdmissionSignatureVerification.verify(
        admission, group, issuer, member, issuer, verifier,
    )
}
