package lantern.protocol

import kotlinx.coroutines.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor

/** Callback substitutes crypto only; actual P-256 chain coverage lives in jvmTest. */
class GroupAdmissionChainVerificationTest {
    private val group = "a".repeat(64)
    private val founder = "b".repeat(64)
    private val delegate = "c".repeat(64)
    private val member = "d".repeat(64)
    private val other = "e".repeat(64)
    private val anchor = GroupTrustAnchor(group, founder)
    private val path = listOf(admit(founder, delegate), admit(delegate, member))

    @Test
    fun directAndDelegatedPathsVerifyEveryCanonicalSignatureInOrder() {
        for (proof in listOf(listOf(admit(founder, member)), path)) {
            val issuers = mutableListOf<String>()
            assertEquals(GroupAdmissionChainResult.VerifiedChain, verify(proof) { issuer, bytes, signature ->
                val admission = proof[issuers.size]
                assertEquals(admission.claim.issuerId, issuer)
                assertContentEquals(GroupAdmissionCodec.signedBytes(admission.claim), bytes)
                assertEquals(admission.signature, signature)
                issuers.add(issuer)
                true
            })
            assertEquals(proof.map { it.claim.issuerId }, issuers)
        }
    }

    @Test
    fun disconnectedReorderedOrForeignGroupProofFailsBeforeCrypto() {
        val cases = listOf(
            listOf(admit(other, member)) to GroupAdmissionChainResult.BrokenChain,
            path.reversed() to GroupAdmissionChainResult.BrokenChain,
            listOf(path[0], admit(other, member)) to GroupAdmissionChainResult.BrokenChain,
            listOf(path[0], admit(delegate, member, other)) to GroupAdmissionChainResult.GroupMismatch,
            listOf(admit(founder, delegate)) to GroupAdmissionChainResult.MemberMismatch,
        )
        for ((proof, expected) in cases) assertEquals(expected, rejectWithoutCrypto(proof))
    }

    @Test
    fun cyclesCannotEstablishMembershipOrReauthorizeTheFounder() {
        val cases = listOf(
            listOf(admit(founder, delegate), admit(delegate, founder)),
            path + admit(member, delegate),
            path + admit(member, founder),
        )
        for (proof in cases) assertEquals(GroupAdmissionChainResult.RepeatedIdentity, rejectWithoutCrypto(proof))
        assertFailsWith<IllegalArgumentException> { admit(founder, founder) }
    }

    @Test
    fun anchorAndTargetAreNeverInferredFromTheProof() {
        assertEquals(GroupAdmissionChainResult.BrokenChain,
            GroupAdmissionChainVerification.verify(GroupTrustAnchor(group, other), member, path) { _, _, _ ->
                error("Foreign anchor must fail before crypto")
            })
        assertEquals(GroupAdmissionChainResult.MemberMismatch,
            GroupAdmissionChainVerification.verify(anchor, other, path) { _, _, _ ->
                error("Foreign target must fail before crypto")
            })
        assertEquals(GroupAdmissionChainResult.InvalidLength, rejectWithoutCrypto(emptyList()))
    }

    @Test
    fun exactBoundIsAcceptedAndOversizeRejectedWithoutCrypto() {
        val ids = (1..GroupAdmissionChainVerification.MAX_ADMISSIONS).map { it.toString(16).padStart(64, '0') }
        val proof = (listOf(founder) + ids).zipWithNext { issuer, recipient -> admit(issuer, recipient) }
        var calls = 0
        assertEquals(GroupAdmissionChainResult.VerifiedChain,
            GroupAdmissionChainVerification.verify(anchor, ids.last(), proof) { _, _, _ -> calls++; true })
        assertEquals(GroupAdmissionChainVerification.MAX_ADMISSIONS, calls)
        assertEquals(GroupAdmissionChainResult.InvalidLength, rejectWithoutCrypto(proof + admit(ids.last(), member)))
    }

    @Test
    fun invalidSignatureStopsWithoutReturningPartialMembership() {
        for (invalidIndex in path.indices) {
            var calls = 0
            assertEquals(GroupAdmissionChainResult.InvalidSignature(invalidIndex), verify(path) { _, _, _ ->
                calls++ != invalidIndex
            })
            assertEquals(invalidIndex + 1, calls)
        }
    }

    @Test
    fun callbackCannotReplaceTheBoundedSnapshot() {
        val supplied = path.toMutableList()
        var calls = 0
        assertEquals(GroupAdmissionChainResult.VerifiedChain, verify(supplied) { issuer, _, _ ->
            assertEquals(path[calls].claim.issuerId, issuer)
            supplied.clear()
            calls++
            true
        })
        assertEquals(2, calls)
    }

    @Test
    fun errorsAndCancellationPropagate() {
        for (failure in listOf(IllegalStateException("Test verifier failure"), CancellationException("Cancelled"))) {
            val thrown = assertFailsWith<Exception> { verify(path) { _, _, _ -> throw failure } }
            assertSame(failure, thrown)
        }
    }

    @Test
    fun invalidTrustedContextIsAProgrammingError() {
        assertFailsWith<IllegalArgumentException> { GroupTrustAnchor("", founder) }
        assertFailsWith<IllegalArgumentException> { GroupTrustAnchor(group, " ") }
        for ((root, target) in listOf(
            GroupTrustAnchor("group", founder) to member,
            GroupTrustAnchor(group, "founder") to member,
            anchor to "member",
        )) {
            assertFailsWith<IllegalArgumentException> {
                GroupAdmissionChainVerification.verify(root, target, path) { _, _, _ -> error("Invalid context") }
            }
        }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionChainResult.InvalidSignature(-1) }
    }

    private fun admit(issuer: String, recipient: String, groupId: String = group) =
        SignedGroupAdmission(GroupAdmissionClaim(groupId, issuer, recipient), "cHJvb2Y=")

    private fun verify(proof: List<SignedGroupAdmission>, callback: (String, ByteArray, String) -> Boolean) =
        GroupAdmissionChainVerification.verify(anchor, member, proof, callback)

    private fun rejectWithoutCrypto(proof: List<SignedGroupAdmission>) = verify(proof) { _, _, _ ->
        error("Malformed proof must fail before crypto")
    }
}
