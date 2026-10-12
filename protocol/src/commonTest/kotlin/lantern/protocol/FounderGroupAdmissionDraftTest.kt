package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository
import kotlinx.coroutines.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.test.assertSame

class FounderGroupAdmissionDraftTest {
    private val founder = "a".repeat(64)
    private val member = "b".repeat(64)
    private val anchor = GroupTrustAnchor("c".repeat(64), founder)
    private val signature = "cHJvb2Y=" // Encoding fixture, deliberately not a real ECDSA signature.

    @Test
    fun firstDelegationUsesSavedOriginAndExistingCanonicalFormat() {
        val draft = FounderGroupAdmissionDraft.prepare(anchor, founder, member)
        val claim = GroupAdmissionClaim(anchor.groupId, founder, member)
        assertEquals(anchor, draft.anchor)
        assertEquals(claim, draft.claim)
        assertContentEquals(GroupAdmissionCodec.signedBytes(claim), draft.signedBytes())
        val proof = draft.withSignature(signature)
        assertEquals(anchor, proof.anchor)
        assertEquals(listOf(SignedGroupAdmission(claim, signature)), proof.admissions)
        val decoded = GroupAdmissionProofCodec.decode(GroupAdmissionProofCodec.encode(proof))
        assertEquals(proof.anchor, decoded.anchor)
        assertEquals(proof.admissions, decoded.admissions)
    }

    @Test
    fun returnedBytesCannotModifyTheDraftOrLaterSignatureInput() {
        val draft = FounderGroupAdmissionDraft.prepare(anchor, founder, member)
        val bytes = draft.signedBytes()
        val expected = bytes.copyOf()
        bytes.fill(0)
        assertContentEquals(expected, draft.signedBytes())
        assertContentEquals(expected, GroupAdmissionCodec.signedBytes(draft.withSignature(signature).admissions.single().claim))
    }

    @Test
    fun delegatedOrForeignIdentityCannotUseFounderOnlyPreparation() {
        for (issuer in listOf(member, "d".repeat(64))) {
            assertFailsWith<IllegalArgumentException> {
                FounderGroupAdmissionDraft.prepare(anchor, issuer, "e".repeat(64))
            }
        }
    }

    @Test
    fun selfAdmissionIsStillForbidden() {
        assertFailsWith<IllegalArgumentException> { FounderGroupAdmissionDraft.prepare(anchor, founder, founder) }
    }

    @Test
    fun malformedIdentifiersAreNotNormalized() {
        val malformed = listOf("", " ", founder.uppercase(), "a".repeat(63), "g".repeat(64), "$founder\n")
        for (id in malformed) {
            assertFailsWith<IllegalArgumentException> { FounderGroupAdmissionDraft.prepare(anchor, id, member) }
            assertFailsWith<IllegalArgumentException> { FounderGroupAdmissionDraft.prepare(anchor, founder, id) }
            if (id.isNotBlank()) {
                assertFailsWith<IllegalArgumentException> {
                    FounderGroupAdmissionDraft.prepare(GroupTrustAnchor(id, founder), founder, member)
                }
                assertFailsWith<IllegalArgumentException> {
                    FounderGroupAdmissionDraft.prepare(GroupTrustAnchor(anchor.groupId, id), founder, member)
                }
            }
        }
    }

    @Test
    fun malformedSignatureIsRejectedWithoutInventingAReplacement() {
        val draft = FounderGroupAdmissionDraft.prepare(anchor, founder, member)
        for (value in listOf("", " ", "bad", "$signature\n", "a".repeat(260))) {
            assertFailsWith<IllegalArgumentException> { draft.withSignature(value) }
        }
    }

    @Test
    fun encodingAndPreparationDoNotAttestCryptographicValidity() {
        val proof = FounderGroupAdmissionDraft.prepare(anchor, founder, member).withSignature(signature)
        var calls = 0
        assertEquals(GroupAdmissionChainResult.InvalidSignature(0),
            GroupAdmissionChainVerification.verify(proof, anchor, member) { issuer, bytes, value ->
                calls++
                assertEquals(founder, issuer)
                assertContentEquals(GroupAdmissionCodec.signedBytes(proof.admissions.single().claim), bytes)
                assertEquals(signature, value)
                false
            })
        assertEquals(1, calls)
    }

    @Test
    fun changedGroupOrMemberChangesSignatureInputAndDoesNotPassIndependentContext() {
        val original = FounderGroupAdmissionDraft.prepare(anchor, founder, member)
        val another = FounderGroupAdmissionDraft.prepare(GroupTrustAnchor("d".repeat(64), founder), founder, member)
        val otherMember = FounderGroupAdmissionDraft.prepare(anchor, founder, "e".repeat(64))
        assertNotEquals(original.signedBytes().decodeToString(), another.signedBytes().decodeToString())
        assertNotEquals(original.signedBytes().decodeToString(), otherMember.signedBytes().decodeToString())
        assertEquals(GroupAdmissionChainResult.AnchorMismatch,
            GroupAdmissionChainVerification.verify(another.withSignature(signature), anchor, member) { _, _, _ ->
                error("Mismatched root must reject before cryptography")
            })
        assertEquals(GroupAdmissionChainResult.MemberMismatch,
            GroupAdmissionChainVerification.verify(otherMember.withSignature(signature), anchor, member) { _, _, _ ->
                error("Mismatched member must reject before cryptography")
            })
        assertTrue(original.withSignature(signature).admissions.size == 1)
    }

    @Test
    fun signingAndVerificationReceiveSeparateCanonicalCopies() {
        val expected = FounderGroupAdmissionDraft.prepare(anchor, founder, member).signedBytes()
        var reads = 0
        val proof = FounderGroupAdmissionDraft.prepareSigned(repository { reads++; anchor }, founder, member,
            sign = { bytes ->
                assertContentEquals(expected, bytes)
                bytes.fill(0)
                signature
            },
            verifySignature = { bytes, value ->
                assertContentEquals(expected, bytes)
                assertEquals(signature, value)
                bytes.fill(1)
                true // Boundary fixture only, not a cryptographic verification.
            })
        assertContentEquals(expected, GroupAdmissionCodec.signedBytes(proof.admissions.single().claim))
        assertEquals(2, reads)
    }

    @Test
    fun invalidOrMissingFoundationNeverCallsOSAdapters() {
        for (saved in listOf(null, GroupTrustAnchor("bad", founder), GroupTrustAnchor(anchor.groupId, member))) {
            assertFailsWith<IllegalArgumentException> {
                FounderGroupAdmissionDraft.prepareSigned(repository { saved }, founder, member,
                    { error("Must not sign") }, { _, _ -> error("Must not verify") })
            }
        }
    }

    @Test
    fun signerFailureAndCancellationPropagateWithoutVerificationOrRetry() {
        for (failure in listOf(IllegalStateException("OS unavailable"), CancellationException("cancelled"))) {
            var reads = 0
            var signs = 0
            val thrown = assertFailsWith<Exception> {
                FounderGroupAdmissionDraft.prepareSigned(repository { reads++; anchor }, founder, member,
                    { signs++; throw failure }, { _, _ -> error("Must not verify failed signing") })
            }
            assertSame(failure, thrown)
            assertEquals(1, signs)
            assertEquals(1, reads)
        }
    }

    @Test
    fun invalidSignatureRefusesBeforeFinalRead() {
        var reads = 0
        assertFailsWith<IllegalStateException> {
            FounderGroupAdmissionDraft.prepareSigned(repository { reads++; anchor }, founder, member,
                { signature }, { _, _ -> false })
        }
        assertEquals(1, reads)
    }

    @Test
    fun verifierFailureIsNotConvertedToInvalidSignatureOrSuccess() {
        val failure = IllegalStateException("provider unavailable")
        val thrown = assertFailsWith<IllegalStateException> {
            FounderGroupAdmissionDraft.prepareSigned(repository { anchor }, founder, member,
                { signature }, { _, _ -> throw failure })
        }
        assertSame(failure, thrown)
    }

    @Test
    fun groupChangeDuringEitherOSCallbackCannotReleaseProof() {
        for (duringSigning in listOf(true, false)) {
            var saved: GroupTrustAnchor? = anchor
            assertFailsWith<IllegalStateException> {
                FounderGroupAdmissionDraft.prepareSigned(repository { saved }, founder, member,
                    {
                        if (duringSigning) saved = null
                        signature
                    },
                    { _, _ ->
                        if (!duringSigning) saved = GroupTrustAnchor("d".repeat(64), founder)
                        true
                    })
            }
        }
    }

    private fun repository(read: () -> GroupTrustAnchor?) = object : LocalGroupRepository {
        override fun localGroup(): GroupTrustAnchor? = read()
        override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean =
            error("Preparing evidence must not write")
    }
}
