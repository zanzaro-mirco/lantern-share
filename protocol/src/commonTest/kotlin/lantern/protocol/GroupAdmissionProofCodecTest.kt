package lantern.protocol

import kotlinx.serialization.SerializationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.text.CharacterCodingException
import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor

class GroupAdmissionProofCodecTest {
    private val group = "a".repeat(64)
    private val founder = "b".repeat(64)
    private val member = "c".repeat(64)
    private val other = "d".repeat(64)
    private val anchor = GroupTrustAnchor(group, founder)
    private val admission = SignedGroupAdmission(GroupAdmissionClaim(group, founder, member), "cHJvb2Y=")
    private val anchorJson = "{\"group\":\"$group\",\"founder\":\"$founder\"}"
    private val admissionJson = SignedGroupAdmissionCodec.encode(admission).decodeToString()
    private val canonical = "{\"version\":1,\"anchor\":$anchorJson,\"admissions\":[$admissionJson]}"

    @Test
    fun canonicalRoundTripReusesTheSignedAdmissionFormat() {
        val proof = GroupAdmissionProof(anchor, listOf(admission))
        assertEquals(canonical, GroupAdmissionProofCodec.encode(proof).decodeToString())
        val decoded = decode(canonical)
        assertEquals(anchor, decoded.anchor)
        assertEquals(listOf(admission), decoded.admissions)
        assertContentEquals(GroupAdmissionCodec.signedBytes(admission.claim),
            GroupAdmissionCodec.signedBytes(decoded.admissions.single().claim))
    }

    @Test
    fun whitespaceOrderingAndEscapedFieldNamesNormalize() {
        val reordered = " { \"admissions\": [$admissionJson], \"anchor\": " +
            "{\"founder\":\"$founder\",\"group\":\"$group\"}, \"ver\\u0073ion\":1 } "
        assertEquals(canonical, GroupAdmissionProofCodec.encode(decode(reordered)).decodeToString())
    }

    @Test
    fun requiredUnknownAndDuplicateEnvelopeFieldsAreRejected() {
        val malformed = listOf(
            "{\"anchor\":$anchorJson,\"admissions\":[$admissionJson]}",
            "{\"version\":1,\"admissions\":[$admissionJson]}",
            "{\"version\":1,\"anchor\":$anchorJson}",
            canonical.dropLast(1) + ",\"extra\":0}",
            canonical.dropLast(1) + ",\"ver\\u0073ion\":1}",
            canonical.dropLast(1) + ",\"anchor\":$anchorJson}",
            canonical.dropLast(1) + ",\"admissions\":[$admissionJson]}",
        )
        for (payload in malformed) assertFailsWith<SerializationException> { decode(payload) }
    }

    @Test
    fun unsupportedVersionsAndWrongTypesDoNotFallback() {
        for (version in listOf("0", "2", "1.0", "1e0", "\"1\"", "null", "true", "[]", "{}")) {
            assertFailsWith<SerializationException> { decode(canonical.replaceFirst("\"version\":1,", "\"version\":$version,")) }
        }
        for (payload in listOf(
            "[]", "null", canonical + "{}",
            canonical.replace(anchorJson, "null"), canonical.replace(anchorJson, "[]"),
            canonical.replace("[$admissionJson]", "{}"), canonical.replace("[$admissionJson]", "null"),
        )) assertFailsWith<SerializationException> { decode(payload) }
    }

    @Test
    fun anchorIsStrictAndNeverInferredFromThePath() {
        val badAnchors = listOf(
            "{\"group\":\"$group\"}", "{\"founder\":\"$founder\"}",
            anchorJson.dropLast(1) + ",\"gr\\u006fup\":\"$group\"}",
            anchorJson.dropLast(1) + ",\"founder\":\"$founder\"}",
            anchorJson.dropLast(1) + ",\"extra\":0}",
            anchorJson.replace(group, group.uppercase()), anchorJson.replace(founder, "founder"),
            "{\"group\":false,\"founder\":\"$founder\"}",
        )
        for (bad in badAnchors) assertFailsWith<SerializationException> { decode(canonical.replace(anchorJson, bad)) }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionProof(GroupTrustAnchor("group", founder), listOf(admission)) }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionProof(GroupTrustAnchor(group, "founder"), listOf(admission)) }
    }

    @Test
    fun countIsBoundedBeforeDecodingTheThirtyThirdEntry() {
        val max = GroupAdmissionChainVerification.MAX_ADMISSIONS
        val entries = List(max) { admissionJson }.joinToString(",")
        val full = canonical.replace(admissionJson, entries)
        assertEquals(max, decode(full).admissions.size)
        assertTrue(full.encodeToByteArray().size < GroupAdmissionProofCodec.MAX_BYTES)
        val failure = assertFailsWith<SerializationException> {
            decode(canonical.replace(admissionJson, "$entries,null"))
        }
        assertEquals("Too many group proof admissions", failure.message)
        assertFailsWith<SerializationException> { decode(canonical.replace(admissionJson, "")) }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionProof(anchor, emptyList()) }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionProof(anchor, List(max + 1) { admission }) }
    }

    @Test
    fun nestedAdmissionValidationIsNotWeakenedByTheProofEnvelope() {
        val invalidAdmissions = listOf(
            admissionJson.replace("\"version\":1", "\"version\":0"),
            admissionJson.replace("\"member\":\"$member\"", "\"member\":\"$founder\""),
            admissionJson.replace("cHJvb2Y=", "abd="),
            admissionJson.dropLast(1) + ",\"signature\":\"cHJvb2Y=\"}",
        )
        for (entry in invalidAdmissions) assertFailsWith<IllegalArgumentException> {
            decode(canonical.replace(admissionJson, entry))
        }
    }

    @Test
    fun byteDepthAndUtf8GuardsApplyBeforeMaterialization() {
        val padded = canonical + " ".repeat(GroupAdmissionProofCodec.MAX_BYTES - canonical.length)
        assertEquals(anchor, decode(padded).anchor)
        assertFailsWith<IllegalArgumentException> { decode(padded + " ") }
        val deep = "[".repeat(100) + "0" + "]".repeat(100)
        assertTrue(deep.length < GroupAdmissionProofCodec.MAX_BYTES)
        assertEquals("Protocol JSON is too deeply nested",
            assertFailsWith<IllegalArgumentException> { decode(deep) }.message)
        assertFailsWith<CharacterCodingException> {
            GroupAdmissionProofCodec.decode(byteArrayOf(0xc0.toByte(), 0xaf.toByte()))
        }
    }

    @Test
    fun proofOwnsItsPathAndEncodedBuffers() {
        val supplied = mutableListOf(admission, admission)
        val proof = GroupAdmissionProof(anchor, supplied)
        supplied.clear()
        (proof.admissions as MutableList<SignedGroupAdmission>).clear()
        assertEquals(listOf(admission, admission), proof.admissions)
        val encoded = GroupAdmissionProofCodec.encode(proof)
        encoded.fill(0)
        assertEquals(canonical.replace(admissionJson, "$admissionJson,$admissionJson"),
            GroupAdmissionProofCodec.encode(proof).decodeToString())
    }

    @Test
    fun verificationComparesReceivedAnchorWithLocalAnchorBeforeCrypto() {
        val decoded = decode(canonical)
        for (local in listOf(GroupTrustAnchor(other, founder), GroupTrustAnchor(group, other))) {
            assertEquals(GroupAdmissionChainResult.AnchorMismatch,
                GroupAdmissionChainVerification.verify(decoded, local, member) { _, _, _ -> error("Untrusted anchor") })
        }
        assertEquals(GroupAdmissionChainResult.VerifiedChain,
            GroupAdmissionChainVerification.verify(decoded, anchor, member) { _, _, _ -> true })
        assertEquals(GroupAdmissionChainResult.MemberMismatch,
            GroupAdmissionChainVerification.verify(decoded, anchor, other) { _, _, _ -> error("Wrong target") })
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionChainVerification.verify(decoded, GroupTrustAnchor("group", founder), member) { _, _, _ -> true }
        }
    }

    @Test
    fun decodingDoesNotVerifyTopologyOrGrantTrust() {
        val repeated = decode(canonical.replace(admissionJson, "$admissionJson,$admissionJson"))
        assertEquals(GroupAdmissionChainResult.BrokenChain,
            GroupAdmissionChainVerification.verify(repeated, anchor, member) { _, _, _ -> error("Broken path") })
        assertEquals("Protocol JSON is too deeply nested", assertFailsWith<IllegalArgumentException> {
            SignedGroupAdmissionCodec.decode(canonical.encodeToByteArray())
        }.message)
        assertFailsWith<SerializationException> { GroupAdmissionProofCodec.decode(admissionJson.encodeToByteArray()) }
    }

    private fun decode(payload: String) = GroupAdmissionProofCodec.decode(payload.encodeToByteArray())
}
