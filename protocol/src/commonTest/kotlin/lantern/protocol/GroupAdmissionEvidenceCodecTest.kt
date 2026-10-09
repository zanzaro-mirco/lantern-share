package lantern.protocol

import kotlinx.serialization.SerializationException
import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.text.CharacterCodingException

class GroupAdmissionEvidenceCodecTest {
    private val group = "a".repeat(64)
    private val founder = "b".repeat(64)
    private val member = "c".repeat(64)
    private val other = "d".repeat(64)
    private val anchor = GroupTrustAnchor(group, founder)
    private val admission = SignedGroupAdmission(GroupAdmissionClaim(group, founder, member), "cHJvb2Y=")
    private val proof = GroupAdmissionProof(anchor, listOf(admission))
    private val proofJson = GroupAdmissionProofCodec.encode(proof).decodeToString()
    // Intentionally not X.509: common codec checks syntax, never certificate validity or trust.
    private val certificate = GroupAdmissionCertificate(founder, "AA==")
    private val certificateJson = "{\"identity\":\"$founder\",\"der\":\"AA==\"}"
    private val canonical = "{\"version\":1,\"type\":\"GROUP_EVIDENCE\",\"proof\":$proofJson," +
        "\"certificates\":[$certificateJson]}"

    @Test
    fun canonicalRoundTripKeepsTheExistingProofBytes() {
        val evidence = GroupAdmissionEvidence(proof, listOf(certificate))
        assertEquals(canonical, GroupAdmissionEvidenceCodec.encode(evidence).decodeToString())
        val decoded = decode(canonical)
        assertContentEquals(GroupAdmissionProofCodec.encode(proof), GroupAdmissionProofCodec.encode(decoded.proof))
        assertEquals(listOf(certificate), decoded.certificates)
    }

    @Test
    fun orderWhitespaceAndEscapedNamesNormalizeWithoutLosingDuplicates() {
        val reordered = " { \"certificates\": [{\"der\":\"AA==\",\"identity\":\"$founder\"}], " +
            "\"proof\":$proofJson, \"type\":\"GROUP_EVIDENCE\", \"ver\\u0073ion\":1 } "
        assertEquals(canonical, GroupAdmissionEvidenceCodec.encode(decode(reordered)).decodeToString())
        for (field in listOf("\"ver\\u0073ion\":1", "\"type\":\"GROUP_EVIDENCE\"",
            "\"proof\":$proofJson", "\"certificates\":[$certificateJson]")) {
            assertFailsWith<SerializationException> { decode(canonical.dropLast(1) + ",$field}") }
        }
    }

    @Test
    fun allFieldsRequiredAndUnknownFieldsRejected() {
        val fields = listOf("\"version\":1", "\"type\":\"GROUP_EVIDENCE\"",
            "\"proof\":$proofJson", "\"certificates\":[$certificateJson]")
        for (missing in fields.indices) {
            assertFailsWith<SerializationException> {
                decode(fields.filterIndexed { index, _ -> index != missing }.joinToString(",", "{", "}"))
            }
        }
        assertFailsWith<SerializationException> { decode(canonical.dropLast(1) + ",\"extra\":0}") }
    }

    @Test
    fun versionTypeAndContainerTypesAreStrict() {
        for (version in listOf("0", "2", "1.0", "1e0", "\"1\"", "null", "true", "[]", "{}")) {
            assertFailsWith<SerializationException> { decode(canonical.replaceFirst("\"version\":1", "\"version\":$version")) }
        }
        for (type in listOf("\"HELLO\"", "\"APPROVE\"", "\"GROUP_CONFIRM\"", "1", "null", "true")) {
            assertFailsWith<SerializationException> { decode(canonical.replace("\"GROUP_EVIDENCE\"", type)) }
        }
        for (payload in listOf("[]", "null", canonical + "{}", canonical.replace(proofJson, "null"),
            canonical.replace(proofJson, "[]"), canonical.replace("[$certificateJson]", "{}"),
            canonical.replace("[$certificateJson]", "null"))) {
            assertFailsWith<SerializationException> { decode(payload) }
        }
    }

    @Test
    fun certificateFieldsAreRequiredUniqueAndTyped() {
        val malformed = listOf(
            "{\"identity\":\"$founder\"}", "{\"der\":\"AA==\"}",
            certificateJson.dropLast(1) + ",\"id\\u0065ntity\":\"$founder\"}",
            certificateJson.dropLast(1) + ",\"der\":\"AA==\"}",
            certificateJson.dropLast(1) + ",\"extra\":false}",
            certificateJson.replace("\"AA==\"", "null"), certificateJson.replace("\"$founder\"", "false"),
        )
        for (entry in malformed) assertFailsWith<SerializationException> { decode(canonical.replace(certificateJson, entry)) }
        for (identity in listOf("alias", founder.uppercase(), founder.dropLast(1))) {
            assertFailsWith<IllegalArgumentException> { GroupAdmissionCertificate(identity, "AA==") }
        }
    }

    @Test
    fun base64IsCanonicalAndBoundedBeforeAnyOsDecoding() {
        for (valid in listOf("AA==", "AAA=", "AAAA", "/w==", "//8=", "////")) {
            assertEquals(valid, GroupAdmissionCertificate(founder, valid).der)
        }
        for (invalid in listOf("", "AA", "AAA", "AB==", "AAB=", "AA===", "====", "AA==AAAA",
            " AA==", "AA==\n", "_w==", "-w==", "\u0000AAA", "AéAA")) {
            assertFailsWith<IllegalArgumentException> { GroupAdmissionCertificate(founder, invalid) }
            assertFailsWith<IllegalArgumentException> { decode(canonical.replace("AA==", invalid.replace("\n", "\\n"))) }
        }
        val maximum = "AAAA".repeat(1365) + "AA==" // Exactly 4096 bytes, no parser involved.
        assertEquals(GroupAdmissionCertificate.MAX_ENCODED_LENGTH, maximum.length)
        assertEquals(maximum, decode(canonical.replace("AA==", maximum)).certificates.single().der)
        for (tooLarge in listOf("AAAA".repeat(1365) + "AAA=", "AAAA".repeat(1366))) {
            assertFailsWith<IllegalArgumentException> { GroupAdmissionCertificate(founder, tooLarge) }
        }
    }

    @Test
    fun certificatesCoverExactlyTheProofIssuersAndNeverTheFinalMember() {
        val delegated = GroupAdmissionProof(anchor, listOf(
            SignedGroupAdmission(GroupAdmissionClaim(group, founder, other), "cHJvb2Y="),
            SignedGroupAdmission(GroupAdmissionClaim(group, other, member), "cHJvb2Y="),
        ))
        val second = GroupAdmissionCertificate(other, "AAA=")
        assertEquals(2, GroupAdmissionEvidence(delegated, listOf(second, certificate)).certificates.size)
        for (entries in listOf(emptyList(), listOf(second), listOf(certificate),
            listOf(certificate, certificate), listOf(certificate, second, GroupAdmissionCertificate(member, "AAAA")))) {
            assertFailsWith<IllegalArgumentException> { GroupAdmissionEvidence(delegated, entries) }
        }
        assertFailsWith<IllegalArgumentException> {
            decode(canonical.replace(certificateJson, certificateJson.replace(founder, member)))
        }
    }

    @Test
    fun duplicateCertificateIdentityCannotReplacePreviousEvidence() {
        val replacement = certificateJson.replace("AA==", "AAA=")
        val error = assertFailsWith<SerializationException> {
            decode(canonical.replace(certificateJson, "$certificateJson,$replacement"))
        }
        assertEquals("Duplicate admission certificate identity", error.message)
    }

    @Test
    fun maximumCountAndSizeFitAndThirtyThirdCertificateIsNotParsed() {
        val ids = (1..33).map { it.toString(16).padStart(64, '0') }
        val path = (0 until 32).map { index ->
            SignedGroupAdmission(GroupAdmissionClaim(group, ids[index], ids[index + 1]), "AAAA".repeat(64))
        }
        val maximumDer = "AAAA".repeat(1365) + "AA=="
        val evidence = GroupAdmissionEvidence(GroupAdmissionProof(GroupTrustAnchor(group, ids.first()), path),
            ids.take(32).map { GroupAdmissionCertificate(it, maximumDer) })
        val bytes = GroupAdmissionEvidenceCodec.encode(evidence)
        assertTrue(bytes.size < GroupAdmissionEvidenceCodec.MAX_BYTES)
        assertEquals(32, GroupAdmissionEvidenceCodec.decode(bytes).certificates.size)
        val overflow = bytes.decodeToString().dropLast(2) + ",null]}"
        assertEquals("Too many admission certificates",
            assertFailsWith<SerializationException> { decode(overflow) }.message)
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionEvidence(evidence.proof, evidence.certificates + GroupAdmissionCertificate(ids.last(), "AA=="))
        }
    }

    @Test
    fun payloadDepthUtf8AndEmptyLimitsAreEnforced() {
        val padded = canonical + " ".repeat(GroupAdmissionEvidenceCodec.MAX_BYTES - canonical.length)
        assertEquals(anchor, decode(padded).proof.anchor)
        assertFailsWith<IllegalArgumentException> { decode(padded + " ") }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionEvidenceCodec.decode(byteArrayOf()) }
        assertEquals("Protocol JSON is too deeply nested", assertFailsWith<IllegalArgumentException> {
            decode("[".repeat(6) + "0" + "]".repeat(6))
        }.message)
        assertFailsWith<CharacterCodingException> {
            GroupAdmissionEvidenceCodec.decode(byteArrayOf(0xc0.toByte(), 0xaf.toByte()))
        }
        assertFailsWith<SerializationException> { decode(canonical.replace(certificateJson, "")) }
    }

    @Test
    fun nestedProofValidationStillRejectsEscapedDuplicatesAndInvalidAdmissions() {
        for (bad in listOf(
            proofJson.replaceFirst("\"version\":1", "\"version\":0"),
            proofJson.dropLast(1) + ",\"ver\\u0073ion\":1}",
            proofJson.replace("\"founder\":\"$founder\"", "\"founder\":\"$founder\",\"founder\":\"$founder\""),
            proofJson.replace("cHJvb2Y=", "AB=="),
        )) assertFailsWith<IllegalArgumentException> { decode(canonical.replace(proofJson, bad)) }
    }

    @Test
    fun receivedAnchorAndParsedCertificatesDoNotAuthorizeMembership() {
        val received = decode(canonical)
        assertEquals(GroupAdmissionChainResult.AnchorMismatch,
            GroupAdmissionChainVerification.verify(received.proof, GroupTrustAnchor(group, other), member) { _, _, _ ->
                error("Untrusted anchor must not reach verification")
            })
        val broken = GroupAdmissionEvidence(GroupAdmissionProof(anchor, listOf(admission, admission)), listOf(certificate))
        assertEquals(GroupAdmissionChainResult.BrokenChain,
            GroupAdmissionChainVerification.verify(broken.proof, anchor, member) { _, _, _ -> error("Broken path") })
    }

    @Test
    fun snapshotsAndEncodedBuffersCannotBeModifiedThroughPublicViews() {
        val entries = mutableListOf(certificate, GroupAdmissionCertificate(other, "AAA="))
        val path = GroupAdmissionProof(anchor, listOf(
            SignedGroupAdmission(GroupAdmissionClaim(group, founder, other), "cHJvb2Y="),
            SignedGroupAdmission(GroupAdmissionClaim(group, other, member), "cHJvb2Y="),
        ))
        val evidence = GroupAdmissionEvidence(path, entries)
        entries.clear()
        (evidence.certificates as MutableList<GroupAdmissionCertificate>).clear()
        assertEquals(2, evidence.certificates.size)
        val encoded = GroupAdmissionEvidenceCodec.encode(evidence)
        val original = encoded.copyOf()
        encoded.fill(0)
        assertContentEquals(original, GroupAdmissionEvidenceCodec.encode(evidence))
    }

    @Test
    fun certificateOrderingIsDeterministicAndOtherWireCodecsRejectEvidence() {
        val path = GroupAdmissionProof(anchor, listOf(
            SignedGroupAdmission(GroupAdmissionClaim(group, founder, other), "cHJvb2Y="),
            SignedGroupAdmission(GroupAdmissionClaim(group, other, member), "cHJvb2Y="),
        ))
        val certificates = listOf(certificate, GroupAdmissionCertificate(other, "AAA="))
        assertContentEquals(GroupAdmissionEvidenceCodec.encode(GroupAdmissionEvidence(path, certificates)),
            GroupAdmissionEvidenceCodec.encode(GroupAdmissionEvidence(path, certificates.reversed())))
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeFrameCodec.decode(canonical.encodeToByteArray()) }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionConfirmationCodec.decode(canonical.encodeToByteArray()) }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionProofCodec.decode(canonical.encodeToByteArray()) }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionEvidenceCodec.decode(GroupAdmissionProofCodec.encode(proof)) }
    }

    private fun decode(payload: String) = GroupAdmissionEvidenceCodec.decode(payload.encodeToByteArray())
}
