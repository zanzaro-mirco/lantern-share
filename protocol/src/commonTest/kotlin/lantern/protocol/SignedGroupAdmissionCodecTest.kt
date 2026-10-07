package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.text.CharacterCodingException
import lantern.domain.GroupAdmissionClaim

class SignedGroupAdmissionCodecTest {
    private val claim = GroupAdmissionClaim("c".repeat(64), "a".repeat(64), "b".repeat(64))
    private val claimJson = GroupAdmissionCodec.encode(claim).decodeToString()
    private val signature = "cHJvb2Y="
    private val admission = SignedGroupAdmission(claim, signature)
    private val vector = """{"claim":$claimJson,"signature":"$signature"}"""

    @Test
    fun canonicalEnvelopeRoundTripsWithoutAnotherVersion() {
        assertEquals(vector, SignedGroupAdmissionCodec.encode(admission).decodeToString())
        assertEquals(admission, decode(vector))
        assertEquals(admission, decode(""" { "signature": "$signature", "claim": $claimJson } """))
        assertEquals(admission, decode(vector.replace(signature, "\\u0063HJvb2Y=")))
        val mutable = SignedGroupAdmissionCodec.encode(admission)
        mutable.fill(0)
        assertEquals(vector, SignedGroupAdmissionCodec.encode(admission).decodeToString())
    }

    @Test
    fun missingUnknownDuplicateAndEscapedDuplicateFieldsAreRejected() {
        val invalid = listOf(
            "{}", "[]", "null", "$vector {}", vector.dropLast(1),
            """{"claim":$claimJson}""", """{"signature":"$signature"}""",
            "{\"version\":1," + vector.drop(1),
            "{\"extra\":false," + vector.drop(1),
            "{\"claim\":$claimJson," + vector.drop(1),
            "{\"cl\\u0061im\":$claimJson," + vector.drop(1),
            "{\"signature\":\"$signature\"," + vector.drop(1),
            "{\"signat\\u0075re\":\"$signature\"," + vector.drop(1),
        )
        for (input in invalid) assertFailsWith<IllegalArgumentException> { decode(input) }
    }

    @Test
    fun nestedClaimRetainsStrictVersionFieldAndIdentityValidation() {
        val invalid = listOf(
            claimJson.replace("\"version\":1", "\"version\":2"),
            claimJson.replace("\"version\":1", "\"version\":\"1\""),
            claimJson.replace("\"version\":1,", ""),
            "{\"vers\\u0069on\":1," + claimJson.drop(1),
            "{\"group\":\"${claim.groupId}\"," + claimJson.drop(1),
            claimJson.replace(claim.memberId, claim.issuerId),
            claimJson.replace(claim.groupId, "g".repeat(64)),
            claimJson.replace("\"${claim.issuerId}\"", "123"),
            "[]", "null", "\"statement\"",
        )
        for (input in invalid) {
            assertFailsWith<IllegalArgumentException> { decode("""{"claim":$input,"signature":"$signature"}""") }
        }
    }

    @Test
    fun signatureMustHaveCanonicalBoundedBase64Syntax() {
        for (encoded in listOf(
            "", " ", "not-base64", "A", "AAA", "AA=", "AB==", "AAB=", "AA===",
            "AA==AA==", "____", "éééé", "AAAA\n", "A".repeat(260),
        )) {
            assertFailsWith<IllegalArgumentException> { SignedGroupAdmission(claim, encoded) }
        }
        for (value in listOf("null", "true", "123", "[]", "{}")) {
            assertFailsWith<IllegalArgumentException> { decode(vector.replace("\"$signature\"", value)) }
        }
        assertFailsWith<IllegalArgumentException> { decode(vector.replace(signature, "AB==")) }
    }

    @Test
    fun acceptedBase64IsNotEvidenceOfAValidEcdsaSignature() {
        for (encoded in listOf("AA==", "AAA=", "AAAA", "////", "AA+/", "A".repeat(256))) {
            val unverified = SignedGroupAdmission(claim, encoded)
            assertEquals(unverified, SignedGroupAdmissionCodec.decode(SignedGroupAdmissionCodec.encode(unverified)))
        }
        assertFailsWith<IllegalArgumentException> {
            SignedGroupAdmission(GroupAdmissionClaim("group", claim.issuerId, claim.memberId), signature)
        }
    }

    @Test
    fun envelopeSizeUtf8AndDepthAreBoundedBeforeParsing() {
        val exact = vector + " ".repeat(SignedGroupAdmissionCodec.MAX_BYTES - vector.encodeToByteArray().size)
        assertEquals(admission, decode(exact))
        assertFailsWith<IllegalArgumentException> { decode("$exact ") }
        assertFailsWith<IllegalArgumentException> { SignedGroupAdmissionCodec.decode(byteArrayOf()) }
        assertFailsWith<CharacterCodingException> { SignedGroupAdmissionCodec.decode(byteArrayOf(0x80.toByte())) }
        val nested = "[".repeat(100) + "0" + "]".repeat(100)
        val deep = vector.replace("\"$signature\"", nested)
        assertTrue(deep.encodeToByteArray().size <= SignedGroupAdmissionCodec.MAX_BYTES)
        val error = assertFailsWith<IllegalArgumentException> { decode(deep) }
        assertEquals("Protocol JSON is too deeply nested", error.message)
    }

    @Test
    fun signedEnvelopeCannotBeConfusedWithUnsignedOrBootstrapOrV0() {
        val bytes = SignedGroupAdmissionCodec.encode(admission)
        assertFailsWith<IllegalArgumentException> { GroupAdmissionCodec.decode(bytes) }
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeFrameCodec.decode(bytes) }
        assertFailsWith<IllegalArgumentException> { Wire.decode(bytes) }
        assertFailsWith<IllegalArgumentException> { SignedGroupAdmissionCodec.decode(GroupAdmissionCodec.encode(claim)) }
    }

    private fun decode(input: String) = SignedGroupAdmissionCodec.decode(input.encodeToByteArray())
}
