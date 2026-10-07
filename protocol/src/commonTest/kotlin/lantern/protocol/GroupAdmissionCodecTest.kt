package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.text.CharacterCodingException
import lantern.domain.GroupAdmissionClaim

class GroupAdmissionCodecTest {
    private val group = "c".repeat(64)
    private val issuer = "a".repeat(64)
    private val member = "b".repeat(64)
    private val claim = GroupAdmissionClaim(group, issuer, member)
    private val vector = """{"version":1,"group":"$group","issuer":"$issuer","member":"$member"}"""

    @Test
    fun canonicalJsonAndSigningVectorAreStableAndDirectional() {
        assertEquals(vector, GroupAdmissionCodec.encode(claim).decodeToString())
        assertEquals(claim, decode(vector))
        val signingVector = "25:lantern-group-admission-1" + "1:1" +
            "64:$group" + "64:$issuer" + "64:$member"
        assertContentEquals(signingVector.encodeToByteArray(), GroupAdmissionCodec.signedBytes(claim))
        assertEquals(232, GroupAdmissionCodec.signedBytes(claim).size)
        val reversed = GroupAdmissionClaim(group, member, issuer)
        assertFalse(GroupAdmissionCodec.signedBytes(claim).contentEquals(GroupAdmissionCodec.signedBytes(reversed)))
    }

    @Test
    fun inputOrderWhitespaceAndEscapesDoNotChangeSignedBytes() {
        val reordered = """ { "member": "$member", "issuer": "$issuer", "version": 1, "group": "$group" } """
        val escaped = vector.replace("\"group\"", "\"gr\\u006fup\"").replace(group, "\\u0063" + group.drop(1))
        for (input in listOf(reordered, escaped)) {
            val decoded = decode(input)
            assertEquals(claim, decoded)
            assertEquals(vector, GroupAdmissionCodec.encode(decoded).decodeToString())
            assertContentEquals(GroupAdmissionCodec.signedBytes(claim), GroupAdmissionCodec.signedBytes(decoded))
        }
    }

    @Test
    fun everyClaimFieldIsBoundByCanonicalBytes() {
        val replacements = listOf(
            claim.copy(groupId = "d".repeat(64)),
            claim.copy(issuerId = "d".repeat(64)),
            claim.copy(memberId = "d".repeat(64)),
        )
        for (replacement in replacements) {
            assertFalse(GroupAdmissionCodec.signedBytes(claim).contentEquals(GroupAdmissionCodec.signedBytes(replacement)))
        }
    }

    @Test
    fun rejectsMissingUnknownAndDuplicateFieldsIncludingEscapedKeys() {
        val fields = listOf(
            "\"version\":1",
            "\"group\":\"$group\"",
            "\"issuer\":\"$issuer\"",
            "\"member\":\"$member\"",
        )
        for (field in fields) {
            assertFailsWith<IllegalArgumentException> { decode("{${fields.filterNot { it == field }.joinToString(",")}}") }
            assertFailsWith<IllegalArgumentException> { decode("{$field,${fields.joinToString(",")}}") }
        }
        for (key in listOf("vers\\u0069on", "gr\\u006fup", "iss\\u0075er", "memb\\u0065r")) {
            val value = if (key.startsWith("vers")) "1" else "\"$group\""
            assertFailsWith<IllegalArgumentException> { decode("{\"$key\":$value," + vector.drop(1)) }
        }
        assertFailsWith<IllegalArgumentException> { decode("{\"extra\":false," + vector.drop(1)) }
    }

    @Test
    fun rejectsUnsupportedVersionsAndAlternativeNumericSpellings() {
        for (version in listOf("0", "2", "-1", "1.0", "1e0", "01", "\"1\"", "true", "null", "[]", "{}")) {
            assertFailsWith<IllegalArgumentException>(version) { decode(vector.replace("\"version\":1", "\"version\":$version")) }
        }
    }

    @Test
    fun rejectsInvalidIdsOnDecodeEncodeAndSigning() {
        val invalidIds = listOf(
            "", "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64),
            "é".repeat(64), " a".repeat(32),
        )
        for (id in invalidIds) {
            for (field in listOf(group, issuer, member)) {
                assertFailsWith<IllegalArgumentException> { decode(vector.replace(field, id)) }
            }
            if (id.isNotBlank()) {
                for (replacement in listOf(
                    claim.copy(groupId = id), claim.copy(issuerId = id), claim.copy(memberId = id),
                )) {
                    assertFailsWith<IllegalArgumentException> { GroupAdmissionCodec.encode(replacement) }
                    assertFailsWith<IllegalArgumentException> { GroupAdmissionCodec.signedBytes(replacement) }
                }
            }
        }
        assertFailsWith<IllegalArgumentException> { decode(vector.replace(member, issuer)) }
    }

    @Test
    fun rejectsNonStringIdsAndNonObjectOrTrailingInput() {
        for (value in listOf("null", "true", "123", "[]", "{}")) {
            for (id in listOf(group, issuer, member)) {
                assertFailsWith<IllegalArgumentException> { decode(vector.replace("\"$id\"", value)) }
            }
        }
        for (input in listOf("{}", "[]", "null", "\"$group\"", vector.dropLast(1), "$vector {}", "$vector true")) {
            assertFailsWith<IllegalArgumentException> { decode(input) }
        }
    }

    @Test
    fun boundsBytesUtf8AndDepthBeforeParsing() {
        val exact = vector + " ".repeat(GroupAdmissionCodec.MAX_BYTES - vector.encodeToByteArray().size)
        assertEquals(claim, decode(exact))
        assertFailsWith<IllegalArgumentException> { decode("$exact ") }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionCodec.decode(byteArrayOf()) }
        val nested = "[".repeat(100) + "0" + "]".repeat(100)
        val deepInput = vector.replace("\"$member\"", nested)
        assertTrue(deepInput.encodeToByteArray().size <= GroupAdmissionCodec.MAX_BYTES)
        val failure = assertFailsWith<IllegalArgumentException> { decode(deepInput) }
        assertEquals("Protocol JSON is too deeply nested", failure.message)
    }

    @Test
    fun malformedUtf8FailsDecodingRatherThanBeingSilentlyReplaced() {
        val malformed = listOf(
            byteArrayOf(0xc3.toByte(), 0x28),
            byteArrayOf(0x80.toByte()),
            byteArrayOf(0xc0.toByte(), 0xaf.toByte()),
            byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()),
            byteArrayOf(0xf4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()),
            byteArrayOf(0xe2.toByte(), 0x82.toByte()),
        )
        for (bytes in malformed) {
            assertFailsWith<CharacterCodingException> { GroupAdmissionCodec.decode(bytes) }
        }
    }

    @Test
    fun returnedBuffersHaveNoSharedOwnership() {
        val signed = GroupAdmissionCodec.signedBytes(claim)
        val encoded = GroupAdmissionCodec.encode(claim)
        signed.fill(0)
        encoded.fill(0)
        assertEquals(vector, GroupAdmissionCodec.encode(claim).decodeToString())
        assertFalse(signed.contentEquals(GroupAdmissionCodec.signedBytes(claim)))
    }

    @Test
    fun activeV0AndBootstrapApprovalRejectTheIsolatedStatement() {
        assertFailsWith<IllegalArgumentException> { Wire.decode(GroupAdmissionCodec.encode(claim)) }
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeApprovalCodec.decode(GroupAdmissionCodec.encode(claim)) }
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeHelloCodec.decode(GroupAdmissionCodec.encode(claim)) }
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeFrameCodec.decode(GroupAdmissionCodec.encode(claim)) }
    }

    private fun decode(value: String) = GroupAdmissionCodec.decode(value.encodeToByteArray())
}
