package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ProtocolHandshakeApprovalCodecTest {
    private val sender = "a".repeat(64)
    private val recipient = "b".repeat(64)
    private val signature = "cHJvb2Y="
    private val vector = """{"sender":"$sender","recipient":"$recipient","signature":"$signature"}"""

    @Test
    fun canonicalVectorRoundTripsWithReorderedAndEscapedFields() {
        val approval = ProtocolHandshakeApproval(sender, recipient, signature)
        assertEquals(vector, ProtocolHandshakeApprovalCodec.encode(approval).decodeToString())
        assertEquals(approval, decode(vector))
        val reordered = """ { "signature": "$signature", "recipient": "$recipient", "sender": "$sender" } """
        assertEquals(approval, decode(reordered))
        assertEquals(approval, decode(vector.replace("cHJvb2Y=", "\\u0063HJvb2Y=")))
        assertEquals(vector, ProtocolHandshakeApprovalCodec.encode(decode(reordered)).decodeToString())
    }

    @Test
    fun rejectsMissingUnknownDuplicateAndMalformedFields() {
        val invalid = listOf(
            "{}", "[]", "null", vector.dropLast(1), "$vector true",
            vector.replace("\"sender\":\"$sender\",", ""),
            vector.replace("\"recipient\":\"$recipient\",", ""),
            vector.replace(",\"signature\":\"$signature\"", ""),
            vector.replace("\"sender\":", "\"extra\":false,\"sender\":"),
            vector.replace("\"sender\":", "\"sender\":\"$sender\",\"sender\":"),
            vector.replace("\"recipient\":", "\"recipient\":\"$recipient\",\"recipient\":"),
            vector.replace("\"signature\":", "\"signature\":\"$signature\",\"signature\":"),
            vector.replace("\"signature\":", "\"signat\\u0075re\":\"$signature\",\"signature\":"),
        )
        for (input in invalid) assertFailsWith<IllegalArgumentException>(input) { decode(input) }
    }

    @Test
    fun rejectsWrongTypesInvalidAddressesAndSignatureEncoding() {
        for (value in listOf("null", "true", "123", "[]", "{}")) {
            assertFailsWith<IllegalArgumentException> { decode(vector.replace("\"$sender\"", value)) }
            assertFailsWith<IllegalArgumentException> { decode(vector.replace("\"$recipient\"", value)) }
            assertFailsWith<IllegalArgumentException> { decode(vector.replace("\"$signature\"", value)) }
        }
        for (identity in listOf("", "a".repeat(63), "c".repeat(65), "A".repeat(64), "é".repeat(64))) {
            assertFailsWith<IllegalArgumentException> { ProtocolHandshakeApproval(identity, recipient, signature) }
            assertFailsWith<IllegalArgumentException> { ProtocolHandshakeApproval(sender, identity, signature) }
        }
        assertFailsWith<IllegalArgumentException> { decode(vector.replace(recipient, sender)) }
        for (encoded in listOf("", " ", "not-base64", "A", "AAA", "AA=", "AB==", "AAB=", "AA===", "AA==AA==", "____", "éééé", "AAAA\n", "A".repeat(260))) {
            assertFailsWith<IllegalArgumentException>(encoded) { ProtocolHandshakeApproval(sender, recipient, encoded) }
        }
    }

    @Test
    fun signatureSyntaxIsNotProofOfEcdsaValidity() {
        for (encoded in listOf("AA==", "AAA=", "AAAA", "////", "AA+/", "A".repeat(256))) {
            val approval = ProtocolHandshakeApproval(sender, recipient, encoded)
            assertEquals(approval, ProtocolHandshakeApprovalCodec.decode(ProtocolHandshakeApprovalCodec.encode(approval)))
        }
    }

    @Test
    fun boundsBytesDepthAndUtf8BeforeParsing() {
        val exact = vector + " ".repeat(ProtocolHandshakeApprovalCodec.MAX_BYTES - vector.encodeToByteArray().size)
        assertEquals(sender, decode(exact).sender)
        assertFailsWith<IllegalArgumentException> { decode("$exact ") }
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeApprovalCodec.decode(byteArrayOf()) }
        kotlin.test.assertFails { ProtocolHandshakeApprovalCodec.decode(byteArrayOf(0xc3.toByte(), 0x28)) }
        val nested = "[".repeat(200) + "0" + "]".repeat(200)
        assertFailsWith<IllegalArgumentException> { decode(vector.replace("\"$signature\"", nested)) }
    }

    @Test
    fun isolatedApprovalIsNotAcceptedByActiveWireV0() {
        assertFailsWith<IllegalArgumentException> { Wire.decode(vector.encodeToByteArray()) }
    }

    private fun decode(value: String) = ProtocolHandshakeApprovalCodec.decode(value.encodeToByteArray())
}
