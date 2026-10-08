package lantern.protocol

import kotlinx.serialization.SerializationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.text.CharacterCodingException

class GroupAdmissionConfirmationCodecTest {
    private val sender = "a".repeat(64)
    private val recipient = "b".repeat(64)
    private val confirmation = GroupAdmissionConfirmation(sender, recipient, "cHJvb2Y=")
    private val fields = listOf("\"version\":1", "\"type\":\"GROUP_CONFIRM\"", "\"sender\":\"$sender\"",
        "\"recipient\":\"$recipient\"", "\"signature\":\"cHJvb2Y=\"")
    private val canonical = fields.joinToString(",", "{", "}")

    @Test
    fun canonicalRoundTripAndSendTicketEncodingRemainUnverified() {
        assertEquals(canonical, GroupAdmissionConfirmationCodec.encode(confirmation).decodeToString())
        assertEquals(confirmation, decode(canonical))
        assertContentEquals(GroupAdmissionConfirmationCodec.encode(confirmation),
            GroupAdmissionConfirmationCodec.encode(GroupAdmissionConfirmationOperation.Send(sender, recipient, confirmation.signature)))
        // Canonical Base64 is not a DER/signature proof.
        assertEquals("AA==", decode(canonical.replace("cHJvb2Y=", "AA==")).signature)
    }

    @Test
    fun orderWhitespaceAndValidEscapesNormalize() {
        val input = fields.reversed().joinToString(" , ", " { ", " } ").replace("\"sender\"", "\"s\\u0065nder\"")
        assertEquals(confirmation, decode(input))
        assertEquals(canonical, GroupAdmissionConfirmationCodec.encode(decode(input)).decodeToString())
    }

    @Test
    fun allFieldsAreRequiredAndDuplicatesIncludingEscapedNamesAreRejected() {
        for (index in fields.indices) {
            assertFailsWith<SerializationException> { decode(fields.filterIndexed { i, _ -> i != index }.joinToString(",", "{", "}")) }
            assertFailsWith<SerializationException> { decode(canonical.dropLast(1) + ",${fields[index]}}") }
        }
        assertFailsWith<SerializationException> { decode(canonical.dropLast(1) + ",\"s\\u0065nder\":\"$sender\"}") }
        assertFailsWith<SerializationException> { decode(canonical.dropLast(1) + ",\"extra\":0}") }
    }

    @Test
    fun versionAndTypeAreExactAndNeverFallbackToBootstrapOrWireZero() {
        for (version in listOf("0", "2", "1.0", "1e0", "\"1\"", "null", "false")) {
            assertFailsWith<SerializationException> { decode(canonical.replace("\"version\":1", "\"version\":$version")) }
        }
        for (type in listOf("\"APPROVE\"", "\"HELLO\"", "\"group_confirm\"", "\"GROUP_CONFIRM \"", "1", "null")) {
            assertFailsWith<SerializationException> { decode(canonical.replace("\"GROUP_CONFIRM\"", type)) }
        }
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeFrameCodec.decode(canonical.encodeToByteArray()) }
        assertFailsWith<IllegalArgumentException> { Wire.decode(canonical.encodeToByteArray()) }
        val bootstrap = ProtocolHandshakeFrameCodec.encode(ProtocolHandshakeFrame.Approve(
            ProtocolHandshakeApproval(sender, recipient, "cHJvb2Y=")))
        assertFailsWith<IllegalArgumentException> { GroupAdmissionConfirmationCodec.decode(bootstrap) }
    }

    @Test
    fun malformedIdentitiesSignaturesAndTypesAreRejectedAtConstructionAndParsing() {
        for (bad in listOf("", "a", sender.uppercase(), sender.dropLast(1), " " + sender)) {
            assertFailsWith<IllegalArgumentException> { GroupAdmissionConfirmation(bad, recipient, confirmation.signature) }
            assertFailsWith<IllegalArgumentException> { decode(canonical.replace(sender, bad)) }
        }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionConfirmation(sender, sender, confirmation.signature) }
        assertFailsWith<IllegalArgumentException> { decode(canonical.replace(recipient, sender)) }
        for (bad in listOf("", "bad", "abd=", "AA", "_A==", "AA==\n", "A".repeat(260))) {
            assertFailsWith<IllegalArgumentException> { GroupAdmissionConfirmation(sender, recipient, bad) }
        }
        for (field in listOf("sender", "recipient", "signature")) {
            val old = fields.single { it.startsWith("\"$field\"") }
            assertFailsWith<SerializationException> { decode(canonical.replace(old, "\"$field\":false")) }
        }
    }

    @Test
    fun exactByteBoundUtf8AndDepthAreEnforced() {
        val padded = canonical + " ".repeat(GroupAdmissionConfirmationCodec.MAX_BYTES - canonical.length)
        assertEquals(confirmation, decode(padded))
        assertFailsWith<IllegalArgumentException> { decode(padded + " ") }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionConfirmationCodec.decode(byteArrayOf()) }
        assertFailsWith<CharacterCodingException> { GroupAdmissionConfirmationCodec.decode(byteArrayOf(0xc0.toByte(), 0xaf.toByte())) }
        assertEquals("Protocol JSON is too deeply nested", assertFailsWith<IllegalArgumentException> {
            decode("[".repeat(30) + "0" + "]".repeat(30))
        }.message)
    }

    @Test
    fun rootAndTrailingDocumentsMustNotBeAccepted() {
        for (bad in listOf("[]", "null", "true", "\"text\"", canonical + "{}")) {
            assertFailsWith<SerializationException> { decode(bad) }
        }
    }

    @Test
    fun buffersAreOwnedByEachCall() {
        val bytes = GroupAdmissionConfirmationCodec.encode(confirmation)
        val decoded = GroupAdmissionConfirmationCodec.decode(bytes)
        bytes.fill(0)
        assertEquals(confirmation, decoded)
        assertEquals(canonical, GroupAdmissionConfirmationCodec.encode(confirmation).decodeToString())
    }

    private fun decode(json: String) = GroupAdmissionConfirmationCodec.decode(json.encodeToByteArray())
}
