package lantern.protocol

import lantern.domain.GroupTextContent
import lantern.domain.SignedGroupText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GroupTextCodecTest {
    private val a = "a".repeat(64)
    private val b = "b".repeat(64)
    private val g = "c".repeat(64)
    private val s = "d".repeat(64)
    private fun content(body: String = "Caffè ☕", recipients: List<String> = listOf(b, a), sequence: Long = 1) =
        GroupTextContent("00000000-0000-0000-0000-000000000001", g, s, a, sequence, 2, recipients, body)
    private fun message() = SignedGroupText(content(), "AQ==")

    @Test
    fun canonicalRoundTripAndRecipientSnapshotAreIndependentOfInputOrder() {
        val source = mutableListOf(b, a)
        val c = content(recipients = source)
        source.clear()
        assertEquals(listOf(a, b), c.recipients)
        assertContentEquals(GroupTextCodec.signedBytes(c), GroupTextCodec.signedBytes(content(recipients = listOf(a, b))))
        val bytes = GroupTextCodec.encode(message())
        assertTrue(message().sameMessage(GroupTextCodec.decode(bytes)))
        assertContentEquals(bytes, GroupTextCodec.encode(GroupTextCodec.decode(bytes)))
        assertEquals("20:lantern-group-text-136:00000000-0000-0000-0000-00000000000164:${g}64:${s}64:${a}1:11:21:264:${a}64:${b}10:Caffè ☕",
            GroupTextCodec.signedBytes(c).decodeToString())
    }

    @Test
    fun everySignedContextFieldChangesCanonicalBytes() {
        val c = content()
        val baseline = GroupTextCodec.signedBytes(c)
        val alternatives = listOf(
            GroupTextContent("00000000-0000-0000-0000-000000000002", g, s, a, 1, 2, c.recipients, c.body),
            GroupTextContent(c.id, b, s, a, 1, 2, c.recipients, c.body),
            GroupTextContent(c.id, g, b, a, 1, 2, c.recipients, c.body),
            GroupTextContent(c.id, g, s, b, 1, 2, c.recipients, c.body),
            content(sequence = 2),
            GroupTextContent(c.id, g, s, a, 1, 3, c.recipients, c.body),
            content(recipients = listOf(a)),
            content(body = "altro"),
        )
        for (other in alternatives) assertFalse(baseline.contentEquals(GroupTextCodec.signedBytes(other)))
    }

    @Test
    fun duplicateUnknownMissingAndWrongTypedFieldsFailClosed() {
        val json = GroupTextCodec.encode(message()).decodeToString()
        for (bad in listOf(
            json.replace("\"version\":1", "\"version\":1,\"version\":1"),
            json.replace("\"body\":", "\"other\":0,\"body\":"),
            json.replace("\"sequence\":1,", ""),
            json.replace("\"sequence\":1", "\"sequence\":\"1\""),
            json.replace("\"sequence\":1", "\"sequence\":1.0"),
            json.replace("\"version\":1", "\"version\":2"),
            json.replace("GROUP_TEXT", "TEXT"),
            json.replace("AQ==", "AR=="),
            json.replace("\"recipients\":[", "\"recipients\":[\"$a\","),
            json.replace("\"$b\"", "1".repeat(64)),
            json + "{}",
        )) assertFails(bad) { GroupTextCodec.decode(bad.encodeToByteArray()) }
    }

    @Test
    fun invalidUtf8DepthOversizeCountersAndContentAreRejected() {
        for (bad in listOf(byteArrayOf(-1), ByteArray(GroupTextCodec.MAX_BYTES + 1), "[[[]]]".encodeToByteArray())) {
            assertFails { GroupTextCodec.decode(bad) }
        }
        assertFails { content(sequence = 0) }
        assertFails { content(sequence = -1) }
        assertFails { content(body = "") }
        assertFails { content(body = "é".repeat(4097)) }
        assertFails { content(body = "\uD800") }
        assertFails { content(recipients = listOf(a, a)) }
        assertFails { content(recipients = listOf(b)) }
        assertTrue(GroupTextCodec.decode(GroupTextCodec.encode(SignedGroupText(content(body = "é".repeat(4096)), "AQ==")))
            .content.body.length == 4096)
        val tooMany = (0..1100).map { it.toString(16).padStart(64, '0') } + a
        assertFails { GroupTextCodec.encode(SignedGroupText(content(recipients = tooMany), "AQ==")) }
    }

    @Test
    fun longCountersAreExactAndDoNotRoundThroughFloatingPoint() {
        val content = GroupTextContent(content().id, g, s, a, Long.MAX_VALUE, Long.MAX_VALUE, listOf(a, b), "testo")
        val decoded = GroupTextCodec.decode(GroupTextCodec.encode(SignedGroupText(content, "AQ=="))).content
        assertEquals(Long.MAX_VALUE, decoded.authorSequence)
        assertEquals(Long.MAX_VALUE, decoded.logicalTime)
        val json = GroupTextCodec.encode(message()).decodeToString()
        for (value in listOf("9223372036854775808", "-1", "0", "1e3")) {
            assertFails { GroupTextCodec.decode(json.replace("\"sequence\":1", "\"sequence\":$value").encodeToByteArray()) }
        }
    }
}
