package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ProtocolHandshakeFrameCodecTest {
    private val sender = "a".repeat(64)
    private val recipient = "b".repeat(64)
    private val hello = """{"identity":"$sender","nonce":"${"1".repeat(64)}","capabilities":{"version":1,"supportedFeatures":["text"],"requiredFeatures":[]}}"""
    private val approval = """{"sender":"$sender","recipient":"$recipient","signature":"cHJvb2Y="}"""
    private val helloFrame = """{"version":1,"type":"HELLO","hello":$hello}"""
    private val approvalFrame = """{"version":1,"type":"APPROVE","approval":$approval}"""

    @Test
    fun canonicalVectorsRoundTripAndDoNotDependOnFieldOrder() {
        for (vector in listOf(helloFrame, approvalFrame)) {
            assertEquals(vector, ProtocolHandshakeFrameCodec.encode(decode(vector)).decodeToString())
        }
        val reorderedHello = """{"hello":$hello,"type":"HELLO","version":1}"""
        val reorderedApproval = """{"approval":$approval,"version":1,"type":"APPROVE"}"""
        assertEquals(helloFrame, ProtocolHandshakeFrameCodec.encode(decode(reorderedHello)).decodeToString())
        assertEquals(decode(approvalFrame), decode(reorderedApproval))
    }

    @Test
    fun rejectsMissingUnknownDuplicateAndContradictoryEnvelopeFields() {
        val invalid = listOf(
            "{}", "[]", "null", "$helloFrame true",
            helloFrame.replace("\"version\":1,", ""),
            helloFrame.replace("\"type\":\"HELLO\",", ""),
            """{"version":1,"type":"HELLO"}""",
            helloFrame.replace("\"HELLO\"", "\"APPROVE\""),
            approvalFrame.replace("\"APPROVE\"", "\"HELLO\""),
            helloFrame.replace("\"HELLO\"", "\"TEXT\""),
            helloFrame.replace("\"version\":1", "\"extra\":false,\"version\":1"),
            helloFrame.replace("\"version\":1", "\"version\":1,\"version\":1"),
            helloFrame.replace("\"type\":\"HELLO\"", "\"type\":\"HELLO\",\"t\\u0079pe\":\"HELLO\""),
            helloFrame.replace("\"hello\":", "\"hello\":$hello,\"hello\":"),
            approvalFrame.replace("\"approval\":", "\"approval\":$approval,\"approval\":"),
            """{"version":1,"type":"HELLO","hello":$hello,"approval":$approval}""",
            """{"version":1,"type":"APPROVE","hello":$hello,"approval":$approval}""",
            helloFrame.replace(hello, "null"),
            approvalFrame.replace(approval, "null"),
            helloFrame.replace("\"identity\":", "\"identity\":\"$sender\",\"identity\":"),
            approvalFrame.replace("\"signature\":", "\"signature\":\"cHJvb2Y=\",\"signature\":"),
        )
        for (vector in invalid) assertFailsWith<IllegalArgumentException>(vector) { decode(vector) }
    }

    @Test
    fun bootstrapVersionAndTypeAreStrictAndDistinctFromOfferedVersion() {
        for (version in listOf("0", "2", "\"1\"", "1.0", "1e0", "null", "true", "[]")) {
            assertFailsWith<IllegalArgumentException>(version) { decode(helloFrame.replaceFirst("\"version\":1", "\"version\":$version")) }
        }
        for (type in listOf("null", "true", "1", "[]", "\"hello\"")) {
            assertFailsWith<IllegalArgumentException>(type) { decode(helloFrame.replace("\"HELLO\"", type)) }
        }
        val futureOffer = decode(helloFrame.replace("\"capabilities\":{\"version\":1", "\"capabilities\":{\"version\":2"))
        assertEquals(2, (futureOffer as ProtocolHandshakeFrame.Hello).participant.capabilities.version)
    }

    @Test
    fun boundsBytesDepthUtf8AndRejectsWireV0() {
        val exact = helloFrame + " ".repeat(ProtocolHandshakeFrameCodec.MAX_BYTES - helloFrame.encodeToByteArray().size)
        assertEquals(sender, (decode(exact) as ProtocolHandshakeFrame.Hello).participant.identity)
        assertFailsWith<IllegalArgumentException> { decode("$exact ") }
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeFrameCodec.decode(byteArrayOf()) }
        kotlin.test.assertFails { ProtocolHandshakeFrameCodec.decode(byteArrayOf(0xc3.toByte(), 0x28)) }
        val nested = "[".repeat(1500) + "0" + "]".repeat(1500)
        assertFailsWith<IllegalArgumentException> { decode(helloFrame.replace("[\"text\"]", nested)) }
        assertFailsWith<IllegalArgumentException> { Wire.decode(helloFrame.encodeToByteArray()) }
        assertFailsWith<IllegalArgumentException> { Wire.decode(approvalFrame.encodeToByteArray()) }
    }

    private fun decode(value: String) = ProtocolHandshakeFrameCodec.decode(value.encodeToByteArray())
}
