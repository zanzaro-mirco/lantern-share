package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith

class ProtocolHandshakeHelloCodecTest {
    private val identity = "a".repeat(64)
    private val nonce = "1".repeat(64)
    private val offer = """{"version":1,"supportedFeatures":["receipts","text"],"requiredFeatures":["text"]}"""
    private val vector = """{"identity":"$identity","nonce":"$nonce","capabilities":$offer}"""

    @Test
    fun canonicalHelloRoundTripsWithoutChangingTranscript() {
        val participant = ProtocolHandshakeParticipant(identity, nonce, ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text")))
        assertEquals(vector, ProtocolHandshakeHelloCodec.encode(participant).decodeToString())
        val decoded = decode(vector)
        assertEquals(identity, decoded.identity)
        assertEquals(nonce, decoded.nonce)
        assertEquals(participant.capabilities.supportedFeatures, decoded.capabilities.supportedFeatures)
        assertEquals(participant.capabilities.requiredFeatures, decoded.capabilities.requiredFeatures)
        assertEquals(vector, ProtocolHandshakeHelloCodec.encode(decoded).decodeToString())
        val other = ProtocolHandshakeParticipant("b".repeat(64), "2".repeat(64), ProtocolCapabilities(1, setOf("text")))
        assertContentEquals(ProtocolHandshakeTranscript.bytes(participant, other), ProtocolHandshakeTranscript.bytes(decoded, other))
    }

    @Test
    fun acceptsReorderingAndFutureOfferButDoesNotNegotiateOrAuthorize() {
        val decoded = decode(""" { "capabilities": $offer, "nonce": "$nonce", "identity": "$identity" } """)
        assertEquals(vector, ProtocolHandshakeHelloCodec.encode(decoded).decodeToString())
        assertEquals(2, decode(vector.replace("\"version\":1", "\"version\":2")).capabilities.version)
    }

    @Test
    fun rejectsDuplicateAndUnknownFieldsIncludingInsideCapabilities() {
        val invalid = listOf(
            vector.replace("\"identity\":", "\"identity\":\"$identity\",\"identity\":"),
            vector.replace("\"nonce\":", "\"nonce\":\"$nonce\",\"nonce\":"),
            vector.replace("\"capabilities\":", "\"capabilities\":$offer,\"capabilities\":"),
            vector.replace("\"identity\":", "\"ident\\u0069ty\":\"$identity\",\"identity\":"),
            vector.replace("\"identity\":", "\"extra\":false,\"identity\":"),
            vector.replace("\"version\":1", "\"version\":1,\"version\":1"),
            vector.replace("\"version\":1", "\"extra\":true,\"version\":1"),
            vector.replace("[\"text\"]", "[\"text\",\"te\\u0078t\"]"),
        )
        for (input in invalid) assertFails(input) { decode(input) }
    }

    @Test
    fun rejectsMissingMalformedAndWronglyTypedFields() {
        val invalid = listOf(
            "{}", "[]", "null", "$vector true", vector.dropLast(1),
            vector.replace("\"identity\":\"$identity\",", ""),
            vector.replace("\"nonce\":\"$nonce\",", ""),
            vector.replace(",\"capabilities\":$offer", ""),
            vector.replace("\"$nonce\"", nonce),
            vector.replace("\"$identity\"", "null"),
            vector.replace("\"$identity\"", "true"),
            vector.replace("\"$identity\"", "[]"),
            vector.replace("\"$identity\"", "\"${identity.uppercase()}\""),
            vector.replace("\"$nonce\"", "\"invalid\""),
            vector.replace(offer, "null"),
            vector.replace(offer, "[]"),
            vector.replace(offer, "{}"),
            vector.replace("\"text\"", "\"missing\"").replace("[\"receipts\",\"missing\"]", "[\"text\"]"),
        )
        for (input in invalid) assertFails(input) { decode(input) }
    }

    @Test
    fun boundsInputAndKeepsStrictUtf8AndModelLimits() {
        val maximumFeatures = (0..31).map { "f" + it.toString().padStart(31, '0') }.toSet()
        val participant = ProtocolHandshakeParticipant(identity, nonce, ProtocolCapabilities(255, maximumFeatures, maximumFeatures))
        val maximum = ProtocolHandshakeHelloCodec.encode(participant)
        assertEquals(maximumFeatures, ProtocolHandshakeHelloCodec.decode(maximum).capabilities.requiredFeatures)
        val exact = vector + " ".repeat(ProtocolHandshakeHelloCodec.MAX_BYTES - vector.encodeToByteArray().size)
        assertEquals(identity, decode(exact).identity)
        assertFails { decode("$exact ") }
        assertFails { ProtocolHandshakeHelloCodec.decode(byteArrayOf()) }
        assertFails { ProtocolHandshakeHelloCodec.decode(byteArrayOf(0xc3.toByte(), 0x28)) }
        val tooMany = (1..33).joinToString(",") { "\"feature-$it\"" }
        assertFails { decode(vector.replace("[\"receipts\",\"text\"]", "[$tooMany]")) }
    }

    @Test
    fun deeplyNestedCapabilitiesFailAsInputErrorsRatherThanRuntimeErrors() {
        val nested = "[".repeat(1500) + "0" + "]".repeat(1500)
        assertFailsWith<IllegalArgumentException> { decode(vector.replace("[\"text\"]", nested)) }
        assertFailsWith<IllegalArgumentException> { decode(vector.replace(offer, nested)) }
    }

    @Test
    fun isolatedHelloPayloadIsNotAcceptedByActiveWireV0() {
        assertFailsWith<IllegalArgumentException> { Wire.decode(vector.encodeToByteArray()) }
    }

    private fun decode(value: String) = ProtocolHandshakeHelloCodec.decode(value.encodeToByteArray())
}
