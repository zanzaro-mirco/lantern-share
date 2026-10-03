package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class ProtocolCapabilitiesCodecTest {
    private val vector = """{"version":1,"supportedFeatures":["receipts","text"],"requiredFeatures":["text"]}"""

    @Test
    fun canonicalVectorAndRoundTrip() {
        val offer = ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text"))
        assertEquals(vector, ProtocolCapabilitiesCodec.encode(offer).decodeToString())
        val decoded = decode(vector)
        assertEquals(offer.version, decoded.version)
        assertEquals(offer.supportedFeatures, decoded.supportedFeatures)
        assertEquals(offer.requiredFeatures, decoded.requiredFeatures)
        assertEquals(vector, ProtocolCapabilitiesCodec.encode(decoded).decodeToString())
    }

    @Test
    fun acceptsReorderedFieldsWhitespaceAndFutureVersionWithoutNegotiatingIt() {
        val offer = decode(""" { "requiredFeatures": [], "supportedFeatures": ["text"], "version": 2 } """)
        assertEquals(2, offer.version)
        assertEquals(
            ProtocolNegotiationResult.Incompatible(ProtocolIncompatibility.UNSUPPORTED_VERSION),
            ProtocolNegotiation.negotiate(offer, offer),
        )
        val empty = decode("""{"version":1,"supportedFeatures":[],"requiredFeatures":[]}""")
        assertTrue(empty.supportedFeatures.isEmpty())
    }

    @Test
    fun rejectsMissingUnknownDuplicateAndMalformedFields() {
        val invalid = listOf(
            "{}", "[]", "null", "$vector true", vector.dropLast(1),
            vector.replace("\"version\":1,", ""),
            vector.replace("\"supportedFeatures\":[\"receipts\",\"text\"],", ""),
            vector.replace(",\"requiredFeatures\":[\"text\"]", ""),
            vector.replace("\"version\":1", "\"version\":1,\"extra\":false"),
            vector.replace("\"version\":1", "\"version\":1,\"version\":2"),
            vector.replace("\"version\":1", "\"version\":1,\"ver\\u0073ion\":1"),
            vector.replace("[\"text\"]", "[\"text\",\"text\"]"),
            vector.replace("[\"receipts\",\"text\"]", "[\"text\",\"te\\u0078t\"]"),
            vector.replace("[\"text\"]", "[\"missing\"]"),
            vector.replace("[\"text\"]", "null"),
            vector.replace("[\"text\"]", "[true]"),
            vector.replace("[\"text\"]", "[123]"),
            vector.replace("[\"text\"]", "[[]]"),
            vector.replace("\"text\"", "\"TEXT\""),
        )
        for (input in invalid) assertFails(input) { decode(input) }
    }

    @Test
    fun rejectsInvalidVersionTypesAndRanges() {
        for (version in listOf("0", "256", "-1", "1.0", "1e0", "\"1\"", "true", "null", "[]", "2147483648")) {
            assertFails(version) { decode(vector.replace("\"version\":1", "\"version\":$version")) }
        }
    }

    @Test
    fun enforcesFeatureAndByteLimitsAndStrictUtf8() {
        val maximum = ProtocolCapabilities(255, (1..32).map { "feature-$it" }.toSet())
        assertEquals(maximum.supportedFeatures, ProtocolCapabilitiesCodec.decode(ProtocolCapabilitiesCodec.encode(maximum)).supportedFeatures)
        val tooMany = (1..33).joinToString(",") { "\"feature-$it\"" }
        assertFails { decode("""{"version":1,"supportedFeatures":[$tooMany],"requiredFeatures":[]}""") }
        assertFails { decode(vector.replace("\"text\"", "\"${"a".repeat(33)}\"")) }
        val exact = vector + " ".repeat(ProtocolCapabilitiesCodec.MAX_BYTES - vector.encodeToByteArray().size)
        assertEquals(1, decode(exact).version)
        assertFails { decode("$exact ") }
        assertFails { ProtocolCapabilitiesCodec.decode(byteArrayOf()) }
        assertFails { ProtocolCapabilitiesCodec.decode(byteArrayOf(0xc3.toByte(), 0x28)) }
    }

    private fun decode(value: String) = ProtocolCapabilitiesCodec.decode(value.encodeToByteArray())
}
