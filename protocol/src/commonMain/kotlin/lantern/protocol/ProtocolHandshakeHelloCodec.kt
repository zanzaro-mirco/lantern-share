package lantern.protocol

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive

/** Isolated v1 HELLO payload, not an envelope accepted by the active v0 transport. */
object ProtocolHandshakeHelloCodec {
    const val MAX_BYTES = ProtocolCapabilitiesCodec.MAX_BYTES + 512
    private val json = Json {
        ignoreUnknownKeys = false
        isLenient = false
    }

    fun encode(participant: ProtocolHandshakeParticipant): ByteArray =
        json.encodeToString(HelloSerializer, participant).encodeToByteArray().also {
            require(it.size in 1..MAX_BYTES) { "Invalid HELLO size" }
        }

    fun decode(bytes: ByteArray): ProtocolHandshakeParticipant {
        return json.decodeFromString(HelloSerializer, decodeBoundedProtocolJson(bytes, MAX_BYTES, maxDepth = 3))
    }

    internal object HelloSerializer : KSerializer<ProtocolHandshakeParticipant> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.HandshakeHello") {
            element<JsonPrimitive>("identity")
            element<JsonPrimitive>("nonce")
            element("capabilities", ProtocolCapabilitiesCodec.OfferSerializer.descriptor)
        }

        override fun serialize(encoder: Encoder, value: ProtocolHandshakeParticipant) {
            encoder.encodeStructure(descriptor) {
                encodeSerializableElement(descriptor, 0, JsonPrimitive.serializer(), JsonPrimitive(value.identity))
                encodeSerializableElement(descriptor, 1, JsonPrimitive.serializer(), JsonPrimitive(value.nonce))
                encodeSerializableElement(descriptor, 2, ProtocolCapabilitiesCodec.OfferSerializer, value.capabilities)
            }
        }

        override fun deserialize(decoder: Decoder): ProtocolHandshakeParticipant = decoder.decodeStructure(descriptor) {
            var seen = 0
            var identity = ""
            var nonce = ""
            var capabilities: ProtocolCapabilities? = null
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..2) throw SerializationException("Unknown HELLO field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate HELLO field")
                seen = seen or bit
                when (index) {
                    0 -> identity = readString(decodeSerializableElement(descriptor, index, JsonPrimitive.serializer()))
                    1 -> nonce = readString(decodeSerializableElement(descriptor, index, JsonPrimitive.serializer()))
                    2 -> capabilities = decodeSerializableElement(descriptor, index, ProtocolCapabilitiesCodec.OfferSerializer)
                }
            }
            if (seen != 7) throw SerializationException("Missing HELLO field")
            ProtocolHandshakeParticipant(identity, nonce, requireNotNull(capabilities))
        }

        private fun readString(value: JsonPrimitive): String {
            if (!value.isString) throw SerializationException("HELLO identity and nonce must be strings")
            return value.content
        }
    }
}
