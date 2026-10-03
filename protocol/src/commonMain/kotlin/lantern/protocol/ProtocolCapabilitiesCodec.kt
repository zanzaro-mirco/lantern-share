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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

/** Isolated v1 offer format. Decoding does not authenticate or authorize the sender. */
object ProtocolCapabilitiesCodec {
    const val MAX_BYTES = 4096
    private val json = Json {
        ignoreUnknownKeys = false
        isLenient = false
    }

    fun encode(offer: ProtocolCapabilities): ByteArray =
        json.encodeToString(OfferSerializer, offer).encodeToByteArray().also {
            require(it.size in 1..MAX_BYTES) { "Invalid offer size" }
        }

    fun decode(bytes: ByteArray): ProtocolCapabilities {
        return json.decodeFromString(OfferSerializer, decodeBoundedProtocolJson(bytes, MAX_BYTES, maxDepth = 2))
    }

    // Streaming structure decoding preserves duplicate keys, unlike parsing to a JsonObject.
    internal object OfferSerializer : KSerializer<ProtocolCapabilities> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.CapabilitiesOffer") {
            element<JsonPrimitive>("version")
            element<JsonArray>("supportedFeatures")
            element<JsonArray>("requiredFeatures")
        }

        override fun serialize(encoder: Encoder, value: ProtocolCapabilities) {
            // Revalidate at the encoding boundary as well as at model construction.
            val checked = ProtocolCapabilities(value.version, value.supportedFeatures, value.requiredFeatures)
            encoder.encodeStructure(descriptor) {
                encodeSerializableElement(descriptor, 0, JsonPrimitive.serializer(), JsonPrimitive(checked.version))
                encodeSerializableElement(descriptor, 1, JsonArray.serializer(), features(checked.supportedFeatures))
                encodeSerializableElement(descriptor, 2, JsonArray.serializer(), features(checked.requiredFeatures))
            }
        }

        override fun deserialize(decoder: Decoder): ProtocolCapabilities = decoder.decodeStructure(descriptor) {
            var seen = 0
            var version = 0
            var supported = emptySet<String>()
            var required = emptySet<String>()
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..2) throw SerializationException("Unknown offer field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate offer field")
                seen = seen or bit
                when (index) {
                    0 -> {
                        val value = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                        if (value.isString || !value.content.matches(Regex("[1-9][0-9]{0,2}"))) {
                            throw SerializationException("Version must be an integer from 1 to 255")
                        }
                        version = value.content.toInt()
                    }
                    1 -> supported = readFeatures(decodeSerializableElement(descriptor, index, JsonArray.serializer()))
                    2 -> required = readFeatures(decodeSerializableElement(descriptor, index, JsonArray.serializer()))
                }
            }
            if (seen != 7) throw SerializationException("Missing offer field")
            ProtocolCapabilities(version, supported, required)
        }

        private fun features(values: Set<String>) = JsonArray(values.sorted().map { JsonPrimitive(it) })

        private fun readFeatures(values: JsonArray): Set<String> {
            val result = mutableSetOf<String>()
            for (value in values) {
                if (value !is JsonPrimitive || !value.isString) {
                    throw SerializationException("Feature must be a string")
                }
                if (!result.add(value.content)) throw SerializationException("Duplicate feature")
            }
            return result
        }
    }
}
