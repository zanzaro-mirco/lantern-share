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

/** Isolated v1 APPROVE payload, deliberately not accepted as a v0 frame. */
object ProtocolHandshakeApprovalCodec {
    const val MAX_BYTES = 1024
    private val json = Json {
        ignoreUnknownKeys = false
        isLenient = false
    }

    fun encode(approval: ProtocolHandshakeApproval): ByteArray =
        json.encodeToString(ApprovalSerializer, approval).encodeToByteArray().also {
            require(it.size in 1..MAX_BYTES) { "Invalid APPROVE size" }
        }

    fun decode(bytes: ByteArray): ProtocolHandshakeApproval =
        json.decodeFromString(ApprovalSerializer, decodeBoundedProtocolJson(bytes, MAX_BYTES, maxDepth = 1))

    internal object ApprovalSerializer : KSerializer<ProtocolHandshakeApproval> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.HandshakeApproval") {
            element<JsonPrimitive>("sender")
            element<JsonPrimitive>("recipient")
            element<JsonPrimitive>("signature")
        }

        override fun serialize(encoder: Encoder, value: ProtocolHandshakeApproval) {
            encoder.encodeStructure(descriptor) {
                encodeSerializableElement(descriptor, 0, JsonPrimitive.serializer(), JsonPrimitive(value.sender))
                encodeSerializableElement(descriptor, 1, JsonPrimitive.serializer(), JsonPrimitive(value.recipient))
                encodeSerializableElement(descriptor, 2, JsonPrimitive.serializer(), JsonPrimitive(value.signature))
            }
        }

        override fun deserialize(decoder: Decoder): ProtocolHandshakeApproval = decoder.decodeStructure(descriptor) {
            var seen = 0
            val values = Array(3) { "" }
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in values.indices) throw SerializationException("Unknown APPROVE field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate APPROVE field")
                seen = seen or bit
                val value = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                if (!value.isString) throw SerializationException("APPROVE fields must be strings")
                values[index] = value.content
            }
            if (seen != 7) throw SerializationException("Missing APPROVE field")
            ProtocolHandshakeApproval(sender = values[0], recipient = values[1], signature = values[2])
        }
    }
}
