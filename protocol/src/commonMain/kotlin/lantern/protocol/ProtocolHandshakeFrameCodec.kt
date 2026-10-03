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

/** Bootstrap handshake messages only, not the full v1 event/session envelope. */
sealed interface ProtocolHandshakeFrame {
    data class Hello(val participant: ProtocolHandshakeParticipant) : ProtocolHandshakeFrame
    data class Approve(val approval: ProtocolHandshakeApproval) : ProtocolHandshakeFrame
}

/** Separate v1 bootstrap codec. No active service accepts these frames. */
object ProtocolHandshakeFrameCodec {
    const val VERSION = 1
    const val MAX_BYTES = ProtocolHandshakeHelloCodec.MAX_BYTES + 512
    private val json = Json {
        ignoreUnknownKeys = false
        isLenient = false
    }

    fun encode(frame: ProtocolHandshakeFrame): ByteArray =
        json.encodeToString(FrameSerializer, frame).encodeToByteArray().also {
            require(it.size in 1..MAX_BYTES) { "Invalid handshake frame size" }
        }

    fun decode(bytes: ByteArray): ProtocolHandshakeFrame =
        json.decodeFromString(FrameSerializer, decodeBoundedProtocolJson(bytes, MAX_BYTES, maxDepth = 4))

    private object FrameSerializer : KSerializer<ProtocolHandshakeFrame> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.HandshakeFrame") {
            element<JsonPrimitive>("version")
            element<JsonPrimitive>("type")
            element("hello", ProtocolHandshakeHelloCodec.HelloSerializer.descriptor, isOptional = true)
            element("approval", ProtocolHandshakeApprovalCodec.ApprovalSerializer.descriptor, isOptional = true)
        }

        override fun serialize(encoder: Encoder, value: ProtocolHandshakeFrame) {
            encoder.encodeStructure(descriptor) {
                encodeSerializableElement(descriptor, 0, JsonPrimitive.serializer(), JsonPrimitive(VERSION))
                when (value) {
                    is ProtocolHandshakeFrame.Hello -> {
                        encodeSerializableElement(descriptor, 1, JsonPrimitive.serializer(), JsonPrimitive("HELLO"))
                        encodeSerializableElement(descriptor, 2, ProtocolHandshakeHelloCodec.HelloSerializer, value.participant)
                    }
                    is ProtocolHandshakeFrame.Approve -> {
                        encodeSerializableElement(descriptor, 1, JsonPrimitive.serializer(), JsonPrimitive("APPROVE"))
                        encodeSerializableElement(descriptor, 3, ProtocolHandshakeApprovalCodec.ApprovalSerializer, value.approval)
                    }
                }
            }
        }

        override fun deserialize(decoder: Decoder): ProtocolHandshakeFrame = decoder.decodeStructure(descriptor) {
            var seen = 0
            var type = ""
            var hello: ProtocolHandshakeParticipant? = null
            var approval: ProtocolHandshakeApproval? = null
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..3) throw SerializationException("Unknown handshake frame field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate handshake frame field")
                seen = seen or bit
                when (index) {
                    0 -> {
                        val version = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                        if (version.isString || version.content != VERSION.toString()) {
                            throw SerializationException("Unsupported handshake frame version")
                        }
                    }
                    1 -> {
                        val value = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                        if (!value.isString) throw SerializationException("Handshake frame type must be a string")
                        type = value.content
                    }
                    2 -> hello = decodeSerializableElement(descriptor, index, ProtocolHandshakeHelloCodec.HelloSerializer)
                    3 -> approval = decodeSerializableElement(descriptor, index, ProtocolHandshakeApprovalCodec.ApprovalSerializer)
                }
            }
            when {
                seen == 7 && type == "HELLO" -> ProtocolHandshakeFrame.Hello(requireNotNull(hello))
                seen == 11 && type == "APPROVE" -> ProtocolHandshakeFrame.Approve(requireNotNull(approval))
                else -> throw SerializationException("Missing or contradictory handshake frame fields")
            }
        }
    }
}
