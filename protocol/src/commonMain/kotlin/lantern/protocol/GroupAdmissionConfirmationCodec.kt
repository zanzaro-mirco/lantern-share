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

/** Supplied attestation, not verified confirmation or a bootstrap APPROVE. */
data class GroupAdmissionConfirmation(val sender: String, val recipient: String, val signature: String) {
    init {
        require(Wire.isFingerprint(sender) && Wire.isFingerprint(recipient) && sender != recipient) {
            "Invalid group confirmation identities"
        }
        require(ProtocolSignatureEncoding.isValid(signature)) { "Invalid group confirmation signature encoding" }
    }
}

/** Isolated message codec: no routing through bootstrap or the active wire-v0 service. */
object GroupAdmissionConfirmationCodec {
    const val VERSION = 1
    const val MAX_BYTES = 1024
    private const val TYPE = "GROUP_CONFIRM"
    private val json = Json {
        ignoreUnknownKeys = false
        isLenient = false
    }

    fun encode(confirmation: GroupAdmissionConfirmation): ByteArray =
        json.encodeToString(ConfirmationSerializer, confirmation).encodeToByteArray().also {
            require(it.size in 1..MAX_BYTES) { "Invalid group confirmation size" }
        }

    /** Encoding does not acknowledge this ticket's transport write. */
    fun encode(request: GroupAdmissionConfirmationOperation.Send): ByteArray =
        encode(GroupAdmissionConfirmation(request.sender, request.recipient, request.signature))

    fun decode(bytes: ByteArray): GroupAdmissionConfirmation = json.decodeFromString(
        ConfirmationSerializer, decodeBoundedProtocolJson(bytes, MAX_BYTES, maxDepth = 1),
    )

    private object ConfirmationSerializer : KSerializer<GroupAdmissionConfirmation> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.GroupAdmissionConfirmationV1") {
            element<JsonPrimitive>("version")
            element<JsonPrimitive>("type")
            element<JsonPrimitive>("sender")
            element<JsonPrimitive>("recipient")
            element<JsonPrimitive>("signature")
        }

        override fun serialize(encoder: Encoder, value: GroupAdmissionConfirmation) = encoder.encodeStructure(descriptor) {
            val values = listOf(JsonPrimitive(VERSION), JsonPrimitive(TYPE), JsonPrimitive(value.sender),
                JsonPrimitive(value.recipient), JsonPrimitive(value.signature))
            values.forEachIndexed { index, primitive ->
                encodeSerializableElement(descriptor, index, JsonPrimitive.serializer(), primitive)
            }
        }

        override fun deserialize(decoder: Decoder): GroupAdmissionConfirmation = decoder.decodeStructure(descriptor) {
            var seen = 0
            val values = Array(3) { "" }
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..4) throw SerializationException("Unknown group confirmation field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate group confirmation field")
                seen = seen or bit
                val value = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                when (index) {
                    0 -> if (value.isString || value.content != VERSION.toString()) {
                        throw SerializationException("Unsupported group confirmation version")
                    }
                    1 -> if (!value.isString || value.content != TYPE) {
                        throw SerializationException("Unsupported group confirmation type")
                    }
                    else -> {
                        if (!value.isString) throw SerializationException("Group confirmation fields must be strings")
                        values[index - 2] = value.content
                    }
                }
            }
            if (seen != 31) throw SerializationException("Missing group confirmation field")
            GroupAdmissionConfirmation(values[0], values[1], values[2])
        }
    }
}
