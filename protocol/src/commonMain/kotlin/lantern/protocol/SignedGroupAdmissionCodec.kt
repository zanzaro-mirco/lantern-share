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
import lantern.domain.GroupAdmissionClaim

/** Supplied signature, NOT a verified credential or permission to persist trust. */
data class SignedGroupAdmission(val claim: GroupAdmissionClaim, val signature: String) {
    init {
        GroupAdmissionCodec.validate(claim)
        require(ProtocolSignatureEncoding.isValid(signature)) { "Invalid admission signature encoding" }
    }
}

/** Statement version is inside `claim`; no second, potentially contradictory version exists. */
object SignedGroupAdmissionCodec {
    const val MAX_BYTES = 1024
    private val json = Json {
        ignoreUnknownKeys = false
        isLenient = false
    }

    fun encode(admission: SignedGroupAdmission): ByteArray =
        json.encodeToString(AdmissionSerializer, admission).encodeToByteArray().also {
            require(it.size in 1..MAX_BYTES) { "Invalid signed admission size" }
        }

    fun decode(bytes: ByteArray): SignedGroupAdmission = json.decodeFromString(
        AdmissionSerializer,
        decodeBoundedProtocolJson(bytes, MAX_BYTES, maxDepth = 2),
    )

    internal object AdmissionSerializer : KSerializer<SignedGroupAdmission> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.SignedGroupAdmissionV1") {
            element("claim", GroupAdmissionCodec.ClaimSerializer.descriptor)
            element<JsonPrimitive>("signature")
        }

        override fun serialize(encoder: Encoder, value: SignedGroupAdmission) {
            encoder.encodeStructure(descriptor) {
                encodeSerializableElement(descriptor, 0, GroupAdmissionCodec.ClaimSerializer, value.claim)
                encodeSerializableElement(descriptor, 1, JsonPrimitive.serializer(), JsonPrimitive(value.signature))
            }
        }

        override fun deserialize(decoder: Decoder): SignedGroupAdmission = decoder.decodeStructure(descriptor) {
            var seen = 0
            var claim: GroupAdmissionClaim? = null
            var signature = ""
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..1) throw SerializationException("Unknown signed admission field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate signed admission field")
                seen = seen or bit
                when (index) {
                    0 -> claim = decodeSerializableElement(descriptor, index, GroupAdmissionCodec.ClaimSerializer)
                    1 -> {
                        val value = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                        if (!value.isString) throw SerializationException("Admission signature must be a string")
                        signature = value.content
                    }
                }
            }
            if (seen != 3) throw SerializationException("Missing signed admission field")
            SignedGroupAdmission(requireNotNull(claim), signature)
        }
    }
}
