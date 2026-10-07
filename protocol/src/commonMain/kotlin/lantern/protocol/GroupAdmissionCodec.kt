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

/**
 * Isolated versioned statement, not a signed credential or an active v0 frame.
 * All accepted IDs have one lowercase hexadecimal spelling. Group IDs represent random
 * 256-bit values; device IDs retain the SHA-256 certificate fingerprint representation.
 * Parsing proves neither randomness nor possession of an identity or group membership.
 */
object GroupAdmissionCodec {
    const val VERSION = 1
    const val MAX_BYTES = 512
    private const val SIGNING_DOMAIN = "lantern-group-admission-1"
    private val json = Json {
        ignoreUnknownKeys = false
        isLenient = false
    }

    fun encode(claim: GroupAdmissionClaim): ByteArray {
        validate(claim)
        return json.encodeToString(ClaimSerializer, claim).encodeToByteArray().also {
            require(it.size in 1..MAX_BYTES) { "Invalid group admission size" }
        }
    }

    fun decode(bytes: ByteArray): GroupAdmissionClaim = json.decodeFromString(
        ClaimSerializer,
        decodeBoundedProtocolJson(bytes, MAX_BYTES, maxDepth = 1),
    )

    /** Canonical bytes for OS signing/verifying, never the received JSON spelling. */
    fun signedBytes(claim: GroupAdmissionClaim): ByteArray {
        validate(claim)
        return listOf(SIGNING_DOMAIN, VERSION.toString(), claim.groupId, claim.issuerId, claim.memberId)
            .joinToString("") { "${it.encodeToByteArray().size}:$it" }
            .encodeToByteArray()
    }

    internal fun validate(claim: GroupAdmissionClaim) {
        require(Wire.isFingerprint(claim.groupId)) { "Invalid group identifier encoding" }
        require(Wire.isFingerprint(claim.issuerId) && Wire.isFingerprint(claim.memberId)) {
            "Invalid group admission identity encoding"
        }
        // GroupAdmissionClaim enforces distinct issuer/member independently of the codec.
    }

    internal object ClaimSerializer : KSerializer<GroupAdmissionClaim> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.GroupAdmissionClaimV1") {
            element<JsonPrimitive>("version")
            element<JsonPrimitive>("group")
            element<JsonPrimitive>("issuer")
            element<JsonPrimitive>("member")
        }

        override fun serialize(encoder: Encoder, value: GroupAdmissionClaim) {
            encoder.encodeStructure(descriptor) {
                encodeSerializableElement(descriptor, 0, JsonPrimitive.serializer(), JsonPrimitive(VERSION))
                encodeSerializableElement(descriptor, 1, JsonPrimitive.serializer(), JsonPrimitive(value.groupId))
                encodeSerializableElement(descriptor, 2, JsonPrimitive.serializer(), JsonPrimitive(value.issuerId))
                encodeSerializableElement(descriptor, 3, JsonPrimitive.serializer(), JsonPrimitive(value.memberId))
            }
        }

        override fun deserialize(decoder: Decoder): GroupAdmissionClaim = decoder.decodeStructure(descriptor) {
            var seen = 0
            val ids = Array(3) { "" }
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..3) throw SerializationException("Unknown group admission field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate group admission field")
                seen = seen or bit
                val value = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                if (index == 0) {
                    // Reject strings, alternate numeric spellings and unsupported versions.
                    if (value.isString || value.content != VERSION.toString()) {
                        throw SerializationException("Unsupported group admission version")
                    }
                } else {
                    if (!value.isString) throw SerializationException("Group admission IDs must be strings")
                    ids[index - 1] = value.content
                }
            }
            if (seen != 15) throw SerializationException("Missing group admission field")
            GroupAdmissionClaim(groupId = ids[0], issuerId = ids[1], memberId = ids[2]).also(::validate)
        }
    }
}
