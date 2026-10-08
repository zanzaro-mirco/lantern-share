package lantern.protocol

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import lantern.domain.GroupTrustAnchor

/** Received proof, not a trusted anchor or verified membership. Owns its bounded path. */
class GroupAdmissionProof(val anchor: GroupTrustAnchor, admissions: List<SignedGroupAdmission>) {
    private val path: List<SignedGroupAdmission>
    val admissions: List<SignedGroupAdmission> get() = path.toList()

    init {
        require(Wire.isFingerprint(anchor.groupId) && Wire.isFingerprint(anchor.founderId)) {
            "Invalid proof anchor identifier encoding"
        }
        require(admissions.size in 1..GroupAdmissionChainVerification.MAX_ADMISSIONS) { "Invalid proof length" }
        path = admissions.toList()
    }
}

/** Isolated v1 envelope. Decoding must never adopt the supplied anchor as local trust. */
object GroupAdmissionProofCodec {
    const val VERSION = 1
    const val MAX_BYTES = 32768
    private val json = Json {
        ignoreUnknownKeys = false
        isLenient = false
    }

    fun encode(proof: GroupAdmissionProof): ByteArray =
        json.encodeToString(ProofSerializer, proof).encodeToByteArray().also {
            require(it.size in 1..MAX_BYTES) { "Invalid group proof size" }
        }

    fun decode(bytes: ByteArray): GroupAdmissionProof = json.decodeFromString(
        ProofSerializer, decodeBoundedProtocolJson(bytes, MAX_BYTES, maxDepth = 4),
    )

    private object ProofSerializer : KSerializer<GroupAdmissionProof> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.GroupAdmissionProofV1") {
            element<JsonPrimitive>("version")
            element("anchor", AnchorSerializer.descriptor)
            element("admissions", PathSerializer.descriptor)
        }

        override fun serialize(encoder: Encoder, value: GroupAdmissionProof) = encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, JsonPrimitive.serializer(), JsonPrimitive(VERSION))
            encodeSerializableElement(descriptor, 1, AnchorSerializer, value.anchor)
            encodeSerializableElement(descriptor, 2, PathSerializer, value.admissions)
        }

        override fun deserialize(decoder: Decoder): GroupAdmissionProof = decoder.decodeStructure(descriptor) {
            var seen = 0
            var anchor: GroupTrustAnchor? = null
            var admissions: List<SignedGroupAdmission>? = null
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..2) throw SerializationException("Unknown group proof field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate group proof field")
                seen = seen or bit
                when (index) {
                    0 -> {
                        val version = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                        if (version.isString || version.content != VERSION.toString()) {
                            throw SerializationException("Unsupported group proof version")
                        }
                    }
                    1 -> anchor = decodeSerializableElement(descriptor, index, AnchorSerializer)
                    2 -> admissions = decodeSerializableElement(descriptor, index, PathSerializer)
                }
            }
            if (seen != 7) throw SerializationException("Missing group proof field")
            GroupAdmissionProof(requireNotNull(anchor), requireNotNull(admissions))
        }
    }

    private object AnchorSerializer : KSerializer<GroupTrustAnchor> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.GroupProofAnchorV1") {
            element<JsonPrimitive>("group")
            element<JsonPrimitive>("founder")
        }

        override fun serialize(encoder: Encoder, value: GroupTrustAnchor) = encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, JsonPrimitive.serializer(), JsonPrimitive(value.groupId))
            encodeSerializableElement(descriptor, 1, JsonPrimitive.serializer(), JsonPrimitive(value.founderId))
        }

        override fun deserialize(decoder: Decoder): GroupTrustAnchor = decoder.decodeStructure(descriptor) {
            var seen = 0
            val ids = Array(2) { "" }
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..1) throw SerializationException("Unknown group proof anchor field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate group proof anchor field")
                seen = seen or bit
                val value = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                if (!value.isString || !Wire.isFingerprint(value.content)) {
                    throw SerializationException("Invalid group proof anchor identifier")
                }
                ids[index] = value.content
            }
            if (seen != 3) throw SerializationException("Missing group proof anchor field")
            GroupTrustAnchor(ids[0], ids[1])
        }
    }

    private object PathSerializer : KSerializer<List<SignedGroupAdmission>> {
        override val descriptor = ListSerializer(SignedGroupAdmissionCodec.AdmissionSerializer).descriptor

        override fun serialize(encoder: Encoder, value: List<SignedGroupAdmission>) = encoder.encodeStructure(descriptor) {
            value.forEachIndexed { index, admission ->
                encodeSerializableElement(descriptor, index, SignedGroupAdmissionCodec.AdmissionSerializer, admission)
            }
        }

        override fun deserialize(decoder: Decoder): List<SignedGroupAdmission> = decoder.decodeStructure(descriptor) {
            val path = mutableListOf<SignedGroupAdmission>()
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (path.size == GroupAdmissionChainVerification.MAX_ADMISSIONS) {
                    throw SerializationException("Too many group proof admissions")
                }
                if (index != path.size) throw SerializationException("Invalid group proof admission index")
                path.add(decodeSerializableElement(descriptor, index, SignedGroupAdmissionCodec.AdmissionSerializer))
            }
            if (path.isEmpty()) throw SerializationException("Empty group proof path")
            path
        }
    }
}
