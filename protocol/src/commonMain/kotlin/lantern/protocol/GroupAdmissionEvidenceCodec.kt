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

/** Public certificate bytes only. Syntax is checked here; DER, pin and key validity belong to OS adapters. */
data class GroupAdmissionCertificate(val identity: String, val der: String) {
    init {
        require(Wire.isFingerprint(identity)) { "Invalid admission certificate identity" }
        require(validCertificateEncoding(der)) { "Invalid admission certificate encoding" }
    }

    companion object {
        const val MAX_DER_BYTES = 4096
        const val MAX_ENCODED_LENGTH = ((MAX_DER_BYTES + 2) / 3) * 4
        private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

        // Linear, bounded scan: no recursive regex on peer-controlled kilobyte strings.
        private fun validCertificateEncoding(value: String): Boolean {
            if (value.length !in 4..MAX_ENCODED_LENGTH || value.length % 4 != 0) return false
            val padding = when {
                value.endsWith("==") -> 2
                value.endsWith("=") -> 1
                else -> 0
            }
            val contentLength = value.length - padding
            if ((value.length / 4) * 3 - padding > MAX_DER_BYTES) return false
            for (index in 0 until contentLength) if (ALPHABET.indexOf(value[index]) < 0) return false
            val last = ALPHABET.indexOf(value[contentLength - 1])
            return when (padding) {
                2 -> last and 15 == 0
                1 -> last and 3 == 0
                else -> true
            }
        }
    }
}

/** Untrusted, complete evidence for one proof. Never adopts its supplied anchor or grants membership. */
class GroupAdmissionEvidence(val proof: GroupAdmissionProof, certificates: List<GroupAdmissionCertificate>) {
    private val supplied: List<GroupAdmissionCertificate>
    val certificates: List<GroupAdmissionCertificate> get() = supplied.toList()

    init {
        require(certificates.size in 1..GroupAdmissionChainVerification.MAX_ADMISSIONS) {
            "Invalid admission certificate count"
        }
        supplied = certificates.toList()
        val identities = supplied.map { it.identity }
        require(identities.toSet().size == identities.size) { "Duplicate admission certificate identity" }
        require(identities.toSet() == proof.admissions.map { it.claim.issuerId }.toSet()) {
            "Admission certificates do not match proof issuers"
        }
    }
}

/** Isolated GROUP_EVIDENCE v1; distinct from HELLO/APPROVE/GROUP_CONFIRM and the active wire 0. */
object GroupAdmissionEvidenceCodec {
    const val VERSION = 1
    const val MAX_BYTES = 262144
    private const val TYPE = "GROUP_EVIDENCE"
    private val json = Json {
        ignoreUnknownKeys = false
        isLenient = false
    }

    @Throws(Exception::class)
    fun encode(evidence: GroupAdmissionEvidence): ByteArray =
        json.encodeToString(EvidenceSerializer, evidence).encodeToByteArray().also {
            require(it.size in 1..MAX_BYTES) { "Invalid group evidence size" }
        }

    @Throws(Exception::class)
    fun decode(bytes: ByteArray): GroupAdmissionEvidence = json.decodeFromString(
        EvidenceSerializer, decodeBoundedProtocolJson(bytes, MAX_BYTES, maxDepth = 5),
    )

    private object EvidenceSerializer : KSerializer<GroupAdmissionEvidence> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.GroupAdmissionEvidenceV1") {
            element<JsonPrimitive>("version")
            element<JsonPrimitive>("type")
            element("proof", GroupAdmissionProofCodec.ProofSerializer.descriptor)
            element("certificates", CertificatesSerializer.descriptor)
        }

        override fun serialize(encoder: Encoder, value: GroupAdmissionEvidence) = encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, JsonPrimitive.serializer(), JsonPrimitive(VERSION))
            encodeSerializableElement(descriptor, 1, JsonPrimitive.serializer(), JsonPrimitive(TYPE))
            encodeSerializableElement(descriptor, 2, GroupAdmissionProofCodec.ProofSerializer, value.proof)
            encodeSerializableElement(descriptor, 3, CertificatesSerializer, value.certificates.sortedBy { it.identity })
        }

        override fun deserialize(decoder: Decoder): GroupAdmissionEvidence = decoder.decodeStructure(descriptor) {
            var seen = 0
            var proof: GroupAdmissionProof? = null
            var certificates: List<GroupAdmissionCertificate>? = null
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..3) throw SerializationException("Unknown group evidence field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate group evidence field")
                seen = seen or bit
                when (index) {
                    0, 1 -> {
                        val value = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                        if (index == 0 && (value.isString || value.content != VERSION.toString())) {
                            throw SerializationException("Unsupported group evidence version")
                        }
                        if (index == 1 && (!value.isString || value.content != TYPE)) {
                            throw SerializationException("Unsupported group evidence type")
                        }
                    }
                    2 -> proof = decodeSerializableElement(descriptor, index, GroupAdmissionProofCodec.ProofSerializer)
                    3 -> certificates = decodeSerializableElement(descriptor, index, CertificatesSerializer)
                }
            }
            if (seen != 15) throw SerializationException("Missing group evidence field")
            GroupAdmissionEvidence(requireNotNull(proof), requireNotNull(certificates))
        }
    }

    private object CertificateSerializer : KSerializer<GroupAdmissionCertificate> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.GroupAdmissionCertificateV1") {
            element<JsonPrimitive>("identity")
            element<JsonPrimitive>("der")
        }

        override fun serialize(encoder: Encoder, value: GroupAdmissionCertificate) = encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, JsonPrimitive.serializer(), JsonPrimitive(value.identity))
            encodeSerializableElement(descriptor, 1, JsonPrimitive.serializer(), JsonPrimitive(value.der))
        }

        override fun deserialize(decoder: Decoder): GroupAdmissionCertificate = decoder.decodeStructure(descriptor) {
            var seen = 0
            val values = Array(2) { "" }
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..1) throw SerializationException("Unknown admission certificate field")
                val bit = 1 shl index
                if (seen and bit != 0) throw SerializationException("Duplicate admission certificate field")
                seen = seen or bit
                val value = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                if (!value.isString) throw SerializationException("Admission certificate fields must be strings")
                values[index] = value.content
            }
            if (seen != 3) throw SerializationException("Missing admission certificate field")
            GroupAdmissionCertificate(values[0], values[1])
        }
    }

    private object CertificatesSerializer : KSerializer<List<GroupAdmissionCertificate>> {
        override val descriptor = ListSerializer(CertificateSerializer).descriptor

        override fun serialize(encoder: Encoder, value: List<GroupAdmissionCertificate>) = encoder.encodeStructure(descriptor) {
            value.forEachIndexed { index, certificate ->
                encodeSerializableElement(descriptor, index, CertificateSerializer, certificate)
            }
        }

        override fun deserialize(decoder: Decoder): List<GroupAdmissionCertificate> = decoder.decodeStructure(descriptor) {
            val certificates = mutableListOf<GroupAdmissionCertificate>()
            val identities = mutableSetOf<String>()
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (certificates.size == GroupAdmissionChainVerification.MAX_ADMISSIONS) {
                    throw SerializationException("Too many admission certificates")
                }
                if (index != certificates.size) throw SerializationException("Invalid admission certificate index")
                val certificate = decodeSerializableElement(descriptor, index, CertificateSerializer)
                if (!identities.add(certificate.identity)) throw SerializationException("Duplicate admission certificate identity")
                certificates.add(certificate)
            }
            if (certificates.isEmpty()) throw SerializationException("Empty admission certificates")
            certificates
        }
    }
}
