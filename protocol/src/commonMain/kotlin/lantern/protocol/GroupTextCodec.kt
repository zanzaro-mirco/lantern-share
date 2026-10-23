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
import lantern.domain.GroupTextContent
import lantern.domain.SignedGroupText

/**
 * New isolated envelope; not accepted on wire 0, B4 or diagnostic B5.
 * Transport integration must negotiate a separate capability before using these bytes.
 */
object GroupTextCodec {
    const val MAX_BYTES = 65536
    private val json = Json { ignoreUnknownKeys = false; isLenient = false }
    private val recipientsSerializer = ListSerializer(JsonPrimitive.serializer())

    @Throws(Exception::class)
    fun encode(message: SignedGroupText): ByteArray {
        require(ProtocolSignatureEncoding.isValid(message.signature)) { "Invalid group text signature encoding" }
        return json.encodeToString(Serializer, message).encodeToByteArray().also {
            require(it.size in 1..MAX_BYTES) { "Group text envelope too large" }
        }
    }

    @Throws(Exception::class)
    fun decode(bytes: ByteArray): SignedGroupText = json.decodeFromString(
        Serializer, decodeBoundedProtocolJson(bytes, MAX_BYTES, maxDepth = 2),
    )

    /** Domain-separated, length-prefixed UTF-8; recipient order is canonical and signed. */
    @Throws(Exception::class)
    fun signedBytes(content: GroupTextContent): ByteArray = buildList {
        add("lantern-group-text-1")
        add(content.id)
        add(content.groupId)
        add(content.sessionId)
        add(content.authorId)
        add(content.authorSequence.toString())
        add(content.logicalTime.toString())
        add(content.recipients.size.toString())
        addAll(content.recipients)
        add(content.body)
    }.joinToString("") { "${it.encodeToByteArray().size}:$it" }.encodeToByteArray().also {
        require(it.size <= MAX_BYTES) { "Group text signing input too large" }
    }

    private object Serializer : KSerializer<SignedGroupText> {
        override val descriptor = buildClassSerialDescriptor("lantern.protocol.GroupTextV1") {
            element<JsonPrimitive>("version")
            element<JsonPrimitive>("type")
            element<JsonPrimitive>("id")
            element<JsonPrimitive>("group")
            element<JsonPrimitive>("session")
            element<JsonPrimitive>("author")
            element<JsonPrimitive>("sequence")
            element<JsonPrimitive>("logicalTime")
            element("recipients", recipientsSerializer.descriptor)
            element<JsonPrimitive>("body")
            element<JsonPrimitive>("signature")
        }

        override fun serialize(encoder: Encoder, value: SignedGroupText) = encoder.encodeStructure(descriptor) {
            val c = value.content
            fun field(index: Int, primitive: JsonPrimitive) {
                encodeSerializableElement(descriptor, index, JsonPrimitive.serializer(), primitive)
            }
            field(0, JsonPrimitive(1))
            field(1, JsonPrimitive("GROUP_TEXT"))
            field(2, JsonPrimitive(c.id))
            field(3, JsonPrimitive(c.groupId))
            field(4, JsonPrimitive(c.sessionId))
            field(5, JsonPrimitive(c.authorId))
            field(6, JsonPrimitive(c.authorSequence))
            field(7, JsonPrimitive(c.logicalTime))
            encodeSerializableElement(descriptor, 8, recipientsSerializer, c.recipients.map(::JsonPrimitive))
            field(9, JsonPrimitive(c.body))
            field(10, JsonPrimitive(value.signature))
        }

        override fun deserialize(decoder: Decoder): SignedGroupText = decoder.decodeStructure(descriptor) {
            val values = Array(11) { "" }
            var recipients: List<String>? = null
            var seen = 0
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) break
                if (index !in 0..10 || seen and (1 shl index) != 0) throw SerializationException("Invalid group text fields")
                seen = seen or (1 shl index)
                if (index == 8) {
                    recipients = decodeSerializableElement(descriptor, index, recipientsSerializer).map {
                        if (!it.isString) throw SerializationException("Group text recipients must be strings")
                        it.content
                    }
                } else {
                    val primitive = decodeSerializableElement(descriptor, index, JsonPrimitive.serializer())
                    val numeric = index == 0 || index == 6 || index == 7
                    if (primitive.isString == numeric) throw SerializationException("Invalid group text field type")
                    values[index] = primitive.content
                }
            }
            if (seen != 2047 || values[0] != "1" || values[1] != "GROUP_TEXT") throw SerializationException("Invalid group text envelope")
            fun counter(index: Int): Long {
                val value = values[index].toLongOrNull() ?: throw SerializationException("Invalid group text counter")
                if (value <= 0 || value.toString() != values[index]) throw SerializationException("Invalid group text counter")
                return value
            }
            require(ProtocolSignatureEncoding.isValid(values[10])) { "Invalid group text signature encoding" }
            SignedGroupText(GroupTextContent(values[2], values[3], values[4], values[5], counter(6), counter(7),
                requireNotNull(recipients), values[9]), values[10])
        }
    }
}
