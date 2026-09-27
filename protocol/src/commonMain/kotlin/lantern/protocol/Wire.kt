package lantern.protocol

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import lantern.domain.ContentLimits

@Serializable
enum class FrameType { HELLO, APPROVE, TEXT, ACK }

@Serializable
data class Frame(
    val version: Int = 0,
    val type: FrameType,
    val sender: String,
    val nonce: String = "",
    val id: String = "",
    val session: String = "",
    val body: String = "",
    val signature: String = "",
)

object Wire {
    const val MAX_FRAME = 65536
    private val fingerprintPattern = Regex("[0-9a-f]{64}")
    private val messageIdPattern = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = false
        isLenient = false
    }

    fun encode(frame: Frame): ByteArray = json.encodeToString(frame).encodeToByteArray().also {
        require(it.size in 1..MAX_FRAME)
    }

    fun decode(bytes: ByteArray): Frame {
        require(bytes.size in 1..MAX_FRAME)
        val f = json.decodeFromString<Frame>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(f.version == 0)
        require(isFingerprint(f.sender))
        when (f.type) {
            FrameType.HELLO -> require(isFingerprint(f.nonce))
            FrameType.TEXT -> require(
                f.id.matches(messageIdPattern) && ContentLimits.isValidText(f.body) &&
                    f.signature.length in 1..256 && isFingerprint(f.session)
            )
            FrameType.APPROVE -> require(
                isFingerprint(f.session) && isFingerprint(f.body) && f.signature.length in 1..256
            )
            FrameType.ACK -> require(f.id.matches(messageIdPattern))
        }
        return f
    }
    fun isFingerprint(value: String): Boolean = value.matches(fingerprintPattern)

    fun signedBytes(f: Frame): ByteArray = listOf("lantern-0", f.type.name, f.sender, f.id, f.session, f.body)
        .joinToString("") { "${it.encodeToByteArray().size}:$it" }.encodeToByteArray()

    fun transcript(idA: String, nonceA: String, idB: String, nonceB: String): String {
        require(idA != idB)
        return if (idA < idB) "lantern-pair-0|$idA|$nonceA|$idB|$nonceB" else "lantern-pair-0|$idB|$nonceB|$idA|$nonceA"
    }
}
