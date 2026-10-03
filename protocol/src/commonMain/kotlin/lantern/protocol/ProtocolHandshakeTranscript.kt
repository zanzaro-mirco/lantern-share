package lantern.protocol

/** An offer bound to one identity and a fresh nonce; not proof of possession or trust. */
class ProtocolHandshakeParticipant(
    val identity: String,
    val nonce: String,
    capabilities: ProtocolCapabilities,
) {
    val capabilities = ProtocolCapabilities(
        capabilities.version,
        capabilities.supportedFeatures,
        capabilities.requiredFeatures,
    )

    init {
        require(Wire.isFingerprint(identity)) { "Invalid handshake identity" }
        require(Wire.isFingerprint(nonce)) { "Invalid handshake nonce" }
    }
}

/** Canonical v1 bytes only. Hashing/signing and identity verification belong to OS adapters. */
object ProtocolHandshakeTranscript {
    fun bytes(first: ProtocolHandshakeParticipant, second: ProtocolHandshakeParticipant): ByteArray {
        require(first.identity != second.identity) { "Handshake needs two distinct identities" }
        val participants = listOf(first, second).sortedBy { it.identity }
        return fields(
            listOf("lantern-handshake-1") + participants.flatMap {
                listOf(it.identity, it.nonce, ProtocolCapabilitiesCodec.encode(it.capabilities).decodeToString())
            },
        )
    }

    /** Directional confirmation: a signature from one peer cannot be reflected as the other's. */
    fun approvalBytes(
        sender: ProtocolHandshakeParticipant,
        recipient: ProtocolHandshakeParticipant,
    ): ByteArray = fields(
        listOf("lantern-handshake-approve-1", sender.identity, recipient.identity, bytes(sender, recipient).decodeToString()),
    )

    // Each field has an ASCII decimal UTF-8 byte count followed by ':' and exactly that many bytes.
    // A colon inside a field does not act as a delimiter.
    private fun fields(values: List<String>): ByteArray = values.joinToString("") {
        "${it.encodeToByteArray().size}:$it"
    }.encodeToByteArray()
}
