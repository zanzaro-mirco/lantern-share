package lantern.protocol

/** Directional v1 proof for the current transcript; not a persisted admission credential. */
data class ProtocolHandshakeApproval(val sender: String, val recipient: String, val signature: String) {
    init {
        require(Wire.isFingerprint(sender) && Wire.isFingerprint(recipient)) { "Invalid approval identity" }
        require(sender != recipient) { "Approval needs two distinct identities" }
        require(isValidSignature(signature)) { "Invalid approval signature encoding" }
    }

    companion object {
        const val MAX_SIGNATURE_LENGTH = ProtocolSignatureEncoding.MAX_LENGTH

        fun isValidSignature(value: String): Boolean = ProtocolSignatureEncoding.isValid(value)
    }
}
