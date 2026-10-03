package lantern.protocol

/** Directional v1 proof for the current transcript; not a persisted admission credential. */
data class ProtocolHandshakeApproval(val sender: String, val recipient: String, val signature: String) {
    init {
        require(Wire.isFingerprint(sender) && Wire.isFingerprint(recipient)) { "Invalid approval identity" }
        require(sender != recipient) { "Approval needs two distinct identities" }
        require(isValidSignature(signature)) { "Invalid approval signature encoding" }
    }

    companion object {
        const val MAX_SIGNATURE_LENGTH = 256
        // Canonical padded standard Base64, including zero unused bits in the final sextet.
        // The OS verifier, not this syntax check, validates DER and the ECDSA signature.
        private val signaturePattern = Regex(
            "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?",
        )

        fun isValidSignature(value: String): Boolean =
            value.length in 4..MAX_SIGNATURE_LENGTH && value.matches(signaturePattern)
    }
}
