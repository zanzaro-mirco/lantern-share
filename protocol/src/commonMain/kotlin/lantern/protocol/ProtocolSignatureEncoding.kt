package lantern.protocol

/** Canonical Base64 syntax only; DER/ECDSA validity must be checked by an OS verifier. */
internal object ProtocolSignatureEncoding {
    const val MAX_LENGTH = 256
    private val pattern = Regex(
        "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?",
    )

    fun isValid(value: String): Boolean = value.length in 4..MAX_LENGTH && value.matches(pattern)
}
