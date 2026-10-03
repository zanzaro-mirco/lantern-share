package lantern.protocol

/** Bound parser recursion before kotlinx.serialization materializes any nested JSON elements. */
internal fun decodeBoundedProtocolJson(bytes: ByteArray, maxBytes: Int, maxDepth: Int): String {
    require(bytes.size in 1..maxBytes) { "Invalid protocol JSON size" }
    val text = bytes.decodeToString(throwOnInvalidSequence = true)
    var depth = 0
    var quoted = false
    var escaped = false
    for (character in text) {
        if (quoted) {
            if (escaped) {
                escaped = false
            } else {
                when (character) {
                    '\\' -> escaped = true
                    '"' -> quoted = false
                }
            }
        } else {
            when (character) {
                '"' -> quoted = true
                '{', '[' -> {
                    depth++
                    require(depth <= maxDepth) { "Protocol JSON is too deeply nested" }
                }
                '}', ']' -> {
                    depth--
                    require(depth >= 0) { "Unbalanced protocol JSON" }
                }
            }
        }
    }
    // This is a depth guard, not another JSON parser; syntax and field validation remain in the codec.
    return text
}
