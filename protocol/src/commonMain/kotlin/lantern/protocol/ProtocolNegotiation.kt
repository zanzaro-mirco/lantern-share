package lantern.protocol

/** Capabilities for one protocol version, not an authorization or a wire frame. */
class ProtocolCapabilities(
    val version: Int,
    supportedFeatures: Set<String>,
    requiredFeatures: Set<String> = emptySet(),
) {
    val supportedFeatures: Set<String> = supportedFeatures.toSet()
    val requiredFeatures: Set<String> = requiredFeatures.toSet()

    init {
        require(version in 1..255) { "Invalid protocol version" }
        require(this.supportedFeatures.size <= MAX_FEATURES) { "Too many protocol features" }
        require(this.supportedFeatures.all { it.matches(FEATURE_NAME) }) { "Invalid protocol feature" }
        require(this.supportedFeatures.containsAll(this.requiredFeatures)) { "Required feature is not supported" }
    }

    private companion object {
        const val MAX_FEATURES = 32
        val FEATURE_NAME = Regex("[a-z][a-z0-9-]{0,31}")
    }
}

enum class ProtocolIncompatibility {
    UNSUPPORTED_VERSION,
    REQUIRED_FEATURE_MISSING,
}

sealed interface ProtocolNegotiationResult {
    data class Compatible(val version: Int, val features: Set<String>) : ProtocolNegotiationResult
    data class Incompatible(val reason: ProtocolIncompatibility) : ProtocolNegotiationResult
}

/** Pure v1 rule. Never falls back to v0 and never grants trust to the peer. */
object ProtocolNegotiation {
    const val VERSION = 1

    fun negotiate(local: ProtocolCapabilities, remote: ProtocolCapabilities): ProtocolNegotiationResult {
        if (local.version != VERSION || remote.version != VERSION) {
            return ProtocolNegotiationResult.Incompatible(ProtocolIncompatibility.UNSUPPORTED_VERSION)
        }
        val commonFeatures = local.supportedFeatures.intersect(remote.supportedFeatures)
        if (!commonFeatures.containsAll(local.requiredFeatures) ||
            !commonFeatures.containsAll(remote.requiredFeatures)
        ) {
            return ProtocolNegotiationResult.Incompatible(ProtocolIncompatibility.REQUIRED_FEATURE_MISSING)
        }
        return ProtocolNegotiationResult.Compatible(VERSION, commonFeatures.sorted().toSet())
    }
}
