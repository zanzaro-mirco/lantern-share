package lantern.domain

import kotlinx.coroutines.flow.StateFlow

data class Peer(val id: String, val name: String, val host: String, val port: Int)
data class ChatLine(val id: String, val sender: String, val text: String, val received: Boolean = false)
data class DeviceState(
    val name: String = "",
    val id: String = "",
    val active: Boolean = false,
    val peers: List<Peer> = emptyList(),
    val trusted: Set<String> = emptySet(),
    val connected: Set<String> = emptySet(),
    val pairingPeer: String? = null,
    val comparisonCode: String? = null,
    val messages: List<ChatLine> = emptyList(),
    val status: String = "Servizio arrestato",
)

interface DeviceController {
    val state: StateFlow<DeviceState>
    fun rename(name: String)
    fun start()
    fun stop()
    fun pair(peer: Peer)
    fun confirm()
    fun reject()
    fun send(peerId: String, text: String)
    fun block(peerId: String)
}
interface DiscoveryService {
    fun start(name: String, id: String, port: Int, onPeer: (Peer) -> Unit, onLost: (String) -> Unit)
    fun stop()
}
interface MessageRepository {
    fun save(id: String, sender: String, session: String, body: String, signature: String): Boolean
    fun history(): List<ChatLine>
    fun acknowledge(id: String)
}
interface IdentityStore {
    val id: String
}

interface TrustRepository {
    fun trusted(): Set<String>
    fun trust(id: String, admission: String)
    fun block(id: String)
}

interface DeviceSettings {
    fun name(): String
    fun rename(name: String)
}

/** Blocking repository contract. Platform callers must use an I/O dispatcher. */
interface DeviceRepository : MessageRepository, TrustRepository, DeviceSettings

object ContentLimits {
    const val DEVICE_NAME_BYTES = 64
    const val TEXT_BYTES = 8192

    fun isValidName(name: String) = name.isNotBlank() && name.encodeToByteArray().size <= DEVICE_NAME_BYTES
    fun isValidText(text: String) = text.encodeToByteArray().size in 1..TEXT_BYTES
}
interface PeerTransport {
    fun close()
}

object Reconnection {
    fun delayMillis(attempt: Int, jitter: Double): Long {
        require(jitter in 0.0..1.0)
        return ((1000L shl attempt.coerceIn(0, 5)).coerceAtMost(30000) * (0.75 + jitter * 0.25)).toLong()
    }
    fun initiates(local: String, remote: String) = local < remote
}
