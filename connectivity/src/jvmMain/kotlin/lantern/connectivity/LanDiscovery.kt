package lantern.connectivity

import lantern.domain.*
import java.net.InetAddress
import javax.jmdns.*

class LanDiscovery(private val address: InetAddress) : DiscoveryService {
    private var mdns: JmDNS? = null
    override fun start(name: String, id: String, port: Int, onPeer: (Peer) -> Unit, onLost: (String) -> Unit) {
        check(mdns == null)
        val dns = JmDNS.create(address, "lantern-${id.take(12)}")
        mdns = dns
        val type = "_lantern._tcp.local."
        val serviceIds = java.util.concurrent.ConcurrentHashMap<String, String>()
        dns.addServiceListener(type, object : ServiceListener {
            override fun serviceAdded(e: ServiceEvent) { dns.requestServiceInfo(type, e.name, true) }
            override fun serviceRemoved(e: ServiceEvent) { serviceIds.remove(e.name)?.let(onLost) }
            override fun serviceResolved(e: ServiceEvent) {
                val info = e.info
                val remote = info.getPropertyString("id") ?: return
                if (remote == id || !remote.matches(Regex("[0-9a-f]{64}")) || info.getPropertyString("v") != "0") return
                val host = info.inetAddresses.firstOrNull { it.javaClass == address.javaClass }?.hostAddress ?: return
                serviceIds[e.name] = remote
                onPeer(Peer(remote, (info.getPropertyString("name") ?: "Lantern").take(64), host, info.port))
            }
        })
        dns.registerService(ServiceInfo.create(type, "lantern-${id.take(16)}", port, 0, 0, mapOf("id" to id, "name" to name, "v" to "0")))
    }
    override fun stop() { mdns?.close(); mdns = null }
}
