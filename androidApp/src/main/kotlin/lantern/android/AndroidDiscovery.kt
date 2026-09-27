package lantern.android

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import lantern.domain.DiscoveryService
import lantern.domain.Peer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

/** Each discovery run owns its callbacks and serialized resolver queue. */
@Suppress("DEPRECATION") // API 29 remains supported; resolution is serialized for the legacy NSD API.
class AndroidDiscovery(context: Context, private val onError: (String) -> Unit) : DiscoveryService {
    private val manager = context.getSystemService(NsdManager::class.java)
    @Volatile private var activeRun: DiscoveryRun? = null

    private class DiscoveryRun(val localId: String, val onPeer: (Peer) -> Unit, val onLost: (String) -> Unit) {
        val ids = ConcurrentHashMap<String, String>()
        val queue = ConcurrentLinkedQueue<NsdServiceInfo>()
        val resolving = AtomicBoolean(false)
        var registration: NsdManager.RegistrationListener? = null
        var discovery: NsdManager.DiscoveryListener? = null
    }

    @Synchronized
    override fun start(name: String, id: String, port: Int, onPeer: (Peer) -> Unit, onLost: (String) -> Unit) {
        stop()
        val run = DiscoveryRun(id, onPeer, onLost)
        activeRun = run
        val service = NsdServiceInfo().apply {
            serviceName = "lantern-${id.take(16)}"
            serviceType = SERVICE_TYPE
            setPort(port)
            setAttribute("id", id)
            setAttribute("name", name)
            setAttribute("v", "0")
        }
        val registration = registrationListener(run)
        run.registration = registration
        manager.registerService(service, NsdManager.PROTOCOL_DNS_SD, registration)
        val discovery = discoveryListener(run)
        run.discovery = discovery
        manager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discovery)
    }

    private fun registrationListener(run: DiscoveryRun) = object : NsdManager.RegistrationListener {
        override fun onServiceRegistered(info: NsdServiceInfo) {}
        override fun onServiceUnregistered(info: NsdServiceInfo) {}
        override fun onRegistrationFailed(info: NsdServiceInfo, code: Int) = report(run, "Pubblicazione NSD fallita", code)
        override fun onUnregistrationFailed(info: NsdServiceInfo, code: Int) = report(run, "Arresto NSD fallito", code)
    }

    private fun discoveryListener(run: DiscoveryRun) = object : NsdManager.DiscoveryListener {
        override fun onDiscoveryStarted(type: String) {}
        override fun onDiscoveryStopped(type: String) {}
        override fun onStartDiscoveryFailed(type: String, code: Int) = report(run, "Scoperta NSD fallita", code)
        override fun onStopDiscoveryFailed(type: String, code: Int) = report(run, "Arresto scoperta fallito", code)
        override fun onServiceFound(info: NsdServiceInfo) {
            if (activeRun !== run || run.queue.size >= MAX_PENDING_RESOLUTIONS) return
            run.queue.add(info)
            resolveNext(run)
        }
        override fun onServiceLost(info: NsdServiceInfo) {
            if (activeRun === run) run.ids.remove(info.serviceName)?.let(run.onLost)
        }
    }

    private fun resolveNext(run: DiscoveryRun) {
        if (activeRun !== run || !run.resolving.compareAndSet(false, true)) return
        val service = run.queue.poll()
        if (service == null) {
            run.resolving.set(false)
            if (run.queue.isNotEmpty()) resolveNext(run)
            return
        }
        try {
            manager.resolveService(service, object : NsdManager.ResolveListener {
                override fun onResolveFailed(info: NsdServiceInfo, code: Int) {
                    report(run, "Risoluzione NSD fallita", code)
                    resolved(run)
                }
                override fun onServiceResolved(info: NsdServiceInfo) {
                    try {
                        publish(run, info)
                    } finally {
                        resolved(run)
                    }
                }
            })
        } catch (error: RuntimeException) {
            run.resolving.set(false)
            if (activeRun === run) onError("Risoluzione NSD non disponibile: ${error.javaClass.simpleName}")
        }
    }

    private fun publish(run: DiscoveryRun, info: NsdServiceInfo) {
        if (activeRun !== run) return
        val remoteId = info.attributes["id"]?.toString(Charsets.UTF_8) ?: return
        val host = info.host?.hostAddress ?: return
        if (remoteId == run.localId || info.attributes["v"]?.toString(Charsets.UTF_8) != "0") return
        run.ids[info.serviceName] = remoteId
        run.onPeer(Peer(remoteId, info.attributes["name"]?.toString(Charsets.UTF_8)?.take(64) ?: "Lantern", host, info.port))
    }

    private fun resolved(run: DiscoveryRun) {
        run.resolving.set(false)
        resolveNext(run)
    }

    private fun report(run: DiscoveryRun, message: String, code: Int) {
        if (activeRun === run) onError("$message: $code")
    }

    @Synchronized
    override fun stop() {
        val run = activeRun ?: return
        activeRun = null
        run.queue.clear()
        run.registration?.let { runCatching { manager.unregisterService(it) } }
        run.discovery?.let { runCatching { manager.stopServiceDiscovery(it) } }
    }

    private companion object {
        const val SERVICE_TYPE = "_lantern._tcp."
        const val MAX_PENDING_RESOLUTIONS = 32
    }
}
