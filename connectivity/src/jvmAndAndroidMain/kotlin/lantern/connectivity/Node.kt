package lantern.connectivity

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import lantern.domain.ContentLimits
import lantern.domain.DeviceController
import lantern.domain.DeviceRepository
import lantern.domain.DeviceState
import lantern.domain.DiscoveryService
import lantern.domain.Peer
import lantern.domain.Reconnection
import lantern.protocol.Wire
import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/** Coordinates service runs. Each run owns its sockets, channels and retry state. */
class Node(
    val identity: Identity,
    private val repository: DeviceRepository,
    private val discovery: DiscoveryService,
    private val address: InetAddress,
    private val requestedPort: Int = 0,
) : DeviceController, AutoCloseable {
    private val mutable = MutableStateFlow(DeviceState(
        name = repository.name(),
        id = identity.id,
        trusted = repository.trusted(),
        messages = repository.history(),
    ))
    override val state = mutable.asStateFlow()
    private val lifetime = SupervisorJob()
    private val scope = CoroutineScope(lifetime + Dispatchers.IO)
    private val resourceCloser = AsyncResourceCloser(scope)
    private val authorization = PairingAuthorization(repository)
    @Volatile private var activeRun: ServiceRun? = null
    @Volatile private var cleanupJob: Job? = null
    @Volatile private var closed = false

    val port: Int get() = activeRun?.server?.localPort ?: 0

    private class ServiceRun {
        @Volatile var server: SSLServerSocket? = null
        var job: Job? = null
        val channels = ConcurrentHashMap<String, PeerConnection>()
        val sockets = ConcurrentHashMap.newKeySet<SSLSocket>()
        val dialing = ConcurrentHashMap.newKeySet<String>()
        val failures = ConcurrentHashMap<String, Int>()
        val retryAt = ConcurrentHashMap<String, Long>()
    }

    private fun isCurrent(run: ServiceRun) = activeRun === run

    private fun update(run: ServiceRun, transform: (DeviceState) -> DeviceState) {
        mutable.update { if (isCurrent(run)) transform(it) else it }
    }

    private fun report(run: ServiceRun, message: String, error: Exception) {
        update(run) { it.copy(status = "$message: ${error.javaClass.simpleName}") }
    }

    @Synchronized
    override fun rename(name: String) {
        check(!closed && activeRun == null)
        require(ContentLimits.isValidName(name))
        repository.rename(name)
        mutable.update { it.copy(name = name) }
    }

    @Synchronized
    override fun start() {
        check(!closed) { "Nodo chiuso" }
        if (activeRun != null) return
        val run = ServiceRun()
        activeRun = run
        mutable.update { it.copy(active = true, status = "Avvio servizio…") }
        run.job = scope.launch {
            try {
                val listener = createListener()
                synchronized(this@Node) {
                    if (!isCurrent(run)) {
                        listener.close()
                        return@launch
                    }
                    run.server = listener
                    discovery.start(
                        state.value.name, identity.id, listener.localPort,
                        { discovered(run, it) }, { lost -> update(run) { it.copy(peers = it.peers.filterNot { peer -> peer.id == lost }) } },
                    )
                }
                update(run) { it.copy(status = "Ricerca LAN su ${address.hostAddress}:${listener.localPort}") }
                launch { reconnectLoop(run) }
                while (isCurrent(run)) {
                    val socket = listener.accept() as SSLSocket
                    if (registerSocket(run, socket)) {
                        launch { handle(run, socket, expectedPeer = null) }
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                synchronized(this@Node) {
                    if (isCurrent(run)) {
                        stop()
                        mutable.update { it.copy(status = "Servizio non disponibile: ${error.javaClass.simpleName}") }
                    }
                }
            }
        }
    }

    private fun createListener(): SSLServerSocket =
        (identity.context(authorization::allowsHandshake).serverSocketFactory
            .createServerSocket(requestedPort, LISTEN_BACKLOG, address) as SSLServerSocket).apply {
            enabledProtocols = arrayOf("TLSv1.3")
            needClientAuth = true
        }

    private suspend fun reconnectLoop(run: ServiceRun) {
        while (isCurrent(run)) {
            authorization.takeExpired()?.let { expired ->
                run.channels[expired]?.close()
                update(run) { it.copy(pairingPeer = null, comparisonCode = null, status = "Associazione scaduta") }
            }
            state.value.peers.filter {
                authorization.allowsHandshake(it.id) && Reconnection.initiates(identity.id, it.id)
            }.forEach { connect(run, it) }
            delay(DISCOVERY_POLL_MILLIS)
        }
    }

    /** Also accepts externally resolved local peers, e.g. a future manual-address adapter. */
    fun discovered(peer: Peer) {
        activeRun?.let { discovered(it, peer) }
    }

    private fun discovered(run: ServiceRun, peer: Peer) {
        if (peer.id == identity.id || peer.port !in 1..65535 || !Wire.isFingerprint(peer.id)) return
        update(run) { it.copy(peers = (it.peers.filterNot { existing -> existing.id == peer.id } + peer).takeLast(MAX_DISCOVERED_PEERS)) }
    }

    @Synchronized
    override fun pair(peer: Peer) {
        val run = checkNotNull(activeRun) { "Servizio arrestato" }
        if (authorization.isTrusted(peer.id)) return
        reject()
        authorization.select(peer.id)
        update(run) { it.copy(pairingPeer = peer.id, comparisonCode = null, status = "Seleziona questo dispositivo anche sull'altro schermo (120 s)") }
        discovered(run, peer)
    }

    override fun confirm() {
        val run = activeRun ?: return
        val peerId = authorization.selectedPeer() ?: return
        val displayedCode = state.value.comparisonCode ?: return
        execute(run, "Conferma fallita") { run.channels[peerId]?.approve(displayedCode) }
    }

    @Synchronized
    override fun reject() {
        val peerId = authorization.cancel()
        peerId?.let { activeRun?.channels?.get(it)?.let(resourceCloser::close) }
        mutable.update { it.copy(pairingPeer = null, comparisonCode = null) }
    }

    @Synchronized
    override fun block(peerId: String) {
        authorization.revoke(peerId)
        activeRun?.channels?.get(peerId)?.let(resourceCloser::close)
        mutable.update {
            it.copy(
                trusted = repository.trusted(),
                pairingPeer = if (it.pairingPeer == peerId) null else it.pairingPeer,
                comparisonCode = if (it.pairingPeer == peerId) null else it.comparisonCode,
            )
        }
    }

    private fun connect(run: ServiceRun, peer: Peer) {
        if (!isCurrent(run) || run.channels.containsKey(peer.id) ||
            monotonicMillis() < (run.retryAt[peer.id] ?: Long.MIN_VALUE) || !run.dialing.add(peer.id)
        ) return
        scope.launch {
            var socket: SSLSocket? = null
            try {
                val remote = InetAddress.getByName(peer.host)
                require(remote.isSiteLocalAddress || remote.isLinkLocalAddress || remote.isLoopbackAddress) { "Indirizzo non locale" }
                socket = identity.context { it == peer.id && authorization.allowsHandshake(it) }
                    .socketFactory.createSocket() as SSLSocket
                if (!registerSocket(run, socket)) return@launch
                socket.connect(InetSocketAddress(remote, peer.port), CONNECT_TIMEOUT_MILLIS)
                handle(run, socket, peer.id)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                report(run, "Collegamento fallito", error)
            } finally {
                socket?.let { run.sockets.remove(it); closeSocket(it) }
                run.dialing.remove(peer.id)
                val failures = run.failures.merge(peer.id, 1, Int::plus) ?: 1
                run.retryAt[peer.id] = monotonicMillis() + Reconnection.delayMillis(failures - 1, Math.random())
            }
        }
    }

    private fun handle(run: ServiceRun, socket: SSLSocket, expectedPeer: String?) {
        var connection: PeerConnection? = null
        try {
            check(isCurrent(run))
            socket.soTimeout = HANDSHAKE_TIMEOUT_MILLIS
            socket.enabledProtocols = arrayOf("TLSv1.3")
            socket.startHandshake()
            val certificate = socket.session.peerCertificates.single() as X509Certificate
            val remoteId = digest(certificate.encoded)
            require(remoteId != identity.id && authorization.allowsHandshake(remoteId))
            require(expectedPeer == null || expectedPeer == remoteId)
            if (expectedPeer == null) require(Reconnection.initiates(remoteId, identity.id))
            connection = PeerConnection(
                socket, remoteId, certificate, identity, authorization, repository,
                isActive = { isCurrent(run) }, onEvent = { event -> onConnectionEvent(run, remoteId, event) },
            )
            if (run.channels.putIfAbsent(remoteId, connection) != null) return
            connection.run()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            report(run, "Canale chiuso", error)
        } finally {
            connection?.let { peer ->
                if (run.channels.remove(peer.remoteId, peer)) update(run) {
                    it.copy(connected = it.connected - peer.remoteId, comparisonCode = if (it.pairingPeer == peer.remoteId) null else it.comparisonCode)
                }
            }
            run.sockets.remove(socket)
            closeSocket(socket)
        }
    }

    private fun onConnectionEvent(run: ServiceRun, peerId: String, event: ConnectionEvent) {
        when (event) {
            is ConnectionEvent.AwaitingComparison -> update(run) {
                if (it.pairingPeer != peerId) it else it.copy(comparisonCode = event.code, status = "Confronta TUTTO il codice sui due schermi, poi conferma su entrambi")
            }
            ConnectionEvent.Connected -> {
                run.failures.remove(peerId)
                run.retryAt.remove(peerId)
                update(run) {
                    it.copy(
                        connected = it.connected + peerId,
                        pairingPeer = if (it.pairingPeer == peerId) null else it.pairingPeer,
                        comparisonCode = if (it.pairingPeer == peerId) null else it.comparisonCode,
                        status = "TLS 1.3 autenticato",
                    )
                }
            }
            ConnectionEvent.RepositoryChanged -> update(run) {
                it.copy(messages = repository.history(), trusted = repository.trusted())
            }
        }
    }

    override fun send(peerId: String, text: String) {
        require(ContentLimits.isValidText(text))
        val run = activeRun ?: return
        execute(run, "Invio fallito") { (run.channels[peerId] ?: error("Peer offline")).sendText(text) }
    }

    private fun execute(run: ServiceRun, failure: String, action: () -> Unit) {
        scope.launch {
            try {
                if (isCurrent(run)) action()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                report(run, failure, error)
            }
        }
    }

    @Synchronized
    override fun stop() {
        val run = activeRun
        activeRun = null
        authorization.cancel()
        run?.job?.cancel()
        run?.let {
            val resources = buildList<Closeable> {
                it.server?.let(::add)
                addAll(it.sockets.toList())
            }
            cleanupJob = resourceCloser.closeAll(resources)
        }
        runCatching { discovery.stop() }
        mutable.update { it.copy(active = false, peers = emptyList(), connected = emptySet(), pairingPeer = null, comparisonCode = null, status = "Servizio arrestato") }
    }

    override fun close() {
        val pendingCleanup = synchronized(this) {
            closed = true
            stop()
            cleanupJob
        }
        runBlocking {
            pendingCleanup?.join()
            lifetime.cancelAndJoin()
        }
    }

    private fun closeSocket(socket: java.io.Closeable) {
        runCatching { socket.close() }
    }

    @Synchronized
    private fun registerSocket(run: ServiceRun, socket: SSLSocket): Boolean {
        if (!isCurrent(run) || run.sockets.size >= MAX_SOCKETS) {
            closeSocket(socket)
            return false
        }
        run.sockets.add(socket)
        return true
    }

    private fun monotonicMillis() = System.nanoTime() / 1_000_000

    private companion object {
        const val MAX_SOCKETS = 16
        const val MAX_DISCOVERED_PEERS = 32
        const val LISTEN_BACKLOG = 10
        const val CONNECT_TIMEOUT_MILLIS = 5_000
        const val HANDSHAKE_TIMEOUT_MILLIS = 10_000
        const val DISCOVERY_POLL_MILLIS = 500L
    }
}
