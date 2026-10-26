package lantern.connectivity

import lantern.domain.DiscoveryService
import lantern.domain.Peer
import lantern.persistence.openDesktopRepository
import java.net.InetAddress
import java.net.Socket
import java.nio.file.Files
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Actual Node runs on loopback: accepted sockets come and go while the run is stopped or reselected.
 * A smoke bound for close(); the exact size/iteration race is pinned deterministically in AsyncResourceCloserTest.
 */
class NodeLifecycleTest {
    @Test
    fun stopSelectionAndCloseSurviveConcurrentSocketChurn() {
        val directory = Files.createTempDirectory("lantern-node-lifecycle-")
        val failures = ConcurrentLinkedQueue<Throwable>()
        try {
            val target = Peer(createDesktopIdentity().identity().id, "peer", "127.0.0.1", 1)
            openDesktopRepository(directory.resolve("node.db")).use { store ->
                val node = Node(createDesktopIdentity().identity(), store, object : DiscoveryService {
                    override fun start(name: String, id: String, port: Int, onPeer: (Peer) -> Unit, onLost: (String) -> Unit) = Unit
                    override fun stop() = Unit
                }, InetAddress.getLoopbackAddress())
                val churning = AtomicBoolean(true)
                // Each connection is accepted, registered and removed again when its TLS handshake fails.
                val churn = List(CHURN_THREADS) { index ->
                    thread(isDaemon = true, name = "lantern-churn-$index") {
                        while (churning.get()) {
                            val port = node.port
                            if (port == 0) Thread.sleep(1) else runCatching { Socket(InetAddress.getLoopbackAddress(), port).close() }
                        }
                    }
                }
                try {
                    repeat(CYCLES) {
                        node.start()
                        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(6)
                        while (node.port == 0) { check(System.nanoTime() < until); Thread.sleep(1) }
                        repeat(SELECTIONS) { runCatching { node.receiveGroupText(target) }.onFailure(failures::add) }
                        runCatching { node.stop() }.onFailure(failures::add)
                    }
                } finally {
                    churning.set(false)
                    churn.forEach { it.join(5_000) }
                }
                // A stop interrupted before closing the listener would leave accept() running forever.
                val closer = thread(isDaemon = true, name = "lantern-node-close") {
                    runCatching { node.close() }.onFailure(failures::add)
                }
                closer.join(CLOSE_TIMEOUT_MILLIS)
                assertFalse(closer.isAlive, "Node.close did not return within $CLOSE_TIMEOUT_MILLIS ms")
            }
        } finally {
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
        assertTrue(failures.isEmpty(), failures.joinToString { it.toString() })
    }

    private companion object {
        const val CHURN_THREADS = 4
        const val CYCLES = 8
        const val SELECTIONS = 50
        const val CLOSE_TIMEOUT_MILLIS = 20_000L
    }
}
