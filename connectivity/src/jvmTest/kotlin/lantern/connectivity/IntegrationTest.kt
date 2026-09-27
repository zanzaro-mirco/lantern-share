package lantern.connectivity

import kotlin.test.*
import lantern.domain.*
import lantern.protocol.*
import lantern.persistence.openDesktopRepository
import java.net.InetAddress
import java.nio.file.Files
import java.security.cert.CertificateException
import javax.net.ssl.SSLSocket

class IntegrationTest {
    private val password = "test-only-long-passphrase".toCharArray()
    private fun identity() = Identity.open(Files.createTempDirectory("lantern-id").resolve("identity.p12"), password)
    @Test fun identitySurvivesRestartAndRejectsWrongPassword() {
        val path = Files.createTempDirectory("lantern-id").resolve("id.p12")
        val first = Identity.open(path, password)
        assertEquals(first.id, Identity.open(path, password).id)
        assertFails { Identity.open(path, "incorrect-passphrase".toCharArray()) }
        val bytes = "signed content".toByteArray()
        assertTrue(Identity.verify(first.certificate, bytes, first.sign(bytes)))
        assertFalse(Identity.verify(first.certificate, "tampered".toByteArray(), first.sign(bytes)))
    }
    @Test fun pinsFailClosed() {
        val a = identity(); val b = identity()
        val trust = PinnedTrust { it == a.id }
        trust.checkServerTrusted(arrayOf(a.certificate), "EC")
        assertFailsWith<CertificateException> { trust.checkServerTrusted(arrayOf(b.certificate), "EC") }
        assertFailsWith<CertificateException> { trust.checkClientTrusted(emptyArray(), "EC") }
    }
    @Test fun durableDeduplication() {
        val path = Files.createTempDirectory("lantern-db").resolve("test.db")
        openDesktopRepository(path).use { s -> assertTrue(s.save("1", "a", "s", "hello", "sig")); assertFalse(s.save("1", "a", "s", "hello", "sig")); assertFails { s.save("1", "a", "s", "altered", "sig") }; s.trust("peer", "admission") }
        openDesktopRepository(path).use { s -> assertEquals("hello", s.history().single().text); assertTrue("peer" in s.trusted()); s.block("peer"); assertTrue(s.trusted().isEmpty()) }
    }
    @Test fun unknownIdentityCannotCompleteApplicationHandshake() {
        val serverId = identity(); val outsider = identity(); val ip = InetAddress.getLoopbackAddress()
        openDesktopRepository(Files.createTempDirectory("reject-db").resolve("db")).use { store ->
            Node(serverId, store, ManualDiscovery(), ip).use { node ->
                node.start(); await { node.port > 0 }
                val socket = outsider.context { it == serverId.id }.socketFactory.createSocket(ip, node.port) as SSLSocket
                socket.use {
                    it.soTimeout = 3000
                    assertFails {
                        it.startHandshake()
                        val hello = Wire.encode(Frame(type = FrameType.HELLO, sender = outsider.id, nonce = randomNonce()))
                        val out = java.io.DataOutputStream(it.outputStream)
                        out.writeInt(hello.size); out.write(hello); out.flush()
                        val input = java.io.DataInputStream(it.inputStream)
                        val length = input.readInt()
                        require(length in 1..Wire.MAX_FRAME)
                        Wire.decode(ByteArray(length).also(input::readFully))
                    }
                }
                assertTrue(node.state.value.connected.isEmpty()); assertTrue(store.trusted().isEmpty())
            }
        }
    }
    private class ManualDiscovery : DiscoveryService {
        override fun start(name: String, id: String, port: Int, onPeer: (Peer) -> Unit, onLost: (String) -> Unit) {}
        override fun stop() {}
    }
    @Test fun callbacksFromStoppedServiceCannotPolluteNewRun() {
        val callbacks = java.util.concurrent.CopyOnWriteArrayList<(Peer) -> Unit>()
        val discovery = object : DiscoveryService {
            override fun start(name: String, id: String, port: Int, onPeer: (Peer) -> Unit, onLost: (String) -> Unit) {
                callbacks.add(onPeer)
            }
            override fun stop() {}
        }
        openDesktopRepository(Files.createTempDirectory("restart-db").resolve("db")).use { repository ->
            Node(identity(), repository, discovery, InetAddress.getLoopbackAddress()).use { node ->
                node.start()
                await { callbacks.size == 1 }
                node.stop()
                node.start()
                await { callbacks.size == 2 }
                val stale = Peer("a".repeat(64), "Stale", "127.0.0.1", 1234)
                callbacks[0](stale)
                assertTrue(node.state.value.peers.isEmpty())
                callbacks[1](stale.copy(name = "Current"))
                assertEquals("Current", node.state.value.peers.single().name)
                node.stop()
                assertFalse(node.state.value.active)
                assertEquals(0, node.port)
            }
        }
    }
    private fun await(timeout: Long = 15000, predicate: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeout
        while (!predicate()) { if (System.currentTimeMillis() > deadline) fail("Timeout"); Thread.sleep(30) }
    }
    @Test fun realTlsPairSendPersistReconnectAndBlock() {
        val a = identity(); val b = identity(); val ip = InetAddress.getLoopbackAddress()
        val sa = openDesktopRepository(Files.createTempDirectory("node-a").resolve("db")); val sb = openDesktopRepository(Files.createTempDirectory("node-b").resolve("db"))
        val na = Node(a, sa, ManualDiscovery(), ip); val nb = Node(b, sb, ManualDiscovery(), ip)
        try {
            na.start(); nb.start(); await { na.port > 0 && nb.port > 0 }
            val pa = Peer(a.id, "A", ip.hostAddress, na.port); val pb = Peer(b.id, "B", ip.hostAddress, nb.port)
            na.discovered(pb); nb.discovered(pa)
            Thread.sleep(600); assertTrue(na.state.value.connected.isEmpty())
            na.pair(pb); nb.pair(pa)
            await { na.state.value.comparisonCode != null && nb.state.value.comparisonCode != null }
            assertEquals(na.state.value.comparisonCode, nb.state.value.comparisonCode)
            na.confirm(); Thread.sleep(100); assertTrue(na.state.value.connected.isEmpty())
            nb.confirm(); await { b.id in na.state.value.connected && a.id in nb.state.value.connected }
            na.send(b.id, "Ciao cifrato 🔐")
            await { nb.state.value.messages.any { it.text == "Ciao cifrato 🔐" } && na.state.value.messages.any { it.received } }
            na.stop(); await { nb.state.value.connected.isEmpty() }
            Thread.sleep(200); na.start(); await { na.port > 0 }
            na.discovered(pb); nb.discovered(pa.copy(port = na.port))
            await(20000) { b.id in na.state.value.connected && a.id in nb.state.value.connected }
            nb.send(a.id, "Dopo riconnessione")
            await { na.state.value.messages.any { it.text == "Dopo riconnessione" } }
            nb.block(a.id); await { na.state.value.connected.isEmpty() }
            assertFalse(a.id in nb.state.value.trusted)
        } finally { na.close(); nb.close(); sa.close(); sb.close() }
    }
}
