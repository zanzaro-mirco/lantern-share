package lantern.connectivity

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.io.PrintStream
import java.net.InetAddress
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.net.ssl.SSLSocket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeState

/** Local JVM/JCA fixture validation only; NOT proof of Apple/JVM interoperability. */
class HandshakeV1InteropFixtureTest {
    @Test
    fun explicitComparisonCompletesBothOwnersBeforeAcknowledgedCleanup() = withFixture { peer ->
        val ticket = assertNotNull(peer.owner.comparison())
        val code = digest(ticket.bytes)
        assertEquals("COMPARISON $code", peer.events.readLine())
        peer.commands.println("CONFIRM $code")
        assertTrue(peer.owner.confirm(ticket))
        assertTrue(peer.owner.readNext())
        assertIs<ProtocolHandshakeState.Ready>(assertIs<HandshakeV1ConnectionState.Active>(peer.owner.state).handshake)
        assertEquals("READY receipts,text", peer.events.readLine())
        peer.commands.println("CLOSE")
        val result = peer.result.get(5, TimeUnit.SECONDS)
        assertEquals(code, result.comparisonCode)
        assertEquals(setOf("receipts", "text"), result.negotiatedFeatures)
        assertFailsWith<IOException> { peer.owner.readNext() }
        assertFalse(peer.owner.confirm(ticket))
        assertTrue(peer.socket.isClosed)
    }

    @Test
    fun wrongOrMalformedControlCannotAuthorizeBootstrap() {
        for (command in listOf("CONFIRM ${"0".repeat(64)}", "x".repeat(74), "CONFIRM \u0080")) {
            withFixture { peer ->
                val ticket = assertNotNull(peer.owner.comparison())
                assertEquals("COMPARISON ${digest(ticket.bytes)}", peer.events.readLine())
                peer.commands.println(command)
                val error = assertFailsWith<ExecutionException> { peer.result.get(5, TimeUnit.SECONDS) }
                if (command.startsWith("CONFIRM 0")) assertIs<IllegalStateException>(error.cause)
                else assertIs<IOException>(error.cause)
                assertFailsWith<IOException> { peer.owner.readNext() }
                assertTrue(peer.socket.isClosed)
                assertFalse(peer.owner.confirm(ticket))
            }
        }
    }

    @Test
    fun missingControlTimesOutAndClosesTransportWithoutApproval() = withFixture(controlTimeoutMillis = 1000) { peer ->
        assertEquals("COMPARISON ${digest(assertNotNull(peer.owner.comparison()).bytes)}", peer.events.readLine())
        val error = assertFailsWith<ExecutionException> { peer.result.get(5, TimeUnit.SECONDS) }
        assertIs<TimeoutException>(error.cause)
        assertFailsWith<IOException> { peer.owner.readNext() }
        assertTrue(peer.socket.isClosed)
    }

    @Test
    fun invalidSelectedPinsAndTimeoutsAreRejectedBeforeCreatingEndpoint() {
        val events = ByteArrayOutputStream()
        PrintStream(events).use { output ->
            for (pin in listOf("", "a".repeat(63), "A".repeat(64), "g".repeat(64))) {
                assertFailsWith<IllegalArgumentException> {
                    HandshakeV1InteropFixture.run(pin, ByteArrayInputStream(byteArrayOf()), output)
                }
            }
            assertFailsWith<IllegalArgumentException> {
                HandshakeV1InteropFixture.run("a".repeat(64), ByteArrayInputStream(byteArrayOf()), output, 0)
            }
        }
        assertEquals(0, events.size())
    }

    @Test
    fun certificateDifferentFromSelectedPinCannotReachBootstrapComparison() {
        assertFailsWith<IOException> {
            withFixture(selectedPeerPin = "f".repeat(64)) {
                fail("Unselected certificate reached bootstrap")
            }
        }
    }

    private data class Peer(
        val owner: HandshakeV1Connection,
        val socket: SSLSocket,
        val commands: PrintStream,
        val events: java.io.BufferedReader,
        val result: java.util.concurrent.Future<HandshakeV1InteropFixture.Result>,
    )

    private fun withFixture(
        controlTimeoutMillis: Long = 10_000,
        selectedPeerPin: String? = null,
        block: (Peer) -> Unit,
    ) {
        val identity = createDesktopIdentity().identity()
        val workers = Executors.newSingleThreadExecutor()
        val scheduler = Executors.newSingleThreadScheduledExecutor()
        val selectedAt = System.nanoTime() / 1_000_000
        try {
            PipedInputStream().use { controlInput ->
                PrintStream(PipedOutputStream(controlInput), true, Charsets.UTF_8).use { commands ->
                    PipedInputStream().use { eventInput ->
                        PrintStream(PipedOutputStream(eventInput), true, Charsets.UTF_8).use { output ->
                            val result = workers.submit<HandshakeV1InteropFixture.Result> {
                                HandshakeV1InteropFixture.run(selectedPeerPin ?: identity.id, controlInput, output, controlTimeoutMillis)
                            }
                            val events = eventInput.bufferedReader(Charsets.UTF_8)
                            // Bound the initial event wait; all following reads are after TLS/frame progress.
                            val listening = scheduler.submit<String> { events.readLine() }.get(5, TimeUnit.SECONDS).split(' ')
                            assertEquals(4, listening.size)
                            assertEquals("LISTENING", listening[0])
                            assertEquals("127.0.0.1", listening[1])
                            val selectedPin = listening[3] // Explicit host selection before real mutual TLS.
                            val context = identity.context { it == selectedPin }
                            (context.socketFactory.createSocket(InetAddress.getByName(listening[1]), listening[2].toInt()) as SSLSocket).use { socket ->
                                socket.enabledProtocols = arrayOf("TLSv1.3")
                                socket.soTimeout = 5000
                                socket.startHandshake()
                                assertEquals("TLSv1.3", socket.session.protocol)
                                val capabilities = ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text"))
                                HandshakeV1Connection.adopt(socket, identity, capabilities, selectedPin, selectedAt, scheduler).use { owner ->
                                    assertTrue(owner.start())
                                    assertTrue(owner.readNext())
                                    block(Peer(owner, socket, commands, events, result))
                                }
                            }
                        }
                    }
                }
            }
        } finally {
            workers.shutdownNow()
            scheduler.shutdownNow()
            assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS))
            assertTrue(scheduler.awaitTermination(5, TimeUnit.SECONDS))
        }
    }
}
