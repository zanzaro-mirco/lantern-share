package lantern.connectivity

import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeApproval
import lantern.protocol.ProtocolHandshakeAttempt
import lantern.protocol.ProtocolHandshakeComparison
import lantern.protocol.ProtocolHandshakeFailure
import lantern.protocol.ProtocolHandshakeFrame
import lantern.protocol.ProtocolHandshakeFrameCodec
import lantern.protocol.ProtocolHandshakeParticipant
import lantern.protocol.ProtocolHandshakeState
import lantern.protocol.ProtocolNegotiationResult

/** Real pinned mutual TLS and JCA signatures; only UI confirmation and selected clocks are simulated. */
class HandshakeV1ConnectionTest {
    private val capabilities = ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text"))

    @Test
    fun ownerRequiresOneHelloWriteAndExplicitConfirmationOnBothSides() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    assertEquals(HandshakeV1ConnectionState.AwaitingStart, left.state)
                    assertFalse(left.readNext())
                    assertFalse(sockets.scheduler.isShutdown)
                    assertNull(left.comparison())
                    exchangeHellos(left, right)
                    val leftCode = assertNotNull(left.comparison())
                    val rightCode = assertNotNull(right.comparison())
                    assertEquals(digest(leftCode.bytes), digest(rightCode.bytes))
                    // Test-only explicit UI confirmation, never inferred from receiving remote proof.
                    assertTrue(left.confirm(leftCode))
                    assertFalse(left.confirm(leftCode))
                    assertTrue(right.readNext())
                    assertEquals(active(ProtocolHandshakeState.AwaitingConfirmation(true)), right.state)
                    assertEquals(active(ProtocolHandshakeState.AwaitingRemoteApproval), left.state)
                    assertTrue(right.confirm(rightCode))
                    assertReady(right)
                    assertTrue(left.readNext())
                    assertReady(left)
                    left.close()
                    assertHandshakeClosed(left, ProtocolHandshakeFailure.Cancelled)
                    assertTrue(sockets.client.isClosed)
                    assertFalse(left.confirm(leftCode))
                    assertFalse(left.start())
                    assertFalse(left.readNext())
                }
            }
            assertTrue(sockets.server.isClosed)
        }
    }

    @Test
    fun initialHelloIsWrittenOnlyOnceAndNotOnReadBeforeStart() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { owner ->
                assertFalse(owner.readNext())
                assertTrue(owner.start())
                assertFalse(owner.start())
                val remote = HandshakeV1FrameStream(sockets.server.inputStream, sockets.server.outputStream)
                assertIs<ProtocolHandshakeFrame.Hello>(remote.read())
                sockets.server.soTimeout = 100
                assertFailsWith<SocketTimeoutException> { remote.read() }
                assertEquals(active(ProtocolHandshakeState.AwaitingHello), owner.state)
            }
        }
    }

    @Test
    fun selectedPinMismatchClosesBeforeHelloAndCannotBeStarted() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val unexpected = foreignId(client, server)
            val owner = HandshakeV1Connection.adopt(sockets.client, client, capabilities, unexpected, sockets.selectedAt, sockets.scheduler)
            assertHandshakeClosed(owner, ProtocolHandshakeFailure.IdentityMismatch)
            assertTrue(sockets.client.isClosed)
            assertFalse(owner.start())
            assertNull(owner.comparison())
        }
    }

    @Test
    fun factoryFailureClosesTransferredSocketWithoutChangingIdentity() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            assertFailsWith<IllegalArgumentException> {
                HandshakeV1Connection.adopt(sockets.client, server, capabilities, server.id, sockets.selectedAt, sockets.scheduler)
            }
            assertTrue(sockets.client.isClosed)
        }
        withSockets(client, server) { sockets ->
            val failure = AssertionError("test-only clock failure")
            assertSame(failure, assertFailsWith<AssertionError> {
                HandshakeV1Connection.adopt(sockets.client, client, capabilities, server.id, sockets.selectedAt, sockets.scheduler) { throw failure }
            })
            assertTrue(sockets.client.isClosed)
        }
    }

    @Test
    fun approvalBeforeHelloClosesEvenOnAnAuthenticatedSocket() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { owner ->
                assertTrue(owner.start())
                val remote = HandshakeV1FrameStream(sockets.server.inputStream, sockets.server.outputStream)
                remote.write(ProtocolHandshakeFrame.Approve(ProtocolHandshakeApproval(server.id, client.id, "cHJvb2Y=")))
                assertFalse(owner.readNext())
                assertHandshakeClosed(owner, ProtocolHandshakeFailure.UnexpectedMessage)
                assertTrue(sockets.client.isClosed)
            }
        }
    }

    @Test
    fun helloIdentityAndCapabilityFailuresCloseOwnedResources() = withPeers { client, server ->
        val cases = listOf(
            ProtocolHandshakeParticipant(foreignId(client, server), randomNonce(), capabilities) to ProtocolHandshakeFailure.IdentityMismatch,
            ProtocolHandshakeParticipant(server.id, randomNonce(), ProtocolCapabilities(2, setOf("text"), setOf("text"))) to null,
        )
        for ((hello, expected) in cases) withSockets(client, server) { sockets ->
            sockets.clientOwner().use { owner ->
                assertTrue(owner.start())
                HandshakeV1FrameStream(sockets.server.inputStream, sockets.server.outputStream).write(ProtocolHandshakeFrame.Hello(hello))
                assertFalse(owner.readNext())
                val failure = assertIs<HandshakeV1ConnectionFailure.Handshake>(assertIs<HandshakeV1ConnectionState.Closed>(owner.state).reason)
                if (expected != null) assertEquals(expected, failure.reason) else assertIs<ProtocolHandshakeFailure.Incompatible>(failure.reason)
                assertTrue(sockets.client.isClosed)
                assertNull(owner.comparison())
            }
        }
    }

    @Test
    fun malformedAndTruncatedTlsFramesCloseAndRethrowWithoutAuthorization() = withPeers { client, server ->
        val invalid = listOf(
            header(0), header(-1), header(ProtocolHandshakeFrameCodec.MAX_BYTES + 1),
            framed("{\"sensitive-peer-content\":true}".encodeToByteArray()),
            framed(byteArrayOf(0xc3.toByte(), 0x28)),
        )
        for (bytes in invalid) withSockets(client, server) { sockets ->
            sockets.clientOwner().use { owner ->
                assertTrue(owner.start())
                sockets.server.outputStream.apply { write(bytes); flush() }
                assertFailsWith<InvalidHandshakeV1FrameException> { owner.readNext() }
                assertEquals(HandshakeV1ConnectionState.Closed(HandshakeV1ConnectionFailure.InvalidFrame), owner.state)
                assertTrue(sockets.client.isClosed)
            }
        }
        for (bytes in listOf(byteArrayOf(0, 0), header(10) + byteArrayOf(1, 2))) withSockets(client, server) { sockets ->
            sockets.clientOwner().use { owner ->
                assertTrue(owner.start())
                sockets.server.outputStream.apply { write(bytes); flush() }
                sockets.server.shutdownOutput()
                assertFailsWith<EOFException> { owner.readNext() }
                assertEquals(HandshakeV1ConnectionState.Closed(HandshakeV1ConnectionFailure.Io), owner.state)
                assertTrue(sockets.client.isClosed)
            }
        }
    }

    @Test
    fun peerDisconnectAndFailedApprovalWriteInvalidateComparison() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    exchangeHellos(left, right)
                    val comparison = assertNotNull(left.comparison())
                    right.close()
                    assertFailsWith<IOException> { left.readNext() }
                    assertEquals(HandshakeV1ConnectionState.Closed(HandshakeV1ConnectionFailure.Io), left.state)
                    assertFalse(left.confirm(comparison))
                    assertTrue(sockets.client.isClosed)
                }
            }
        }
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    exchangeHellos(left, right)
                    val comparison = assertNotNull(left.comparison())
                    sockets.client.shutdownOutput()
                    assertFailsWith<IOException> { left.confirm(comparison) }
                    assertEquals(HandshakeV1ConnectionState.Closed(HandshakeV1ConnectionFailure.Io), left.state)
                    assertTrue(sockets.client.isClosed)
                }
            }
        }
    }

    @Test
    fun cancellationReleasesConcurrentReaderAndCannotBeUndone() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val readerEntered = CountDownLatch(1)
            var signalReader = false
            val owner = sockets.clientOwner(now = {
                if (signalReader) readerEntered.countDown()
                monotonicMillis()
            })
            sockets.serverOwner().use { remote ->
                owner.use {
                    exchangeHellos(owner, remote)
                    val comparison = assertNotNull(owner.comparison())
                    signalReader = true
                    val executor = Executors.newSingleThreadExecutor()
                    try {
                        val reading = executor.submit<Boolean> {
                            try { owner.readNext() } catch (_: IOException) { false }
                        }
                        assertTrue(readerEntered.await(5, TimeUnit.SECONDS))
                        owner.close()
                        assertFalse(reading.get(5, TimeUnit.SECONDS))
                        assertHandshakeClosed(owner, ProtocolHandshakeFailure.Cancelled)
                        assertTrue(sockets.client.isClosed)
                        assertFalse(owner.confirm(comparison))
                    } finally {
                        owner.close()
                        executor.shutdownNow()
                        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
                    }
                }
            }
        }
    }

    @Test
    fun readingStateAtExactDeadlineClosesSocketEvenWithoutTimer() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            var now = 1000L
            sockets.clientOwner(selectedAt = now, now = { now }).use { owner ->
                assertTrue(owner.start())
                now += ProtocolHandshakeAttempt.TIMEOUT_MILLIS
                assertHandshakeClosed(owner, ProtocolHandshakeFailure.Expired)
                assertTrue(sockets.client.isClosed)
                assertFalse(owner.start())
            }
        }
    }

    @Test
    fun silentPeerCannotKeepReadAliveBeyondTheSelectionBudget() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val selectedAt = monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 1000
            sockets.clientOwner(selectedAt = selectedAt).use { owner ->
                assertTrue(owner.start())
                assertFailsWith<IOException> { owner.readNext() }
                assertHandshakeClosed(owner, ProtocolHandshakeFailure.Expired)
                assertTrue(sockets.client.isClosed)
            }
        }
    }

    @Test
    fun previousConnectionComparisonCannotConfirmFreshNonces() = withPeers { client, server ->
        var previous: ProtocolHandshakeComparison? = null
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    exchangeHellos(left, right)
                    previous = assertNotNull(left.comparison())
                }
            }
        }
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    exchangeHellos(left, right)
                    val current = assertNotNull(left.comparison())
                    assertNotEquals(digest(assertNotNull(previous).bytes), digest(current.bytes))
                    assertFalse(left.confirm(assertNotNull(previous)))
                    assertEquals(active(ProtocolHandshakeState.AwaitingConfirmation(false)), left.state)
                    assertTrue(left.confirm(current))
                }
            }
        }
    }

    @Test
    fun scheduledDeadlineClosesIdleSocketWithoutAnyReaderOrStateInspection() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val selectedAt = monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 500
            sockets.clientOwner(selectedAt = selectedAt).use { owner ->
                val afterDeadline = CountDownLatch(1)
                sockets.scheduler.schedule({ afterDeadline.countDown() }, 700, TimeUnit.MILLISECONDS)
                assertTrue(afterDeadline.await(5, TimeUnit.SECONDS))
                // Check the physical socket BEFORE a state read can enforce expiry itself.
                assertTrue(sockets.client.isClosed)
                assertHandshakeClosed(owner, ProtocolHandshakeFailure.Expired)
                assertFalse(sockets.scheduler.isShutdown)
            }
        }
    }

    @Test
    fun unavailableDeadlineSchedulerCannotLeaveTransferredSocketOpen() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.scheduler.shutdown()
            assertFailsWith<RejectedExecutionException> { sockets.clientOwner() }
            assertTrue(sockets.client.isClosed)
        }
    }

    private fun exchangeHellos(left: HandshakeV1Connection, right: HandshakeV1Connection) {
        assertTrue(left.start())
        assertFalse(left.start())
        assertTrue(right.start())
        assertTrue(left.readNext())
        assertTrue(right.readNext())
    }

    private fun active(state: ProtocolHandshakeState) = HandshakeV1ConnectionState.Active(state)

    private fun assertReady(owner: HandshakeV1Connection) = assertEquals(
        active(ProtocolHandshakeState.Ready(ProtocolNegotiationResult.Compatible(1, setOf("receipts", "text")))), owner.state,
    )

    private fun assertHandshakeClosed(owner: HandshakeV1Connection, reason: ProtocolHandshakeFailure) = assertEquals(
        HandshakeV1ConnectionState.Closed(HandshakeV1ConnectionFailure.Handshake(reason)), owner.state,
    )

    private fun foreignId(client: Identity, server: Identity) = listOf("c", "d", "e").map { it.repeat(64) }.first { it != client.id && it != server.id }
    private fun monotonicMillis() = System.nanoTime() / 1_000_000

    private fun header(length: Int) = java.io.ByteArrayOutputStream().also { DataOutputStream(it).writeInt(length) }.toByteArray()
    private fun framed(payload: ByteArray) = header(payload.size) + payload

    private inner class Sockets(val client: SSLSocket, val server: SSLSocket, val clientIdentity: Identity, val serverIdentity: Identity, val selectedAt: Long, val scheduler: ScheduledExecutorService) {
        fun clientOwner(selectedAt: Long = this.selectedAt, now: () -> Long = ::monotonicMillis) = HandshakeV1Connection.adopt(
            client, clientIdentity, capabilities, serverIdentity.id, selectedAt, scheduler, now,
        )
        fun serverOwner() = HandshakeV1Connection.adopt(server, serverIdentity, capabilities, clientIdentity.id, selectedAt, scheduler)
    }

    private fun withSockets(client: Identity, server: Identity, block: (Sockets) -> Unit) {
        val selectedAt = monotonicMillis()
        val loopback = InetAddress.getLoopbackAddress()
        val executor = Executors.newSingleThreadScheduledExecutor()
        val listener = server.context { it == client.id }.serverSocketFactory.createServerSocket(0, 1, loopback) as SSLServerSocket
        listener.use {
            listener.needClientAuth = true
            listener.enabledProtocols = arrayOf("TLSv1.3")
            listener.soTimeout = 5000
            try {
                val accepting = executor.submit<SSLSocket> {
                    val socket = listener.accept() as SSLSocket
                    try {
                        socket.soTimeout = 5000
                        socket.enabledProtocols = arrayOf("TLSv1.3")
                        socket.startHandshake()
                        socket
                    } catch (error: Throwable) {
                        socket.close()
                        throw error
                    }
                }
                (client.context { it == server.id }.socketFactory.createSocket(loopback, listener.localPort) as SSLSocket).use { clientSocket ->
                    clientSocket.soTimeout = 5000
                    clientSocket.enabledProtocols = arrayOf("TLSv1.3")
                    clientSocket.startHandshake()
                    accepting.get(5, TimeUnit.SECONDS).use { serverSocket ->
                        block(Sockets(clientSocket, serverSocket, client, server, selectedAt, executor))
                    }
                }
            } finally {
                listener.close()
                executor.shutdownNow()
                assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    private fun withPeers(block: (Identity, Identity) -> Unit) {
        val directory = Files.createTempDirectory("lantern-v1-owner-test-")
        val password = "test-only-owner-passphrase".toCharArray()
        try {
            block(Identity.open(directory.resolve("client.p12"), password), Identity.open(directory.resolve("server.p12"), password))
        } finally {
            password.fill('\u0000')
            Files.walk(directory).use { files -> files.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }
}
