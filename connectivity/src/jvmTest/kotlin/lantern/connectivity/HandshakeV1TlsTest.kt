package lantern.connectivity

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.nio.file.Files
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeApproval
import lantern.protocol.ProtocolHandshakeAttempt
import lantern.protocol.ProtocolHandshakeFailure
import lantern.protocol.ProtocolHandshakeFrame
import lantern.protocol.ProtocolHandshakeFrameCodec
import lantern.protocol.ProtocolHandshakeParticipant
import lantern.protocol.ProtocolHandshakeState
import lantern.protocol.ProtocolNegotiationResult

/** Explicitly pinned test connections only; no v1 routing or trust changes in Node/PeerConnection. */
class HandshakeV1TlsTest {
    @Test
    fun mutualTlsCarriesHelloAndDirectionalApprovalsWithMatchingTranscript() = withIdentities { client, server ->
        val (clientExchange, serverExchange) = connect(client, server)
        assertVerified(clientExchange)
        assertVerified(serverExchange)
        assertEquals(clientExchange.comparisonDigest, serverExchange.comparisonDigest)
        assertEquals(server.id, clientExchange.authenticatedPeer)
        assertEquals(client.id, serverExchange.authenticatedPeer)
        assertEquals("TLSv1.3", clientExchange.tlsProtocol)
        assertEquals("TLSv1.3", serverExchange.tlsProtocol)
    }

    @Test
    fun genuinelyAuthenticatedPeerCannotAddressApprovalToAnotherDevice() = withIdentities { client, server ->
        val thirdId = listOf("c".repeat(64), "d".repeat(64), "e".repeat(64)).first { it != client.id && it != server.id }
        val (clientExchange, serverExchange) = connect(client, server, changeServerApproval = { it.copy(recipient = thirdId) })
        assertEquals(server.id, clientExchange.authenticatedPeer)
        assertEquals(ProtocolHandshakeState.Closed(ProtocolHandshakeFailure.AddressMismatch), clientExchange.state)
        assertVerified(serverExchange)
    }

    @Test
    fun signedApprovalCannotBeReplayedOnFreshTlsConnection() = withIdentities { client, server ->
        val first = connect(client, server)
        assertVerified(first.first)
        assertVerified(first.second)
        val staleServerApproval = first.second.outgoingApproval
        val second = connect(client, server, changeServerApproval = { staleServerApproval })
        assertEquals(server.id, second.first.authenticatedPeer)
        assertNotEquals(first.first.local.nonce, second.first.local.nonce)
        assertNotEquals(first.second.local.nonce, second.second.local.nonce)
        assertNotEquals(first.first.comparisonDigest, second.first.comparisonDigest)
        assertEquals(ProtocolHandshakeState.Closed(ProtocolHandshakeFailure.InvalidSignature), second.first.state)
        assertVerified(second.second)
    }

    @Test
    fun cancelledAttemptCannotAdvanceOnDelayedSuccessfulWriteCallback() = withIdentities { client, server ->
        val (clientExchange, serverExchange) = connect(client, server, afterServerWrite = { it.cancel() })
        assertEquals(ProtocolHandshakeState.Closed(ProtocolHandshakeFailure.Cancelled), serverExchange.state)
        // The peer got the bytes, but that cannot resurrect the locally cancelled candidate.
        assertVerified(clientExchange)
    }

    private data class Exchange(
        val local: ProtocolHandshakeParticipant,
        val outgoingApproval: ProtocolHandshakeApproval,
        val authenticatedPeer: String,
        val tlsProtocol: String,
        val comparisonDigest: String,
        val state: ProtocolHandshakeState,
    )

    private fun connect(
        client: Identity,
        server: Identity,
        changeServerApproval: (ProtocolHandshakeApproval) -> ProtocolHandshakeApproval = { it },
        afterServerWrite: (ProtocolHandshakeAttempt) -> Unit = {},
    ): Pair<Exchange, Exchange> {
        val loopback = InetAddress.getLoopbackAddress()
        val executor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "lantern-v1-tls-test").apply { isDaemon = true }
        }
        val listener = server.context { it == client.id }.serverSocketFactory.createServerSocket(0, 1, loopback) as SSLServerSocket
        listener.use {
            it.needClientAuth = true
            it.enabledProtocols = arrayOf("TLSv1.3")
            it.soTimeout = 5000
            try {
                val serverResult = executor.submit<Exchange> {
                    (listener.accept() as SSLSocket).use { socket ->
                        exchange(socket, server, client.id, setOf("text", "receipts", "server-option"), setOf("receipts"), changeServerApproval, afterServerWrite)
                    }
                }
                val clientResult = (client.context { pin -> pin == server.id }.socketFactory.createSocket(loopback, listener.localPort) as SSLSocket).use { socket ->
                    exchange(socket, client, server.id, setOf("text", "receipts", "client-option"), setOf("text"))
                }
                return clientResult to serverResult.get(10, TimeUnit.SECONDS)
            } finally {
                listener.close()
                executor.shutdownNow()
                check(executor.awaitTermination(10, TimeUnit.SECONDS)) { "TLS test worker did not stop" }
            }
        }
    }

    private fun exchange(
        socket: SSLSocket,
        identity: Identity,
        selectedPeer: String,
        supported: Set<String>,
        required: Set<String>,
        changeApproval: (ProtocolHandshakeApproval) -> ProtocolHandshakeApproval = { it },
        afterWrite: (ProtocolHandshakeAttempt) -> Unit = {},
    ): Exchange {
        val selectedAt = System.nanoTime() / 1_000_000
        socket.soTimeout = 5000
        socket.enabledProtocols = arrayOf("TLSv1.3")
        socket.startHandshake()
        val certificate = socket.session.peerCertificates.single() as X509Certificate
        val authenticatedPeer = digest(certificate.encoded)
        val local = ProtocolHandshakeParticipant(identity.id, randomNonce(), ProtocolCapabilities(1, supported, required))
        val attempt = ProtocolHandshakeAttempt(local, selectedPeer, authenticatedPeer, selectedAt, { System.nanoTime() / 1_000_000 }) { bytes, signature ->
            Identity.verify(certificate, bytes, signature)
        }
        val input = DataInputStream(socket.inputStream)
        val output = DataOutputStream(socket.outputStream)
        writePayload(output, ProtocolHandshakeFrameCodec.encode(assertNotNull(attempt.localHello)))
        val remoteHello = ProtocolHandshakeFrameCodec.decode(readPayload(input, ProtocolHandshakeFrameCodec.MAX_BYTES))
        assertTrue(attempt.receive(remoteHello))
        val comparison = assertNotNull(attempt.comparison())
        val transcript = comparison.bytes
        // Explicit confirmation is simulated only here; production still requires the physical UI.
        val signing = assertNotNull(attempt.confirm(comparison))
        val sending = assertNotNull(attempt.signed(signing, identity.sign(signing.bytes)))
        val outgoingApproval = changeApproval(sending.approval)
        writePayload(output, ProtocolHandshakeFrameCodec.encode(ProtocolHandshakeFrame.Approve(outgoingApproval)))
        afterWrite(attempt)
        attempt.sent(sending)
        val incomingApproval = ProtocolHandshakeFrameCodec.decode(readPayload(input, ProtocolHandshakeFrameCodec.MAX_BYTES))
        attempt.receive(incomingApproval)
        return Exchange(local, outgoingApproval, authenticatedPeer, socket.session.protocol, digest(transcript), attempt.state)
    }

    // Test-only length framing of isolated bootstrap messages; Node still routes wire v0 only.
    private fun writePayload(output: DataOutputStream, bytes: ByteArray) {
        output.writeInt(bytes.size)
        output.write(bytes)
        output.flush()
    }

    private fun readPayload(input: DataInputStream, maxBytes: Int): ByteArray {
        val size = input.readInt()
        require(size in 1..maxBytes)
        return ByteArray(size).also(input::readFully)
    }

    private fun assertVerified(exchange: Exchange) {
        assertEquals(
            ProtocolHandshakeState.Ready(ProtocolNegotiationResult.Compatible(1, setOf("receipts", "text"))),
            exchange.state,
        )
    }

    private fun withIdentities(block: (Identity, Identity) -> Unit) {
        val directory = Files.createTempDirectory("lantern-v1-tls-test-")
        val password = "test-only-v1-tls-passphrase".toCharArray()
        try {
            block(Identity.open(directory.resolve("client.p12"), password), Identity.open(directory.resolve("server.p12"), password))
        } finally {
            password.fill('\u0000')
            Files.walk(directory).use { files ->
                files.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }
}
