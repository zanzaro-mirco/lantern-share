package lantern.connectivity

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.PrintStream
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeState

/**
 * Disposable JVM counterpart for a future Apple integration test; NOT an app entry point.
 * The host supplies the explicitly selected peer pin BEFORE TLS. stdout contains public test
 * metadata only. stdin carries host-simulated comparison/cleanup, never bootstrap network frames.
 * After parameter validation run() owns/closes input; output belongs to the host.
 * No product keys, database, discovery or trust.
 */
object HandshakeV1InteropFixture {
    private val pinPattern = Regex("[0-9a-f]{64}")
    private const val IO_TIMEOUT_MILLIS = 10_000
    private const val MAX_COMMAND_BYTES = 73 // 7 + space + 64-character digest + optional CR before LF.

    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 1) { "Usage: runHandshakeV1InteropFixture -PinteropPeerPin=<selected pin>" }
        run(args.single(), System.`in`, System.out)
    }

    data class Result(val comparisonCode: String, val negotiatedFeatures: Set<String>)

    fun run(
        selectedPeerID: String,
        input: InputStream,
        output: PrintStream,
        controlTimeoutMillis: Long = IO_TIMEOUT_MILLIS.toLong(),
    ): Result {
        require(pinPattern.matches(selectedPeerID)) { "Invalid selected peer pin" }
        require(controlTimeoutMillis in 1..IO_TIMEOUT_MILLIS.toLong()) { "Invalid fixture control timeout" }
        val selectedAt = System.nanoTime() / 1_000_000
        val identity = createDesktopIdentity().identity() // Fresh OS/JCA material in memory, test only.
        val scheduler = Executors.newSingleThreadScheduledExecutor()
        val control = Executors.newSingleThreadExecutor { task ->
            Thread(task, "lantern-interop-fixture-control").apply { isDaemon = true }
        }
        var rejection: ComparisonRejected? = null
        var cancelled: Result? = null
        try {
            input.use {
                val loopback = InetAddress.getByName("127.0.0.1")
                val context = identity.context { it == selectedPeerID }
                (context.serverSocketFactory.createServerSocket(0, 1, loopback) as SSLServerSocket).use { listener ->
                    listener.needClientAuth = true
                    listener.enabledProtocols = arrayOf("TLSv1.3")
                    listener.soTimeout = IO_TIMEOUT_MILLIS
                    event(output, "LISTENING 127.0.0.1 ${listener.localPort} ${identity.id}")
                    (listener.accept() as SSLSocket).use { socket ->
                        socket.soTimeout = IO_TIMEOUT_MILLIS
                        socket.enabledProtocols = arrayOf("TLSv1.3")
                        socket.startHandshake()
                        val capabilities = ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text"))
                        HandshakeV1Connection.adopt(socket, identity, capabilities, selectedPeerID, selectedAt, scheduler).use { owner ->
                            check(owner.start()) { "Fixture HELLO write rejected" }
                            check(owner.readNext()) { "Fixture peer HELLO rejected" }
                            val comparison = checkNotNull(owner.comparison()) { "Fixture comparison unavailable" }
                            val code = digest(comparison.bytes)
                            event(output, "COMPARISON $code")
                            fun command(): String {
                                val pending = control.submit<String> { readCommand(input) }
                                return try {
                                    pending.get(controlTimeoutMillis, TimeUnit.MILLISECONDS)
                                } catch (error: ExecutionException) {
                                    throw error.cause ?: error
                                } finally { pending.cancel(true) }
                            }
                            val action = command()
                            if (action == "OBSERVE_CLOSE") {
                                // Test-only branch: observe real peer EOF/reset without confirming.
                                val waiting = owner.state as? HandshakeV1ConnectionState.Active
                                val awaiting = waiting?.handshake as? ProtocolHandshakeState.AwaitingConfirmation
                                checkNotNull(awaiting) { "Fixture not awaiting confirmation" }
                                check(!awaiting.remoteApproved) { "Unexpected remote approval" }
                                val pending = control.submit<Boolean> { owner.readNext() }
                                try {
                                    pending.get(controlTimeoutMillis, TimeUnit.MILLISECONDS)
                                    error("Expected peer transport closure, not a bootstrap frame")
                                } catch (error: ExecutionException) {
                                    val cause = error.cause
                                    if (cause !is IOException || cause is SocketTimeoutException) throw error
                                    val closed = owner.state as? HandshakeV1ConnectionState.Closed
                                    check(closed?.reason == HandshakeV1ConnectionFailure.Io && socket.isClosed) {
                                        "Peer closure not observed"
                                    }
                                    check(!owner.confirm(comparison) && !owner.start()) { "Closed fixture resumed" }
                                } finally { pending.cancel(true) }
                                cancelled = Result(code, emptySet())
                            } else {
                                if (action != "CONFIRM $code") {
                                    throw ComparisonRejected() // No signing/APPROVE for discordant test UI.
                                }
                                check(owner.confirm(comparison)) { "Fixture confirmation rejected" }
                                check(owner.readNext()) { "Fixture peer approval rejected" }
                                val active = owner.state as? HandshakeV1ConnectionState.Active
                                val ready = active?.handshake as? ProtocolHandshakeState.Ready
                                checkNotNull(ready) { "Fixture bootstrap not ready" }
                                event(output, "READY ${ready.capabilities.features.sorted().joinToString(",")}")
                                // Keep TLS alive until the host has also observed peer READY. Immediate
                                // linger-zero close could discard an APPROVE still queued for the peer.
                                check(command() == "CLOSE") { "Fixture cleanup acknowledgement rejected" }
                                return Result(code, ready.capabilities.features.toSet())
                            }
                        }
                    }
                }
            }
        } catch (error: ComparisonRejected) {
            // Never classify a resource-cleanup failure as a successful negative test.
            if (error.suppressed.isNotEmpty()) throw error
            rejection = error
        } finally {
            control.shutdownNow()
            scheduler.shutdownNow()
        }
        cancelled?.let {
            event(output, "CLOSED BEFORE_CONFIRMATION") // Attest only after successful cleanup.
            return it
        }
        val rejected = checkNotNull(rejection)
        event(output, "REJECTED COMPARISON") // Only after resource cleanup, not a TLS frame.
        throw rejected
    }

    private class ComparisonRejected : IllegalStateException("Explicit fixture comparison rejected")

    private fun event(output: PrintStream, text: String) {
        output.println(text)
        output.flush()
        if (output.checkError()) throw IOException("Fixture event write failed")
    }

    private fun readCommand(input: InputStream): String {
        val command = StringBuilder()
        while (true) {
            val byte = input.read()
            if (byte < 0) throw EOFException("Fixture control command truncated")
            if (byte == 10) return command.toString().removeSuffix("\r")
            if (command.length >= MAX_COMMAND_BYTES || byte != 13 && byte !in 32..126) {
                throw IOException("Invalid fixture control command")
            }
            command.append(byte.toChar())
        }
    }
}
