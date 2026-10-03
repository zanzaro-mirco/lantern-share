package lantern.connectivity

import java.io.Closeable
import java.io.IOException
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeAttempt
import lantern.protocol.ProtocolHandshakeComparison
import lantern.protocol.ProtocolHandshakeFailure
import lantern.protocol.ProtocolHandshakeFrame
import lantern.protocol.ProtocolHandshakeParticipant
import lantern.protocol.ProtocolHandshakeState

internal sealed interface HandshakeV1ConnectionState {
    data object AwaitingStart : HandshakeV1ConnectionState
    data object SendingHello : HandshakeV1ConnectionState
    /** Ready inside this view is revocable bootstrap progress, NOT application authorization. */
    data class Active(val handshake: ProtocolHandshakeState) : HandshakeV1ConnectionState
    data class Closed(val reason: HandshakeV1ConnectionFailure) : HandshakeV1ConnectionState
}

internal sealed interface HandshakeV1ConnectionFailure {
    data class Handshake(val reason: ProtocolHandshakeFailure) : HandshakeV1ConnectionFailure
    data object InvalidFrame : HandshakeV1ConnectionFailure
    data object Io : HandshakeV1ConnectionFailure
    data object Adapter : HandshakeV1ConnectionFailure
}

/**
 * Owns one already pinned, mutually authenticated TLS 1.3 socket. Isolated from Node and wire v0.
 * Blocking start/readNext/confirm/close belong on I/O workers, never the UI thread.
 * State-machine calls are serialized, but no blocking I/O or signing holds the state lock:
 * close can invalidate the attempt and close the socket while a read/write/sign is in flight.
 * The caller drives reads and supplies a shared deadline scheduler, which this owner never shuts down.
 */
internal class HandshakeV1Connection private constructor(
    private val socket: SSLSocket,
    private val identity: Identity,
    private val attempt: ProtocolHandshakeAttempt,
) : Closeable {
    private val stream = HandshakeV1FrameStream(socket.inputStream, socket.outputStream)
    private val stateLock = Any()
    private val readerLock = Any()
    private val writerLock = Any()
    private val cleanupStarted = AtomicBoolean()
    private val cleanupFinished = CountDownLatch(1)
    private var phase: HandshakeV1ConnectionState = HandshakeV1ConnectionState.AwaitingStart
    private var failure: HandshakeV1ConnectionFailure? = null
    private var expiryTask: ScheduledFuture<*>? = null

    val state: HandshakeV1ConnectionState
        get() = guarded { synchronized(stateLock) { snapshotLocked() } }

    /** Exactly one successful initial HELLO write; neither queued bytes nor duplicate starts count. */
    fun start(): Boolean = guarded {
        synchronized(writerLock) {
            val hello = synchronized(stateLock) {
                if (snapshotLocked() is HandshakeV1ConnectionState.Closed ||
                    phase != HandshakeV1ConnectionState.AwaitingStart
                ) return@synchronized null
                phase = HandshakeV1ConnectionState.SendingHello
                attempt.localHello
            } ?: return@guarded false
            stream.write(hello)
            synchronized(stateLock) {
                if (snapshotLocked() is HandshakeV1ConnectionState.Closed) return@synchronized false
                phase = HandshakeV1ConnectionState.Active(attempt.state)
                true
            }
        }
    }

    /** One reader at a time; no frame is routed until the HELLO write actually succeeded. */
    fun readNext(): Boolean = guarded {
        synchronized(readerLock) {
            if (!synchronized(stateLock) { activeLocked() }) return@guarded false
            val frame = stream.read {
                synchronized(stateLock) {
                    if (!activeLocked()) throw IOException("V1 bootstrap is closed")
                    val remaining = attempt.remainingMillis
                    if (remaining == null) {
                        snapshotLocked()
                        throw IOException("V1 bootstrap deadline reached")
                    }
                    socket.soTimeout = remaining.toInt()
                }
            }
            synchronized(stateLock) {
                if (!activeLocked()) return@synchronized false
                attempt.receive(frame).also { snapshotLocked() }
            }
        }
    }

    fun comparison(): ProtocolHandshakeComparison? = guarded {
        synchronized(stateLock) { if (activeLocked()) attempt.comparison() else null }
    }

    /** The UI must pass the retained ticket ONLY after explicit comparison on both devices. */
    fun confirm(comparison: ProtocolHandshakeComparison): Boolean = guarded {
        val signing = synchronized(stateLock) {
            if (activeLocked()) attempt.confirm(comparison) else null
        } ?: return@guarded false
        val signature = identity.sign(signing.bytes)
        val sending = synchronized(stateLock) {
            if (activeLocked()) attempt.signed(signing, signature) else null
        } ?: return@guarded false
        synchronized(writerLock) {
            if (!synchronized(stateLock) { activeLocked() }) return@guarded false
            stream.write(ProtocolHandshakeFrame.Approve(sending.approval))
            synchronized(stateLock) {
                if (!activeLocked()) return@synchronized false
                attempt.sent(sending).also { snapshotLocked() }
            }
        }
    }

    override fun close() = guarded {
        synchronized(stateLock) {
            closeLocked(HandshakeV1ConnectionFailure.Handshake(ProtocolHandshakeFailure.Cancelled))
        }
    }

    private fun activeLocked(): Boolean = snapshotLocked() is HandshakeV1ConnectionState.Active

    private fun snapshotLocked(): HandshakeV1ConnectionState {
        failure?.let { return HandshakeV1ConnectionState.Closed(it) }
        val handshake = attempt.state
        if (handshake is ProtocolHandshakeState.Closed) {
            closeLocked(HandshakeV1ConnectionFailure.Handshake(handshake.reason))
            return HandshakeV1ConnectionState.Closed(checkNotNull(failure))
        }
        return if (phase is HandshakeV1ConnectionState.Active) HandshakeV1ConnectionState.Active(handshake) else phase
    }

    private fun closeLocked(reason: HandshakeV1ConnectionFailure) {
        if (failure == null) failure = reason
        attempt.cancel()
        expiryTask?.cancel(false)
        expiryTask = null
    }

    private fun armDeadline(scheduler: ScheduledExecutorService): Unit = guarded {
        synchronized(stateLock) {
            if (snapshotLocked() is HandshakeV1ConnectionState.Closed) return@synchronized
            val remaining = attempt.remainingMillis
            if (remaining == null) {
                snapshotLocked()
                return@synchronized
            }
            // Includes idle confirmation and a TLS read/write stalled INSIDE the provider.
            expiryTask = scheduler.schedule({ armDeadline(scheduler) }, remaining, TimeUnit.MILLISECONDS)
        }
    }

    private inline fun <T> guarded(block: () -> T): T {
        var primary: Throwable? = null
        try {
            return block()
        } catch (error: Throwable) {
            primary = error
            synchronized(stateLock) {
                // Preserve a protocol failure (including expiry) over the consequential I/O error.
                try {
                    snapshotLocked()
                } catch (clockError: Throwable) {
                    if (clockError !== error) error.addSuppressed(clockError)
                }
                closeLocked(when (error) {
                    is InvalidHandshakeV1FrameException -> HandshakeV1ConnectionFailure.InvalidFrame
                    is IOException -> HandshakeV1ConnectionFailure.Io
                    else -> HandshakeV1ConnectionFailure.Adapter
                })
            }
            throw error
        } finally {
            if (synchronized(stateLock) { failure != null }) {
                try {
                    if (cleanupStarted.compareAndSet(false, true)) {
                        try {
                            abortSocket(socket)
                        } finally {
                            cleanupFinished.countDown()
                        }
                    } else {
                        // A timeout and the awakened reader may finish together. Return only after cleanup.
                        cleanupFinished.await()
                    }
                } catch (cleanupError: Throwable) {
                    if (cleanupError is InterruptedException) Thread.currentThread().interrupt()
                    if (primary == null) throw cleanupError
                    if (primary !== cleanupError) primary.addSuppressed(cleanupError)
                }
            }
        }
    }

    companion object {
        /** Transfers socket ownership even on initialization failure. TLS was established by the caller. */
        fun adopt(
            socket: SSLSocket,
            identity: Identity,
            capabilities: ProtocolCapabilities,
            selectedPeerIdentity: String,
            selectedAtMillis: Long,
            scheduler: ScheduledExecutorService,
            nowMillis: () -> Long = { System.nanoTime() / 1_000_000 },
        ): HandshakeV1Connection {
            try {
                val session = socket.session
                require(session.protocol == "TLSv1.3") { "TLS 1.3 required" }
                val certificate = session.peerCertificates.single() as X509Certificate
                require(digest(session.localCertificates.single().encoded) == identity.id) { "Local TLS identity mismatch" }
                val attempt = ProtocolHandshakeAttempt(
                    ProtocolHandshakeParticipant(identity.id, randomNonce(), capabilities),
                    selectedPeerIdentity,
                    digest(certificate.encoded),
                    selectedAtMillis,
                    nowMillis,
                ) { bytes, signature -> Identity.verify(certificate, bytes, signature) }
                return HandshakeV1Connection(socket, identity, attempt).also { it.armDeadline(scheduler) }
            } catch (error: Throwable) {
                try {
                    abortSocket(socket)
                } catch (cleanupError: Throwable) {
                    if (cleanupError !== error) error.addSuppressed(cleanupError)
                }
                throw error
            }
        }

        private fun abortSocket(socket: SSLSocket) {
            if (socket.isClosed) return
            var failure: Throwable? = null
            fun remember(error: Throwable) {
                val previous = failure
                if (previous == null) failure = error else if (previous !== error) previous.addSuppressed(error)
            }
            try {
                socket.setSoLinger(true, 0)
            } catch (error: Throwable) {
                remember(error)
            }
            try {
                // Terminal bootstrap abort: discard inbound data, never interpret truncation as success.
                // JDK 17 close() otherwise drains peer records using the long application read timeout.
                socket.shutdownInput()
            } catch (_: SSLException) {
                // JSSE reports missing close_notify AFTER shutting down input. Expected for an abort.
            } catch (error: Throwable) {
                remember(error)
            }
            try {
                socket.close()
            } catch (error: Throwable) {
                remember(error)
            }
            failure?.let { throw it }
        }
    }
}
