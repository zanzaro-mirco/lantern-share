package lantern.connectivity

import lantern.protocol.GroupAdmissionBridgeFailure
import lantern.protocol.GroupAdmissionBridgeState
import lantern.protocol.GroupAdmissionChainVerification
import lantern.protocol.GroupAdmissionComparison
import lantern.protocol.GroupAdmissionConfirmationBridge
import lantern.protocol.GroupAdmissionConfirmationContext
import lantern.protocol.GroupAdmissionConfirmationFrameDecoder
import lantern.protocol.Wire
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

internal class InvalidGroupAdmissionFrameException : IOException("Invalid group confirmation frame")

/**
 * Isolated owner of one mutually authenticated, explicitly pinned TLS 1.3 socket.
 * No Node routing, bootstrap handover, root adoption or durable membership.
 * The caller supplies the SAME connection's verified offers/context and frozen issuer
 * certificates, drives reads on I/O workers and owns the shared deadline scheduler.
 * Core calls are serialized; signing and blocking I/O never hold the state lock.
 */
internal class GroupAdmissionConnection private constructor(
    private val socket: SSLSocket,
    private val identity: Identity,
    private val bridge: GroupAdmissionConfirmationBridge,
) : Closeable {
    private val input = socket.inputStream
    private val output = socket.outputStream
    private val stateLock = Any()
    private val readerLock = Any()
    private val writerLock = Any()
    private val cleanupStarted = AtomicBoolean()
    private val cleanupFinished = CountDownLatch(1)
    private var failure: GroupAdmissionBridgeFailure? = null
    private var expiryTask: ScheduledFuture<*>? = null

    /** Also observable when the deadline task, rather than an application call, runs cleanup. */
    @Volatile
    var cleanupFailure: Throwable? = null
        private set

    val state: GroupAdmissionBridgeState
        get() = guarded { synchronized(stateLock) { snapshotLocked() } }

    /** No input or comparison is available before the entire anchored proof verifies. */
    fun prepare(): Boolean = guarded {
        synchronized(stateLock) {
            if (snapshotLocked() != GroupAdmissionBridgeState.AwaitingStart) return@synchronized false
            val accepted = bridge.prepare()
            val current = snapshotLocked()
            accepted && current !is GroupAdmissionBridgeState.Closed
        }
    }

    fun comparison(): GroupAdmissionComparison? = guarded {
        synchronized(stateLock) {
            if (!activeLocked()) return@synchronized null
            val ticket = bridge.comparison()
            if (snapshotLocked() is GroupAdmissionBridgeState.Closed) null else ticket
        }
    }

    /** One bounded TLS chunk; true can mean a partial frame, NOT a remote confirmation. */
    fun readChunk(): Boolean = guarded {
        synchronized(readerLock) {
            if (!synchronized(stateLock) { activeLocked() }) return@guarded false
            val bytes = ByteArray(GroupAdmissionConfirmationFrameDecoder.MAX_CHUNK_BYTES)
            synchronized(stateLock) {
                if (!activeLocked()) return@guarded false
                val remaining = bridge.remainingMillis()
                if (remaining == null) {
                    snapshotLocked()
                    return@guarded false
                }
                socket.soTimeout = remaining.toInt()
            }
            val count = input.read(bytes)
            synchronized(stateLock) {
                if (!activeLocked()) return@synchronized false
                if (count < 0) {
                    framed { bridge.finish() }
                    snapshotLocked()
                    return@synchronized false
                }
                if (count == 0) throw IOException("Group confirmation stream made no progress")
                val accepted = framed { bridge.accept(bytes.copyOf(count)) }
                val current = snapshotLocked()
                accepted && current !is GroupAdmissionBridgeState.Closed
            }
        }
    }

    /** Called with the retained ticket ONLY after explicit full-code comparison by the user. */
    fun confirm(comparison: GroupAdmissionComparison): Boolean = guarded {
        val signing = synchronized(stateLock) {
            if (!activeLocked()) return@synchronized null
            val ticket = bridge.confirm(comparison)
            if (snapshotLocked() is GroupAdmissionBridgeState.Closed) null else ticket
        } ?: return@guarded false
        val signature = identity.sign(signing.bytes)
        val sending = synchronized(stateLock) {
            if (!activeLocked()) return@synchronized null
            val ticket = bridge.signed(signing, signature)
            if (snapshotLocked() is GroupAdmissionBridgeState.Closed) null else ticket
        } ?: return@guarded false
        synchronized(writerLock) {
            if (!synchronized(stateLock) { activeLocked() }) return@guarded false
            output.write(sending.bytes)
            output.flush()
            synchronized(stateLock) {
                if (!activeLocked()) return@synchronized false
                val accepted = bridge.sent(sending)
                val current = snapshotLocked()
                accepted && current !is GroupAdmissionBridgeState.Closed
            }
        }
    }

    override fun close() = lifecycle { bridge.cancel() }
    fun block() = lifecycle { bridge.block() }
    fun leaveGroup() = lifecycle { bridge.leaveGroup() }

    private fun lifecycle(event: () -> Unit): Unit = guarded {
        synchronized(stateLock) {
            if (snapshotLocked() !is GroupAdmissionBridgeState.Closed) event()
            snapshotLocked()
        }
    }

    private fun activeLocked(): Boolean = snapshotLocked() is GroupAdmissionBridgeState.Active

    private fun snapshotLocked(): GroupAdmissionBridgeState {
        failure?.let { return GroupAdmissionBridgeState.Closed(it) }
        val state = bridge.state()
        if (state is GroupAdmissionBridgeState.Closed) closeLocked(state.reason)
        return state
    }

    private fun closeLocked(reason: GroupAdmissionBridgeFailure) {
        if (failure == null) failure = reason
        bridge.cancel()
        expiryTask?.cancel(false)
        expiryTask = null
    }

    private fun armDeadline(scheduler: ScheduledExecutorService): Unit = guarded {
        synchronized(stateLock) {
            if (snapshotLocked() is GroupAdmissionBridgeState.Closed) return@synchronized
            val remaining = bridge.remainingMillis()
            if (remaining == null) {
                snapshotLocked()
                return@synchronized
            }
            // Original selection budget, including idle UI and stalled read/write/signing.
            expiryTask = scheduler.schedule({ armDeadline(scheduler) }, remaining, TimeUnit.MILLISECONDS)
        }
    }

    /** Only framing errors are sanitized; unexpected verifier/clock failures keep their identity. */
    private inline fun <T> framed(block: () -> T): T = try {
        block()
    } catch (error: IllegalArgumentException) {
        if ((bridge.state() as? GroupAdmissionBridgeState.Closed)?.reason == GroupAdmissionBridgeFailure.InvalidFrame) {
            throw InvalidGroupAdmissionFrameException()
        }
        throw error
    }

    private inline fun <T> guarded(block: () -> T): T {
        var primary: Throwable? = null
        try {
            return block()
        } catch (error: Throwable) {
            primary = error
            synchronized(stateLock) {
                try {
                    snapshotLocked()
                } catch (stateError: Throwable) {
                    if (stateError !== error) error.addSuppressed(stateError)
                }
                closeLocked(if (error is IOException) GroupAdmissionBridgeFailure.Transport else GroupAdmissionBridgeFailure.Adapter)
            }
            throw error
        } finally {
            if (synchronized(stateLock) { failure != null }) {
                try {
                    if (cleanupStarted.compareAndSet(false, true)) {
                        try {
                            abortSocket(socket)
                        } catch (error: Throwable) {
                            cleanupFailure = error
                            throw error
                        } finally {
                            cleanupFinished.countDown()
                        }
                    } else {
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
        /**
         * Ownership transfers even on failure. No live bootstrap owner may still own this socket.
         * Context nonces/offers must already be verified on this connection; not imported from
         * another attempt. Snapshot certificate map must not be mutated concurrently while copied.
         * Certificates are evidence only: the independent anchor and full chain establish binding.
         */
        fun adopt(
            socket: SSLSocket,
            identity: Identity,
            context: GroupAdmissionConfirmationContext,
            issuerCertificates: Map<String, X509Certificate>,
            selectedPeerIdentity: String,
            selectedAtMillis: Long,
            scheduler: ScheduledExecutorService,
            nowMillis: () -> Long = { System.nanoTime() / 1_000_000 },
        ): GroupAdmissionConnection {
            try {
                require(issuerCertificates.size <= GroupAdmissionChainVerification.MAX_ADMISSIONS) { "Too many issuer certificates" }
                require(issuerCertificates.keys.all(Wire::isFingerprint)) { "Invalid issuer certificate pin" }
                val session = socket.session
                require(session.protocol == "TLSv1.3") { "TLS 1.3 required" }
                val peerCertificate = session.peerCertificates.single() as X509Certificate
                val localPin = digest(session.localCertificates.single().encoded)
                require(localPin == identity.id) { "Local admission TLS identity mismatch" }
                val peerPin = digest(peerCertificate.encoded)
                // Actual TLS certificates override untrusted map entries for the two endpoints.
                val certificates = issuerCertificates.toMap() + mapOf(identity.id to identity.certificate, peerPin to peerCertificate)
                val verifier = GroupAdmissionCertificateVerifier(certificates::get)
                socket.setSoLinger(true, 0)
                val bridge = GroupAdmissionConfirmationBridge(context, identity.id, localPin,
                    selectedPeerIdentity, peerPin, selectedAtMillis, nowMillis,
                    verifier::verify, { bytes, signature -> verifier.verify(peerPin, bytes, signature) })
                return GroupAdmissionConnection(socket, identity, bridge).also { it.armDeadline(scheduler) }
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
                // Terminal abort, never promote truncated data; avoid JDK draining pending records.
                socket.shutdownInput()
            } catch (_: SSLException) {
                // JSSE already shut input down; missing close_notify is expected for an abort.
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
