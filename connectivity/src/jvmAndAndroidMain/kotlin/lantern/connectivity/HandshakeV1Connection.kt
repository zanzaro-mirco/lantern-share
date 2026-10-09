package lantern.connectivity

import java.io.Closeable
import java.io.IOException
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import kotlin.concurrent.read
import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupAdmissionConfirmationContext
import lantern.protocol.GroupAdmissionProof
import lantern.protocol.GroupAdmissionEvidence
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
    /** Terminal ownership release, even if the receiving adapter subsequently fails to initialize. */
    data object ReleasedToGroup : HandshakeV1ConnectionState
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
 * Blocking start/readNext/confirm/transferToGroup/close belong on I/O workers, never the UI thread.
 * State-machine calls are serialized, but no blocking I/O or signing holds the state lock:
 * close can invalidate the attempt and close the socket while a read/write/sign is in flight.
 * The caller drives reads and supplies a shared deadline scheduler, which this owner never shuts down.
 */
internal class HandshakeV1Connection private constructor(
    private val socket: SSLSocket,
    private val identity: Identity,
    private val attempt: ProtocolHandshakeAttempt,
    private val selectedPeerIdentity: String,
    private val selectedAtMillis: Long,
    private val scheduler: ScheduledExecutorService,
    private val nowMillis: () -> Long,
) : Closeable {
    private val stream = HandshakeV1FrameStream(socket.inputStream, socket.outputStream)
    private val stateLock = Any()
    private val readerLock = Any()
    private val writerLock = Any()
    // Transfer never waits behind a blocked read/write/sign. Cancellation remains independent.
    private val operations = ReentrantReadWriteLock()
    private val cleanupStarted = AtomicBoolean()
    private val cleanupFinished = CountDownLatch(1)
    private var phase: HandshakeV1ConnectionState = HandshakeV1ConnectionState.AwaitingStart
    private var failure: HandshakeV1ConnectionFailure? = null
    private var expiryTask: ScheduledFuture<*>? = null
    private var exchangingEvidence = false

    val state: HandshakeV1ConnectionState
        get() = guarded { synchronized(stateLock) { snapshotLocked() } }

    /** Exactly one successful initial HELLO write; neither queued bytes nor duplicate starts count. */
    fun start(): Boolean = socketOperation {
        synchronized(writerLock) {
            val hello = synchronized(stateLock) {
                if (snapshotLocked() is HandshakeV1ConnectionState.Closed ||
                    phase != HandshakeV1ConnectionState.AwaitingStart
                ) return@synchronized null
                phase = HandshakeV1ConnectionState.SendingHello
                attempt.localHello
            } ?: return@socketOperation false
            stream.write(hello)
            synchronized(stateLock) {
                if (snapshotLocked() is HandshakeV1ConnectionState.Closed) return@synchronized false
                phase = HandshakeV1ConnectionState.Active(attempt.state)
                true
            }
        }
    }

    /** One reader at a time; no frame is routed until the HELLO write actually succeeded. */
    fun readNext(): Boolean = socketOperation {
        synchronized(readerLock) {
            if (!synchronized(stateLock) { activeLocked() }) return@socketOperation false
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
        synchronized(stateLock) { if (activeLocked() && !exchangingEvidence) attempt.comparison() else null }
    }

    /** The UI must pass the retained ticket ONLY after explicit comparison on both devices. */
    fun confirm(comparison: ProtocolHandshakeComparison): Boolean = socketOperation {
        val signing = synchronized(stateLock) {
            if (activeLocked()) attempt.confirm(comparison) else null
        } ?: return@socketOperation false
        val signature = identity.sign(signing.bytes)
        val sending = synchronized(stateLock) {
            if (activeLocked()) attempt.signed(signing, signature) else null
        } ?: return@socketOperation false
        synchronized(writerLock) {
            if (!synchronized(stateLock) { activeLocked() }) return@socketOperation false
            stream.write(ProtocolHandshakeFrame.Approve(sending.approval))
            synchronized(stateLock) {
                if (!activeLocked()) return@synchronized false
                attempt.sent(sending).also { snapshotLocked() }
            }
        }
    }

    private inline fun <T> socketOperation(block: () -> T): T = operations.read { guarded(block) }

    /** Issuer-only evidence write and handover, with no intermediate bootstrap APPROVE window. */
    fun sendEvidenceAndTransfer(
        expectedAnchor: GroupTrustAnchor,
        evidence: GroupAdmissionEvidence,
    ): GroupAdmissionConnection? = exchangeEvidence(expectedAnchor, evidence)

    /** Member-only receive; the mandatory anchor is independent of the received proof. */
    fun receiveEvidenceAndTransfer(expectedAnchor: GroupTrustAnchor): GroupAdmissionConnection? =
        exchangeEvidence(expectedAnchor, null)

    private fun exchangeEvidence(
        expectedAnchor: GroupTrustAnchor,
        outgoing: GroupAdmissionEvidence?,
    ): GroupAdmissionConnection? {
        val exclusive = operations.writeLock()
        if (!exclusive.tryLock()) return null
        try {
            return guarded {
                synchronized(stateLock) {
                    if (!activeLocked()) return@guarded null
                    val offers = attempt.offersForGroupAdmission() ?: return@guarded null
                    if (outgoing != null) {
                        val context = GroupAdmissionConfirmationContext.fromBootstrapOffers(offers, expectedAnchor, outgoing.proof)
                        require(context.issuerIdentity == identity.id) { "Only issuer sends group evidence" }
                    }
                    exchangingEvidence = true
                }
                // No state lock across parsing or I/O: cancellation and the original timer stay live.
                val evidence = outgoing ?: stream.readEvidence {
                    synchronized(stateLock) {
                        requireEvidenceActiveLocked()
                        socket.soTimeout = checkNotNull(attempt.remainingMillis).toInt()
                    }
                }
                synchronized(stateLock) {
                    requireEvidenceActiveLocked()
                    val offers = checkNotNull(attempt.offersForGroupAdmission())
                    val context = GroupAdmissionConfirmationContext.fromBootstrapOffers(offers, expectedAnchor, evidence.proof)
                    require((context.issuerIdentity == identity.id) == (outgoing != null)) { "Group evidence role mismatch" }
                }
                val certificates = GroupAdmissionEvidenceCertificates.decode(evidence)
                synchronized(stateLock) { requireEvidenceActiveLocked() }
                if (outgoing != null) {
                    stream.writeEvidence(evidence)
                    synchronized(stateLock) { requireEvidenceActiveLocked() }
                }
                // Reentrant exclusive lock: no old read/sign/write can enter before atomic release.
                transferToGroup(expectedAnchor, evidence.proof, certificates)
            }
        } finally {
            exclusive.unlock()
        }
    }

    private fun requireEvidenceActiveLocked() {
        if (!activeLocked() || attempt.remainingMillis == null) {
            snapshotLocked()
            throw IOException("Group evidence attempt is closed")
        }
    }

    /**
     * Single-use handover on this exact TLS channel, before any bootstrap APPROVE.
     * null means not eligible or an operation is in flight; ownership remains here in that case.
     * Lock acquisition never waits for blocked I/O; receiving initialization still belongs on I/O.
     * Anchor/proof/certificates are supplied independently, not adopted from discovery or Ready.
     * After release this owner's close, callbacks and timer cannot touch the receiving socket.
     */
    fun transferToGroup(
        expectedAnchor: GroupTrustAnchor,
        proof: GroupAdmissionProof,
        issuerCertificates: Map<String, X509Certificate>,
    ): GroupAdmissionConnection? {
        val transferLock = operations.writeLock()
        if (!transferLock.tryLock()) return null
        try {
            return guarded {
                synchronized(stateLock) {
                    if (!activeLocked()) return@synchronized null
                    val offers = attempt.offersForGroupAdmission()
                    if (offers == null) {
                        snapshotLocked()
                        return@synchronized null
                    }
                    val context = GroupAdmissionConfirmationContext.fromBootstrapOffers(offers, expectedAnchor, proof)
                    // The old timer also enters stateLock: it can never abort the new owner.
                    expiryTask?.cancel(false)
                    expiryTask = null
                    attempt.cancel()
                    phase = HandshakeV1ConnectionState.ReleasedToGroup
                    GroupAdmissionConnection.adopt(socket, identity, context, issuerCertificates,
                        selectedPeerIdentity, selectedAtMillis, scheduler) {
                        nowMillis().also { require(it >= offers.observedAtMillis) { "Handover clock moved backwards" } }
                    }
                }
            }
        } finally {
            transferLock.unlock()
        }
    }

    override fun close() = guarded {
        synchronized(stateLock) {
            closeLocked(HandshakeV1ConnectionFailure.Handshake(ProtocolHandshakeFailure.Cancelled))
        }
    }

    private fun activeLocked(): Boolean = snapshotLocked() is HandshakeV1ConnectionState.Active

    private fun snapshotLocked(): HandshakeV1ConnectionState {
        if (phase == HandshakeV1ConnectionState.ReleasedToGroup) return phase
        failure?.let { return HandshakeV1ConnectionState.Closed(it) }
        val handshake = attempt.state
        if (handshake is ProtocolHandshakeState.Closed) {
            closeLocked(HandshakeV1ConnectionFailure.Handshake(handshake.reason))
            return HandshakeV1ConnectionState.Closed(checkNotNull(failure))
        }
        return if (phase is HandshakeV1ConnectionState.Active) HandshakeV1ConnectionState.Active(handshake) else phase
    }

    private fun closeLocked(reason: HandshakeV1ConnectionFailure) {
        if (phase == HandshakeV1ConnectionState.ReleasedToGroup) return
        if (failure == null) failure = reason
        attempt.cancel()
        expiryTask?.cancel(false)
        expiryTask = null
    }

    private fun armDeadline(scheduler: ScheduledExecutorService): Unit = guarded {
        synchronized(stateLock) {
            if (snapshotLocked() is HandshakeV1ConnectionState.Closed ||
                phase == HandshakeV1ConnectionState.ReleasedToGroup
            ) return@synchronized
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
                    is InvalidHandshakeV1FrameException, is InvalidGroupEvidenceFrameException -> HandshakeV1ConnectionFailure.InvalidFrame
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
                // Prepare abort while the transport is live. macOS can reject SO_LINGER changes
                // after a peer reset, even when SSLSocket.isClosed still reports false.
                // This owner never hands the socket to application traffic or graceful reuse.
                socket.setSoLinger(true, 0)
                val attempt = ProtocolHandshakeAttempt(
                    ProtocolHandshakeParticipant(identity.id, randomNonce(), capabilities),
                    selectedPeerIdentity,
                    digest(certificate.encoded),
                    selectedAtMillis,
                    nowMillis,
                ) { bytes, signature -> Identity.verify(certificate, bytes, signature) }
                return HandshakeV1Connection(socket, identity, attempt, selectedPeerIdentity,
                    selectedAtMillis, scheduler, nowMillis).also { it.armDeadline(scheduler) }
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
