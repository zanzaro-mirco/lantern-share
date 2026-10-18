package lantern.connectivity

import lantern.domain.LocalGroupRepository
import lantern.domain.PendingGroupAdoption
import lantern.domain.GroupAdoptionRepository
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupAdmissionChainVerification
import lantern.protocol.GroupAdmissionComparison
import lantern.protocol.GroupAdmissionConfirmation
import lantern.protocol.GroupAdmissionConfirmationFrameDecoder
import lantern.protocol.GroupAdmissionConfirmationState
import lantern.protocol.GroupAdmissionEvidence
import lantern.protocol.GroupRootAdoptionAttempt
import lantern.protocol.GroupRootAdoptionFailure
import lantern.protocol.GroupRootAdoptionHandover
import lantern.protocol.GroupRootAdoptionJournal
import lantern.protocol.GroupRootAdoptionJournalCodec
import lantern.protocol.GroupRootAdoptionState
import lantern.protocol.GroupAdmissionProof
import lantern.protocol.ProtocolHandshakeOffers
import lantern.protocol.Wire
import java.io.Closeable
import java.io.IOException
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import kotlin.coroutines.cancellation.CancellationException

/**
 * Owns one selected, mutually pinned TLS socket during a new member's comparison.
 * The received root is only a candidate. Core rules remain in GroupRootAdoptionAttempt;
 * this adapter owns OS signatures, bounded framing, idle expiry and terminal socket abort.
 * The caller supplies verified offers from THIS channel after retiring its bootstrap owner.
 * Handover keeps the SAME socket/timer owner and routes lifecycle to the live continuation;
 * no resource is released to an unguarded caller. Reads after handover observe EOF/failure
 * only; additional data is rejected, not interpreted as a new protocol or commit message.
 * Local commit uses policy A; no Node caller or application traffic is enabled here.
 */
internal class GroupRootAdoptionConnection private constructor(
    private val socket: SSLSocket,
    private val identity: Identity,
    private val repository: LocalGroupRepository,
    private val attempt: GroupRootAdoptionAttempt,
    private val offers: ProtocolHandshakeOffers,
    private val proof: GroupAdmissionProof,
    private val certificates: Map<String, X509Certificate>,
) : Closeable {
    private val input = socket.inputStream
    private val output = socket.outputStream
    private val decoder = GroupAdmissionConfirmationFrameDecoder()
    private val stateLock = Any()
    private val readerLock = Any()
    private val writerLock = Any()
    private val cleanupStarted = AtomicBoolean()
    private val cleanupFinished = CountDownLatch(1)
    private var expiryTask: ScheduledFuture<*>? = null
    private var prepared = false
    private var closed = false
    private var continuation: GroupRootAdoptionHandover? = null
    private var localConfirmation: GroupAdmissionConfirmation? = null
    private var remoteConfirmation: GroupAdmissionConfirmation? = null
    private var ioInFlight = 0

    @Volatile
    var cleanupFailure: Throwable? = null
        private set

    val state: GroupRootAdoptionState
        get() = guarded { synchronized(stateLock) { snapshotLocked() } }

    /** Keep the repository alive until this owner has been closed and all I/O joined. */
    fun prepare(currentIdentity: Identity): Boolean = guarded {
        synchronized(stateLock) {
            if (!comparingLocked() || prepared) return@synchronized false
            val accepted = attempt.prepare(currentIdentity.id, repository)
            prepared = accepted
            val active = activeLocked()
            accepted && active
        }
    }

    fun comparison(): GroupAdmissionComparison? = guarded {
        synchronized(stateLock) {
            if (!prepared || !comparingLocked()) return@synchronized null
            val comparison = attempt.comparison()
            if (activeLocked()) comparison else null
        }
    }

    /** Called only after the user compares the complete code on both physical devices. */
    fun confirm(comparison: GroupAdmissionComparison): Boolean = guardedIo {
        val signing = synchronized(stateLock) {
            if (!prepared || !comparingLocked()) return@synchronized null
            val request = attempt.confirm(comparison)
            if (activeLocked()) request else null
        } ?: return@guardedIo false
        // Neither OS signing nor TLS write holds the lifecycle lock.
        val signature = identity.sign(signing.bytes)
        val sending = synchronized(stateLock) {
            if (!activeLocked()) return@synchronized null
            val request = attempt.signed(signing, signature)
            if (activeLocked()) request else null
        } ?: return@guardedIo false
        val bytes = GroupAdmissionConfirmationFrameDecoder.encode(sending)
        synchronized(writerLock) {
            if (!synchronized(stateLock) { activeLocked() }) return@guardedIo false
            output.write(bytes)
            output.flush()
            synchronized(stateLock) {
                if (!activeLocked()) return@synchronized false
                val accepted = attempt.sent(sending)
                if (accepted) localConfirmation = GroupAdmissionConfirmation(sending.sender, sending.recipient, sending.signature)
                val active = activeLocked()
                accepted && active
            }
        }
    }

    /** One bounded chunk, not necessarily a complete or valid remote confirmation. */
    fun readChunk(): Boolean = guardedIo {
        synchronized(readerLock) {
            synchronized(stateLock) {
                if (!prepared || !activeLocked()) return@guardedIo false
                val remaining = remainingLocked()
                if (remaining == null) {
                    snapshotLocked()
                    return@guardedIo false
                }
                socket.soTimeout = remaining.toInt()
            }
            val buffer = ByteArray(GroupAdmissionConfirmationFrameDecoder.MAX_CHUNK_BYTES)
            val count = input.read(buffer)
            synchronized(stateLock) {
                if (!activeLocked()) return@synchronized false
                if (count < 0) {
                    try {
                        if (continuation == null) decoder.finish()
                    } finally {
                        transportClosedLocked()
                        snapshotLocked()
                    }
                    return@synchronized false
                }
                if (count == 0) throw IOException("Root confirmation stream made no progress")
                if (continuation != null) throw IOException("Unexpected data after root adoption handover")
                for (confirmation in decoder.accept(buffer.copyOf(count))) {
                    if (!attempt.receive(confirmation.sender, confirmation.recipient, confirmation.signature)) {
                        snapshotLocked()
                        return@synchronized false
                    }
                    remoteConfirmation = confirmation
                }
                activeLocked()
            }
        }
    }

    /**
     * Switches this transport owner to its revocable continuation without moving resources.
     * Caller supplies a fresh OS-generated attempt ID and serializes identity/group changes.
     * Null while not fully confirmed, already handed over or ANY old I/O/signing is pending;
     * no wait/drain under the lifecycle lock. Join those calls before retrying.
     * Returned material is not staged, membership or a commit acknowledgement.
     */
    fun handover(currentIdentity: Identity, attemptId: String): PendingGroupAdoption? = guarded {
        synchronized(stateLock) {
            if (!prepared || !comparingLocked() || ioInFlight != 0) return@synchronized null
            if (attempt.state() != GroupRootAdoptionState.Active(GroupAdmissionConfirmationState.Confirmed)) return@synchronized null
            val evidence = GroupAdmissionEvidence(proof, proof.admissions.map { it.claim.issuerId }.distinct().map { pin ->
                certificate(pin, checkNotNull(certificates[pin]) { "Missing root admission certificate" })
            })
            val memberCertificate = certificate(identity.id, identity.certificate)
            val journal = GroupRootAdoptionJournal(evidence, offers.local, offers.remote, memberCertificate,
                checkNotNull(localConfirmation), checkNotNull(remoteConfirmation))
            val record = PendingGroupAdoption(attemptId, identity.id, offers.remote.identity, proof.anchor,
                GroupRootAdoptionJournalCodec.encode(journal))
            val next = attempt.handover(currentIdentity.id, repository, record, evidence, memberCertificate)
                ?: return@synchronized null
            continuation = next
            // No partial pre-handover frame may be silently discarded at the phase boundary.
            decoder.finish()
            localConfirmation = null
            remoteConfirmation = null
            if (activeLocked()) record else null
        }
    }

    /** Call after handover, with joined I/O and current OS identity, on the lifecycle worker. */
    fun commitLocal(currentIdentity: Identity, replacingInterrupted: PendingGroupAdoption? = null): Boolean = guarded {
        synchronized(stateLock) {
            if (ioInFlight != 0 || !activeLocked()) return@synchronized false
            val next = continuation ?: return@synchronized false
            val store = repository as? GroupAdoptionRepository
                ?: error("Root owner needs a durable adoption repository")
            val committed = next.commitLocal(currentIdentity.id, store, replacingInterrupted)
            snapshotLocked()
            committed
        }
    }

    override fun close() = lifecycle({ attempt.cancel() }, { it.cancel() })
    fun block() = lifecycle({ attempt.block() }, { it.block() })
    fun leaveGroup() = lifecycle({ attempt.leaveGroup() }, { it.leaveGroup() })

    private fun lifecycle(event: () -> Unit, continued: (GroupRootAdoptionHandover) -> Unit): Unit = guarded {
        synchronized(stateLock) {
            if (activeLocked()) continuation?.let(continued) ?: event()
            snapshotLocked()
        }
    }

    private fun activeLocked(): Boolean = snapshotLocked() is GroupRootAdoptionState.Active
    private fun comparingLocked(): Boolean = continuation == null && activeLocked()
    private fun remainingLocked(): Long? {
        val previous = attempt.remainingMillis()
        val next = continuation
        return if (next == null) previous else next.remainingMillis()
    }
    private fun transportClosedLocked() {
        val next = continuation
        if (next == null) attempt.transportClosed() else next.transportClosed()
    }

    private fun snapshotLocked(): GroupRootAdoptionState {
        // A trusted clock callback may reenter handover during attempt.state(). Observe
        // the installed continuation AFTER that callback, never publish a stale phase.
        val previous = attempt.state()
        val current = continuation?.rootState() ?: previous
        if (current is GroupRootAdoptionState.Closed || current == GroupRootAdoptionState.Committed ||
            current == GroupRootAdoptionState.CommitOutcomeUnknown) {
            closed = true
            localConfirmation = null
            remoteConfirmation = null
            decoder.close()
            expiryTask?.cancel(false)
            expiryTask = null
        }
        return current
    }

    private fun armDeadline(scheduler: ScheduledExecutorService): Unit = guarded {
        synchronized(stateLock) {
            if (!activeLocked()) return@synchronized
            val remaining = remainingLocked()
            if (remaining == null) {
                snapshotLocked()
                return@synchronized
            }
            expiryTask = scheduler.schedule({ armDeadline(scheduler) }, remaining, TimeUnit.MILLISECONDS)
        }
    }

    private inline fun <T> guarded(operation: () -> T): T {
        var primary: Throwable? = null
        try {
            return operation()
        } catch (error: Throwable) {
            primary = error
            synchronized(stateLock) {
                try {
                    if (error is CancellationException) continuation?.cancel() ?: attempt.cancel() else transportClosedLocked()
                    snapshotLocked()
                } catch (stateError: Throwable) {
                    if (stateError !== error) error.addSuppressed(stateError)
                }
                closed = true
                decoder.close()
                expiryTask?.cancel(false)
                expiryTask = null
            }
            throw error
        } finally {
            if (synchronized(stateLock) { closed }) {
                try {
                    if (cleanupStarted.compareAndSet(false, true)) {
                        try { abortSocket(socket) } catch (error: Throwable) {
                            cleanupFailure = error
                            throw error
                        } finally { cleanupFinished.countDown() }
                    } else cleanupFinished.await()
                } catch (cleanupError: Throwable) {
                    if (cleanupError is InterruptedException) Thread.currentThread().interrupt()
                    if (primary == null) throw cleanupError
                    if (primary !== cleanupError) primary.addSuppressed(cleanupError)
                }
            }
        }
    }

    private inline fun <T> guardedIo(operation: () -> T): T {
        synchronized(stateLock) { ioInFlight++ }
        try { return guarded(operation) } finally { synchronized(stateLock) { ioInFlight-- } }
    }

    private fun certificate(pin: String, value: X509Certificate) =
        GroupAdmissionCertificate(pin, Base64.getEncoder().encodeToString(value.encoded))

    companion object {
        /** Socket ownership transfers even on error; database and scheduler remain caller-owned. */
        fun adopt(
            socket: SSLSocket,
            identity: Identity,
            repository: LocalGroupRepository,
            offers: ProtocolHandshakeOffers,
            proof: GroupAdmissionProof,
            issuerCertificates: Map<String, X509Certificate>,
            selectedPeerIdentity: String,
            selectedAtMillis: Long,
            scheduler: ScheduledExecutorService,
            nowMillis: () -> Long = { System.nanoTime() / 1_000_000 },
        ): GroupRootAdoptionConnection {
            try {
                require(issuerCertificates.size <= GroupAdmissionChainVerification.MAX_ADMISSIONS) { "Too many issuer certificates" }
                require(issuerCertificates.keys.all(Wire::isFingerprint)) { "Invalid issuer certificate pin" }
                val session = socket.session
                require(session.protocol == "TLSv1.3") { "TLS 1.3 required" }
                require(digest(session.localCertificates.single().encoded) == identity.id) { "Local root TLS identity mismatch" }
                val peerCertificate = session.peerCertificates.single() as X509Certificate
                val peerPin = digest(peerCertificate.encoded)
                val certificates = issuerCertificates.toMap() + mapOf(identity.id to identity.certificate, peerPin to peerCertificate)
                val verifier = GroupAdmissionCertificateVerifier(certificates::get)
                val attempt = GroupRootAdoptionAttempt(offers, identity.id, selectedPeerIdentity,
                    peerPin, proof, selectedAtMillis, nowMillis, verifier::verify,
                    { bytes, signature -> verifier.verify(peerPin, bytes, signature) })
                socket.setSoLinger(true, 0)
                return GroupRootAdoptionConnection(socket, identity, repository, attempt, offers, proof, certificates)
                    .also { it.armDeadline(scheduler) }
            } catch (error: Throwable) {
                try { abortSocket(socket) } catch (cleanupError: Throwable) {
                    if (cleanupError !== error) error.addSuppressed(cleanupError)
                }
                throw error
            }
        }

        private fun abortSocket(socket: SSLSocket) {
            if (socket.isClosed) return
            var primary: Throwable? = null
            try { socket.shutdownInput() } catch (_: SSLException) {
                // Terminal abort: missing close_notify must not drain pending peer data.
            } catch (error: Throwable) { primary = error }
            try { socket.close() } catch (error: Throwable) {
                val previous = primary
                if (previous == null) primary = error else if (previous !== error) previous.addSuppressed(error)
            }
            primary?.let { throw it }
        }
    }
}
