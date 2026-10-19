package lantern.connectivity

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import lantern.domain.GroupAdmissionFailure
import lantern.domain.GroupAdmissionRole
import lantern.domain.GroupAdmissionState
import lantern.domain.GroupMembershipController
import lantern.domain.GroupMembershipCheckState
import lantern.domain.GroupAdoptionRepository
import lantern.domain.GroupTrustAnchor
import lantern.domain.Peer
import lantern.domain.PendingGroupAdoption
import lantern.protocol.GroupAdmissionBridgeState
import lantern.protocol.GroupAdmissionConfirmationState
import lantern.protocol.GroupRootAdoptionState
import lantern.protocol.GroupMembershipEvidenceCodec
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeAttempt
import lantern.protocol.Wire
import java.io.Closeable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLSocket
import kotlin.coroutines.cancellation.CancellationException

internal enum class GroupSelectionMode { ADMISSION, MEMBERSHIP_CHECK }

/**
 * One exclusive admission or membership-check selection per Node. Uses its listener/discovery, but never wire 0,
 * peer trust or chat. All database/OS/network work runs on the supplied Node IO scope.
 * Founders and durably adopted members issue through the same verified local-proof producer.
 * Node closes this owner and joins its workers before the caller releases the database.
 */
internal class GroupAdmissionService(
    private val identity: Identity,
    private val repository: GroupAdoptionRepository?,
    private val scope: CoroutineScope,
    private val running: () -> Boolean,
) : GroupMembershipController, AutoCloseable {
    private val mutable = MutableStateFlow<GroupAdmissionState>(GroupAdmissionState.Idle)
    override val admissionState = mutable.asStateFlow()
    private val revision = MutableStateFlow(0L)
    override val membershipRevision = revision.asStateFlow()
    private val membershipCheck = MutableStateFlow<GroupMembershipCheckState>(GroupMembershipCheckState.Idle)
    override val membershipCheckState = membershipCheck.asStateFlow()
    private val selected = AtomicReference<Selection?>()
    private val scheduler = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "lantern-group-deadline").apply { isDaemon = true }
    }

    private enum class Phase { LIVE, COMMITTING, FINISHED, CANCELLED }

    private class Selection(val peer: Peer, val selectedAt: Long, val mode: GroupSelectionMode) {
        val phase = AtomicReference(Phase.LIVE)
        val claimed = AtomicBoolean()
        val click = CompletableDeferred<Unit>()
        val owner = AtomicReference<Closeable?>()
        @Volatile var socket: SSLSocket? = null
        @Volatile var ready = false
        @Volatile var comparison: GroupAdmissionState.Comparing? = null
        var anchor: GroupTrustAnchor? = null
        var membership: PendingGroupAdoption? = null
        var replacing: PendingGroupAdoption? = null
        var expiry: Job? = null
    }

    val active: Boolean get() = selected.get() != null
    /** Bind each TLS handshake to the exact selection, never adopt an earlier live socket. */
    fun selectionToken(): Any? = selected.get()
    fun matchesSelection(token: Any?): Boolean = selected.get() === token
    fun selectedPeer(): Peer? = selected.get()?.takeIf(::eligible)?.peer
    fun allowsHandshake(peerId: String): Boolean = selected.get()?.let { it.peer.id == peerId && eligible(it) } == true

    private fun eligible(selection: Selection) = selection.ready && !selection.claimed.get() &&
        selection.phase.get() == Phase.LIVE && now() - selection.selectedAt in 0 until ProtocolHandshakeAttempt.TIMEOUT_MILLIS

    override fun selectGroupPeer(peer: Peer, replaceInterrupted: Boolean) = select(peer, replaceInterrupted, null)
    override fun verifyGroupPeer(peer: Peer) = select(peer, false, null, GroupSelectionMode.MEMBERSHIP_CHECK)

    /** Wait for Node's old PoC sockets to drain before permitting a different protocol. */
    fun select(peer: Peer, replaceInterrupted: Boolean, previousCleanup: Job?, mode: GroupSelectionMode = GroupSelectionMode.ADMISSION) {
        if (!running() || peer.id == identity.id || !Wire.isFingerprint(peer.id) || peer.port !in 1..65535) return
        cancelGroup()
        val selection = Selection(peer, now(), mode)
        selected.set(selection)
        if (mode == GroupSelectionMode.ADMISSION) mutable.value = GroupAdmissionState.Selecting(peer)
        else membershipCheck.value = GroupMembershipCheckState.Checking(peer)
        selection.expiry = scope.launch {
            delay(ProtocolHandshakeAttempt.TIMEOUT_MILLIS)
            if (selection.phase.compareAndSet(Phase.LIVE, Phase.CANCELLED)) {
                publishFailure(selection, GroupAdmissionFailure.FAILED)
                selection.click.cancel()
                retire(selection)
            }
        }
        scope.launch {
            try {
                previousCleanup?.join()
                val store = repository ?: error("Durable group repository unavailable")
                selection.anchor = store.localGroup()
                selection.membership = store.committedGroupAdoption()
                if (mode == GroupSelectionMode.MEMBERSHIP_CHECK) {
                    check(selection.anchor != null) { "No local membership" }
                    // Reject unusable local credentials before enabling a selected TLS pin.
                    // The live exchange revalidates OS certificates, which may expire meanwhile.
                    prepareLocalMembership(identity, store)
                    checkMembership(selection, store)
                }
                val interrupted = if (mode == GroupSelectionMode.ADMISSION) store.pendingGroupAdoption() else null
                if (interrupted != null) {
                    if (!replaceInterrupted) {
                        fail(selection, GroupAdmissionFailure.INTERRUPTED)
                        return@launch
                    }
                    check(interrupted.localIdentity == identity.id && selection.anchor == null)
                    selection.replacing = interrupted
                }
                if (current(selection) && selection.phase.get() == Phase.LIVE) selection.ready = true
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                fail(selection, GroupAdmissionFailure.UNAVAILABLE)
            }
        }
    }

    override fun confirmGroup(comparison: GroupAdmissionState.Comparing) {
        val selection = selected.get() ?: return
        if (selection.phase.get() == Phase.LIVE && selection.comparison === comparison && current(selection)) {
            selection.click.complete(Unit)
        }
    }

    override fun cancelGroup() {
        selected.getAndSet(null)?.let { previous ->
            previous.phase.compareAndSet(Phase.LIVE, Phase.CANCELLED)
            previous.expiry?.cancel()
            previous.click.cancel()
            scope.launch { retire(previous) }
        }
        mutable.value = GroupAdmissionState.Idle
        membershipCheck.value = GroupMembershipCheckState.Idle
    }

    fun block(peerId: String) {
        if (selected.get()?.peer?.id == peerId) cancelGroup()
    }

    /** Consumes only the selected v1 socket. Called after mutual TLS and pin verification. */
    suspend fun handle(socket: SSLSocket, peerId: String, token: Any) {
        val selection = selected.get() ?: error("No group selection")
        check(selection === token && selection.peer.id == peerId && eligible(selection) && selection.claimed.compareAndSet(false, true))
        selection.socket = socket
        try {
            checkLive(selection)
            val anchor = selection.anchor
            val localRole = if (anchor == null) CANDIDATE_FEATURE else ISSUER_FEATURE
            val remoteRole = if (anchor == null) ISSUER_FEATURE else CANDIDATE_FEATURE
            val capabilities = if (selection.mode == GroupSelectionMode.MEMBERSHIP_CHECK)
                ProtocolCapabilities(1, setOf(GroupMembershipEvidenceCodec.FEATURE), setOf(GroupMembershipEvidenceCodec.FEATURE))
            else ProtocolCapabilities(1, setOf(ADMISSION_FEATURE, localRole), setOf(ADMISSION_FEATURE))
            val bootstrap = HandshakeV1Connection.adopt(socket, identity, capabilities,
                peerId, selection.selectedAt, scheduler)
            install(selection, bootstrap)
            check(bootstrap.start() && bootstrap.readNext())
            if (selection.mode == GroupSelectionMode.MEMBERSHIP_CHECK) {
                verifyMembership(selection, bootstrap)
                return
            }
            val remoteFeatures = checkNotNull(bootstrap.remoteCapabilitiesForGroup()).supportedFeatures
            // Public role metadata prevents two readers/two issuers from waiting in the wrong
            // phase. It grants no authority: actual root/proof/signatures/consent are mandatory.
            check(remoteRole in remoteFeatures && localRole !in remoteFeatures)
            if (anchor == null) receive(selection, bootstrap) else issue(selection, bootstrap, anchor)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            fail(selection, GroupAdmissionFailure.FAILED)
        } finally {
            selection.expiry?.cancel()
            retire(selection)
        }
    }

    private fun verifyMembership(selection: Selection, bootstrap: HandshakeV1Connection) {
        val store = checkNotNull(repository)
        val anchor = checkNotNull(selection.anchor)
        checkLive(selection)
        checkMembership(selection, store)
        val local = prepareLocalMembership(identity, store)
        checkLive(selection)
        checkMembership(selection, store)
        val remote = checkNotNull(bootstrap.exchangeMembership(local))
        check(verifyPeerMembership(remote, anchor, selection.peer.id))
        checkLive(selection)
        checkMembership(selection, store)
        check(selection.phase.compareAndSet(Phase.LIVE, Phase.FINISHED))
        membershipCheck.update { if (current(selection)) GroupMembershipCheckState.Verified(selection.peer, anchor.groupId) else it }
        // A local result only. Last writer must not reset queued TLS bytes before the peer
        // consumes them. Peer close/invalid data/timer/cancel all reach finally and close.
        if (identity.id > selection.peer.id) bootstrap.awaitMembershipPeerClose()
    }

    private suspend fun issue(selection: Selection, bootstrap: HandshakeV1Connection, anchor: GroupTrustAnchor) {
        val store = checkNotNull(repository)
        checkLive(selection)
        checkMembership(selection, store)
        val evidence = prepareLocalGroupAdmission(identity, store, selection.peer.id)
        checkLive(selection)
        checkMembership(selection, store)
        val group = checkNotNull(bootstrap.sendEvidenceAndTransfer(anchor, evidence))
        install(selection, group)
        check(group.prepare())
        val ticket = checkNotNull(group.comparison())
        awaitComparison(selection, GroupAdmissionRole.ISSUER, anchor.groupId, ticket.bytes)
        checkLive(selection)
        checkMembership(selection, store)
        check(group.confirm(ticket))
        publish(selection, GroupAdmissionState.AwaitingPeer(selection.peer))
        while (group.state != GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Confirmed)) {
            checkLive(selection)
            check(group.readChunk())
        }
        check(selection.phase.compareAndSet(Phase.LIVE, Phase.FINISHED))
        selection.expiry?.cancel()
        publish(selection, GroupAdmissionState.Completed(anchor.groupId, adoptedLocally = false))
        // Local write + remote signature are NOT proof of the member's SQLite commit.
        // Keep TLS alive until the member commits/retires (or the original owner expires).
        try {
            while (group.readChunk()) Unit
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            // Both signatures were already observed, not a remote commit acknowledgement.
        }
    }

    private fun checkMembership(selection: Selection, store: GroupAdoptionRepository) {
        check(store.localGroup() == selection.anchor)
        val current = store.committedGroupAdoption()
        val saved = selection.membership
        check(if (saved == null) current == null else current != null && saved.sameRecord(current))
    }

    private suspend fun receive(selection: Selection, bootstrap: HandshakeV1Connection) {
        val store = checkNotNull(repository)
        val root = checkNotNull(bootstrap.receiveRootEvidenceAndTransfer(store))
        install(selection, root)
        check(root.prepare(identity))
        val ticket = checkNotNull(root.comparison())
        // The candidate group ID is already bound to the full comparison; do not infer trust.
        awaitComparison(selection, GroupAdmissionRole.NEW_MEMBER, root.candidateAnchor.groupId, ticket.bytes)
        checkLive(selection)
        check(root.confirm(ticket))
        publish(selection, GroupAdmissionState.AwaitingPeer(selection.peer))
        while (root.state != GroupRootAdoptionState.Active(GroupAdmissionConfirmationState.Confirmed)) {
            checkLive(selection)
            check(root.readChunk())
        }
        checkLive(selection)
        val record = checkNotNull(root.handover(identity, randomNonce()))
        // Nonblocking handoff arbitration. Cancellation before this CAS prevents commit;
        // after it is ordered after the in-flight local transaction (ADR 012 policy A).
        check(selection.phase.compareAndSet(Phase.LIVE, Phase.COMMITTING))
        try {
            check(root.commitLocal(identity, selection.replacing))
        } catch (error: Exception) {
            selection.phase.set(Phase.FINISHED)
            publish(selection, GroupAdmissionState.Failed(selection.peer,
                if (root.state == GroupRootAdoptionState.CommitOutcomeUnknown) GroupAdmissionFailure.COMMIT_OUTCOME_UNKNOWN
                else GroupAdmissionFailure.FAILED))
            throw error
        } finally {
            // A cancel/stop can hide this attempt's outcome but cannot roll back SQLite.
            // Wake read-only presentation even when this selection is no longer current.
            revision.update { it + 1 }
        }
        selection.phase.set(Phase.FINISHED)
        publish(selection, GroupAdmissionState.Completed(record.anchor.groupId, adoptedLocally = true))
    }

    private suspend fun awaitComparison(selection: Selection, role: GroupAdmissionRole, groupId: String, bytes: ByteArray) {
        checkLive(selection)
        val comparison = GroupAdmissionState.Comparing(selection.peer, role, groupId, digest(bytes))
        selection.comparison = comparison
        publish(selection, comparison)
        // No second read/sign operation while the UI owns the comparison. The owner timer
        // stays armed; EOF/write failure still invalidates before any local commit.
        selection.click.await()
        checkLive(selection)
    }

    private fun install(selection: Selection, owner: Closeable) {
        selection.owner.set(owner)
        if (!current(selection) || selection.phase.get() != Phase.LIVE) {
            owner.close()
            error("Admission retired")
        }
    }

    private fun checkLive(selection: Selection) {
        check(current(selection) && selection.phase.get() == Phase.LIVE)
        check(now() - selection.selectedAt in 0 until ProtocolHandshakeAttempt.TIMEOUT_MILLIS)
    }

    private fun current(selection: Selection) = running() && selected.get() === selection
    private fun publish(selection: Selection, value: GroupAdmissionState) {
        mutable.update { if (current(selection)) value else it }
    }

    private fun fail(selection: Selection, reason: GroupAdmissionFailure) {
        if (selection.phase.compareAndSet(Phase.LIVE, Phase.FINISHED)) {
            selection.expiry?.cancel()
            publishFailure(selection, reason)
        }
    }

    private fun publishFailure(selection: Selection, reason: GroupAdmissionFailure) {
        if (selection.mode == GroupSelectionMode.ADMISSION) publish(selection, GroupAdmissionState.Failed(selection.peer, reason))
        else membershipCheck.update { if (current(selection)) GroupMembershipCheckState.Failed(selection.peer, reason) else it }
    }

    private fun retire(selection: Selection) {
        try {
            try { selection.owner.getAndSet(null)?.close() } finally { selection.socket?.close() }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            fail(selection, GroupAdmissionFailure.FAILED)
        }
    }

    override fun close() {
        cancelGroup()
        scheduler.shutdownNow()
    }

    private fun now() = System.nanoTime() / 1_000_000

    private companion object {
        const val ADMISSION_FEATURE = "group-admission"
        const val ISSUER_FEATURE = "group-issuer"
        const val CANDIDATE_FEATURE = "group-candidate"
    }
}
