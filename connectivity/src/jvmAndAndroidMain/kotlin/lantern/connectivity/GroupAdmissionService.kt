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
import lantern.domain.GroupRosterTextController
import lantern.domain.StoredGroupText
import lantern.domain.GroupRosterState
import lantern.domain.GroupRosterFailure
import lantern.domain.GroupTextState
import lantern.domain.GroupTextFailure
import lantern.domain.GroupTextRepository
import lantern.domain.GroupTextContent
import lantern.domain.SignedGroupText
import lantern.domain.ContentLimits
import lantern.domain.GroupSessionState
import lantern.domain.SessionCandidate
import lantern.domain.SessionSelection
import lantern.domain.GroupMembershipCheckState
import lantern.domain.GroupAdoptionRepository
import lantern.domain.GroupTrustAnchor
import lantern.domain.Peer
import lantern.domain.PendingGroupAdoption
import lantern.protocol.GroupAdmissionBridgeState
import lantern.protocol.GroupAdmissionConfirmationState
import lantern.protocol.GroupRootAdoptionState
import lantern.protocol.GroupMembershipEvidenceCodec
import lantern.protocol.GroupSessionOffer
import lantern.protocol.GroupSessionOfferCodec
import lantern.protocol.GroupTextTransferCodec
import lantern.protocol.GroupTextTransferContext
import lantern.protocol.GroupTextDeliveryContext
import lantern.protocol.GroupRosterTextCodec
import lantern.protocol.GroupTextSavedReceipt
import lantern.protocol.GroupMembershipEvidence
import lantern.protocol.GroupTextCodec
import lantern.protocol.GroupTextReceiver
import lantern.protocol.GroupSessionRoster
import lantern.protocol.GroupSessionRosterCodec
import lantern.protocol.GroupSessionJoin
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeAttempt
import lantern.protocol.Wire
import java.io.Closeable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.UUID
import java.util.Base64
import javax.net.ssl.SSLSocket
import java.security.cert.X509Certificate
import kotlin.coroutines.cancellation.CancellationException

internal enum class GroupSelectionMode { ADMISSION, MEMBERSHIP_CHECK, SESSION, TEXT, ROSTER, ROSTER_TEXT }

/**
 * One exclusive group selection per Node. Uses its listener/discovery, never wire 0
 * or PoC peer trust. All database/OS/network work runs on the supplied Node IO scope.
 * Founders and durably adopted members issue through the same verified local-proof producer.
 * Node closes this owner and joins its workers before the caller releases the database.
 */
internal class GroupAdmissionService(
    private val identity: Identity,
    private val repository: GroupAdoptionRepository?,
    private val scope: CoroutineScope,
    private val running: () -> Boolean,
) : GroupRosterTextController, AutoCloseable {
    private val mutable = MutableStateFlow<GroupAdmissionState>(GroupAdmissionState.Idle)
    override val admissionState = mutable.asStateFlow()
    private val revision = MutableStateFlow(0L)
    override val membershipRevision = revision.asStateFlow()
    private val membershipCheck = MutableStateFlow<GroupMembershipCheckState>(GroupMembershipCheckState.Idle)
    override val membershipCheckState = membershipCheck.asStateFlow()
    private val sessionState = MutableStateFlow<GroupSessionState>(GroupSessionState.Idle)
    override val groupSessionState = sessionState.asStateFlow()
    private val textState = MutableStateFlow<GroupTextState>(GroupTextState.Idle)
    override val groupTextState = textState.asStateFlow()
    private val rosterState = MutableStateFlow<GroupRosterState>(GroupRosterState.Idle)
    override val groupRosterState = rosterState.asStateFlow()
    private val lastDelivery = MutableStateFlow<StoredGroupText?>(null)
    override val lastRosterTextDelivery = lastDelivery.asStateFlow()
    private val sessionLock = Any()
    // Only current-run, authenticated observations. Never read from history/discovery/SQLite.
    private var localSession: LocalSession? = null
    private class LocalSession(val anchor: GroupTrustAnchor, val membership: PendingGroupAdoption?, val candidate: SessionCandidate,
        val participants: Set<String>? = null, val roster: GroupSessionRoster? = null)
    private val selected = AtomicReference<Selection?>()
    private val scheduler = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "lantern-group-deadline").apply { isDaemon = true }
    }

    private enum class Phase { LIVE, COMMITTING, FINISHED, CANCELLED }

    private class Selection(val peer: Peer, val selectedAt: Long, val mode: GroupSelectionMode, val text: String?, val messageId: String?) {
        val sending: Boolean get() = text != null || messageId != null
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
        var sessionOffer: GroupSessionOffer? = null
        @Volatile var attemptedMessageId: String? = null
        @Volatile var textFailure = GroupTextFailure.FAILED
        @Volatile var rosterFailure = GroupRosterFailure.FAILED
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
    override fun negotiateGroupSession(peer: Peer) = select(peer, false, null, GroupSelectionMode.SESSION)
    override fun sendGroupText(peer: Peer, text: String) {
        require(ContentLimits.isValidText(text))
        select(peer, false, null, GroupSelectionMode.TEXT, text)
    }
    override fun receiveGroupText(peer: Peer) = select(peer, false, null, GroupSelectionMode.TEXT)
    override fun synchronizeGroupRoster(peer: Peer) = select(peer, false, null, GroupSelectionMode.ROSTER)
    override fun sendRosterText(peer: Peer, text: String) {
        require(ContentLimits.isValidText(text))
        select(peer, false, null, GroupSelectionMode.ROSTER_TEXT, text)
    }
    override fun receiveRosterText(peer: Peer) = select(peer, false, null, GroupSelectionMode.ROSTER_TEXT)
    override fun deliverRosterText(peer: Peer, messageId: String) =
        select(peer, false, null, GroupSelectionMode.ROSTER_TEXT, messageId = messageId)

    /** Wait for Node's old PoC sockets to drain before permitting a different protocol. */
    fun select(peer: Peer, replaceInterrupted: Boolean, previousCleanup: Job?, mode: GroupSelectionMode = GroupSelectionMode.ADMISSION,
        text: String? = null, messageId: String? = null) {
        if (!running() || peer.id == identity.id || !Wire.isFingerprint(peer.id) || peer.port !in 1..65535) return
        cancelGroup()
        val selection = Selection(peer, now(), mode, text, messageId)
        synchronized(sessionLock) { selected.set(selection) }
        when (mode) {
            GroupSelectionMode.ADMISSION -> mutable.value = GroupAdmissionState.Selecting(peer)
            GroupSelectionMode.MEMBERSHIP_CHECK -> membershipCheck.value = GroupMembershipCheckState.Checking(peer)
            GroupSelectionMode.SESSION -> sessionState.value = GroupSessionState.Negotiating(peer)
            GroupSelectionMode.TEXT, GroupSelectionMode.ROSTER_TEXT -> textState.value = GroupTextState.Waiting(peer, selection.sending)
            GroupSelectionMode.ROSTER -> rosterState.value = GroupRosterState.Synchronizing(peer)
        }
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
                if (mode != GroupSelectionMode.ADMISSION) {
                    check(selection.anchor != null) { "No local membership" }
                    // Reject unusable local credentials before enabling a selected TLS pin.
                    // The live exchange revalidates OS certificates, which may expire meanwhile.
                    prepareLocalMembership(identity, store)
                    checkMembership(selection, store)
                    if (mode == GroupSelectionMode.TEXT || mode == GroupSelectionMode.ROSTER_TEXT) {
                        check(store is GroupTextRepository) { "Group text repository unavailable" }
                        if (messageId != null) {
                            val saved = checkNotNull(store.groupText(messageId)).message
                            check(saved.content.authorId == identity.id && saved.content.groupId == selection.anchor?.groupId &&
                                peer.id in saved.content.recipients) { "Not an authored copy for this recipient" }
                        }
                    }
                    if (mode == GroupSelectionMode.SESSION || mode == GroupSelectionMode.TEXT || mode == GroupSelectionMode.ROSTER || mode == GroupSelectionMode.ROSTER_TEXT) {
                        val anchor = checkNotNull(selection.anchor)
                        val previous = synchronized(sessionLock) {
                            localSession?.takeIf {
                                it.anchor == anchor && sameMembership(it.membership, selection.membership)
                            }?.candidate
                        }
                        // OS randomness may initialize/block: never hold the cancellation lock here.
                        selection.sessionOffer = GroupSessionOffer(previous ?: SessionCandidate(anchor.groupId, randomNonce(), false),
                            established = previous != null)
                    }
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
        synchronized(sessionLock) { selected.getAndSet(null) }?.let { previous ->
            previous.phase.compareAndSet(Phase.LIVE, Phase.CANCELLED)
            previous.expiry?.cancel()
            previous.click.cancel()
            scope.launch { retire(previous) }
        }
        mutable.value = GroupAdmissionState.Idle
        membershipCheck.value = GroupMembershipCheckState.Idle
        sessionState.value = GroupSessionState.Idle
        textState.value = GroupTextState.Idle
        rosterState.value = GroupRosterState.Idle
    }

    /** Called by Node.stop under its run lock. A later LAN/run never revives this observation. */
    fun resetSessions() = synchronized(sessionLock) { localSession = null }

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
            val membershipFeatures = if (selection.mode == GroupSelectionMode.SESSION || selection.mode == GroupSelectionMode.TEXT || selection.mode == GroupSelectionMode.ROSTER || selection.mode == GroupSelectionMode.ROSTER_TEXT)
                setOf(GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE)
            else setOf(GroupMembershipEvidenceCodec.FEATURE)
            val capabilities = if (selection.mode == GroupSelectionMode.ROSTER_TEXT) {
                val required = GroupRosterTextCodec.requiredFeatures
                val role = if (selection.sending) GroupTextTransferCodec.SENDER_FEATURE else GroupTextTransferCodec.RECEIVER_FEATURE
                ProtocolCapabilities(1, required + role, required)
            } else if (selection.mode == GroupSelectionMode.TEXT) {
                val required = membershipFeatures + GroupTextTransferCodec.FEATURE
                val role = if (selection.text == null) GroupTextTransferCodec.RECEIVER_FEATURE else GroupTextTransferCodec.SENDER_FEATURE
                ProtocolCapabilities(1, required + role, required)
            } else if (selection.mode == GroupSelectionMode.ROSTER) {
                val required = membershipFeatures + GroupSessionRosterCodec.FEATURE
                ProtocolCapabilities(1, required, required)
            } else if (selection.mode != GroupSelectionMode.ADMISSION)
                ProtocolCapabilities(1, membershipFeatures, membershipFeatures)
            else ProtocolCapabilities(1, setOf(ADMISSION_FEATURE, localRole), setOf(ADMISSION_FEATURE))
            val bootstrap = HandshakeV1Connection.adopt(socket, identity, capabilities,
                peerId, selection.selectedAt, scheduler)
            install(selection, bootstrap)
            check(bootstrap.start() && bootstrap.readNext())
            if (selection.mode == GroupSelectionMode.MEMBERSHIP_CHECK) {
                verifyMembership(selection, bootstrap)
                return
            }
            if (selection.mode == GroupSelectionMode.SESSION) {
                negotiateSession(selection, bootstrap)
                return
            }
            if (selection.mode == GroupSelectionMode.TEXT || selection.mode == GroupSelectionMode.ROSTER_TEXT) {
                transferText(selection, bootstrap)
                return
            }
            if (selection.mode == GroupSelectionMode.ROSTER) {
                synchronizeRoster(selection, bootstrap)
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
        if (identity.id > selection.peer.id) bootstrap.awaitGroupExchangePeerClose()
    }

    private fun negotiateSession(selection: Selection, bootstrap: HandshakeV1Connection) {
        val store = checkNotNull(repository)
        val anchor = checkNotNull(selection.anchor)
        val offer = checkNotNull(selection.sessionOffer)
        checkLive(selection)
        checkMembership(selection, store)
        val local = prepareLocalMembership(identity, store)
        checkLive(selection)
        checkMembership(selection, store)
        val remote = checkNotNull(bootstrap.negotiateSession(local, offer) { evidence ->
            checkLive(selection)
            checkMembership(selection, store)
            val verified = verifyPeerMembership(evidence, anchor, selection.peer.id)
            checkLive(selection)
            checkMembership(selection, store)
            verified
        })
        val result = offer.select(anchor, remote)
        checkLive(selection)
        checkMembership(selection, store)
        synchronized(sessionLock) {
            checkLive(selection)
            check(selection.phase.compareAndSet(Phase.LIVE, Phase.FINISHED))
            when (result) {
                is SessionSelection.Join -> {
                    val participants = localSession?.takeIf { it.anchor == anchor && sameMembership(it.membership, selection.membership) &&
                        it.candidate.sessionId == result.session.sessionId }?.participants
                    localSession = LocalSession(anchor, selection.membership, result.session, participants,
                        localSession?.roster?.takeIf { participants != null && it.sessionId == result.session.sessionId })
                    sessionState.value = GroupSessionState.Selected(selection.peer, result.session)
                }
                is SessionSelection.Choose -> sessionState.value = GroupSessionState.NeedsChoice(selection.peer, result.sessions)
                SessionSelection.Create -> error("Two session offers cannot require creation")
            }
        }
        // A local decision, not an ACK or authorization for chat. Keep the last writer alive.
        if (identity.id > selection.peer.id) bootstrap.awaitGroupExchangePeerClose()
    }

    private fun transferText(selection: Selection, bootstrap: HandshakeV1Connection) {
        val store = checkNotNull(repository)
        val texts = store as GroupTextRepository
        val anchor = checkNotNull(selection.anchor)
        val offer = checkNotNull(selection.sessionOffer)
        fun checkContext() {
            checkLive(selection)
            checkMembership(selection, store)
        }
        fun markUsed(context: GroupTextDeliveryContext) = synchronized(sessionLock) {
            checkLive(selection)
            val held = checkNotNull(localSession)
            check(held.anchor == anchor && sameMembership(held.membership, selection.membership) &&
                held.candidate.sessionId == context.sessionId && held.participants == context.recipients)
            // Conservative before a potentially ambiguous commit. Never clear on failure/cancel.
            localSession = LocalSession(anchor, selection.membership, held.candidate.copy(used = true), held.participants, held.roster)
        }
        fun outgoing(context: GroupTextDeliveryContext): SignedGroupText {
            checkContext()
            val saved = selection.messageId?.let { checkNotNull(texts.groupText(it)).message }
            val signed = if (saved != null) {
                // A local copy is data, not permission. Current TLS/roster/scope must match it.
                if (saved.content.groupId != context.groupId || saved.content.sessionId != context.sessionId ||
                    saved.content.recipients.toSet() != context.recipients) {
                    selection.textFailure = GroupTextFailure.ROSTER_REQUIRED
                    error("Saved copy does not match the current session snapshot")
                }
                context.checkMessage(saved)
                check(Identity.verify(identity.certificate, GroupTextCodec.signedBytes(saved.content), saved.signature))
                saved
            } else {
                val counters = texts.reserveGroupTextCounters(anchor.groupId, identity.id)
                val content = GroupTextContent(UUID.randomUUID().toString(), anchor.groupId, context.sessionId, identity.id,
                    counters.authorSequence, counters.logicalTime, context.recipients, checkNotNull(selection.text))
                SignedGroupText(content, identity.sign(GroupTextCodec.signedBytes(content)))
            }
            GroupTextCodec.encode(signed)
            checkContext()
            markUsed(context)
            selection.attemptedMessageId = signed.content.id
            checkContext()
            texts.saveGroupText(signed, identity.id)
            checkContext()
            return signed
        }
        fun incoming(context: GroupTextDeliveryContext, received: SignedGroupText, certificate: X509Certificate): GroupTextSavedReceipt {
            checkContext()
            val inboxStore = object : GroupTextRepository by texts {
                override fun saveGroupText(message: SignedGroupText, localIdentity: String): Boolean {
                    checkContext()
                    // Admission to the durable step is ordered with cancel/stop; an entered
                    // transaction may finish, but revocation prevents every later ACK.
                    markUsed(context)
                    selection.attemptedMessageId = message.content.id
                    return texts.saveGroupText(message, localIdentity)
                }
            }
            return GroupTextReceiver(inboxStore).receive(received, anchor.groupId, context.sessionId, identity.id, selection.peer.id,
                context.recipients, {
                    checkContext()
                    true
                }) { bytes, signature -> Identity.verify(certificate, bytes, signature) }
        }
        fun completed(saved: SignedGroupText) {
            checkContext()
            if (selection.sending) texts.acknowledgeGroupText(saved, selection.peer.id)
            val delivered = if (selection.sending && selection.mode == GroupSelectionMode.ROSTER_TEXT)
                checkNotNull(texts.groupText(saved.content.id)) else null
            checkContext()
            synchronized(sessionLock) {
                checkLive(selection)
                check(selection.phase.compareAndSet(Phase.LIVE, Phase.FINISHED))
                textState.value = if (selection.sending) GroupTextState.Sent(selection.peer, saved)
                    else GroupTextState.Received(selection.peer, saved)
                if (delivered != null) lastDelivery.value = delivered
            }
        }
        checkContext()
        if (selection.mode == GroupSelectionMode.ROSTER_TEXT) {
            val exchange = RosterExchange(selection)
            checkNotNull(bootstrap.transferRosterText(exchange.membership, offer, selection.sending,
                exchange::verifyRemote, exchange::propose, exchange::mergeVerified,
                installRoster = { roster ->
                    exchange.install(roster)
                    synchronized(sessionLock) {
                        checkLive(selection)
                        textState.value = GroupTextState.Transferring(selection.peer)
                    }
                }, outgoing = ::outgoing, incoming = ::incoming, completed = ::completed))
        } else {
            val local = prepareLocalMembership(identity, store)
            checkContext()
            checkNotNull(bootstrap.transferGroupText(local, offer, selection.sending,
                verifyRemote = { evidence ->
                    checkContext()
                    val valid = verifyPeerMembership(evidence, anchor, selection.peer.id)
                    checkContext()
                    valid
                },
                selectSession = { remote ->
                    checkContext()
                    val result = offer.select(anchor, remote)
                    if (result !is SessionSelection.Join) {
                        selection.textFailure = GroupTextFailure.SESSION_CHOICE_REQUIRED
                        error("Explicit session choice required")
                    }
                    val context = GroupTextTransferContext(anchor.groupId, result.session.sessionId,
                        if (selection.sending) identity.id else selection.peer.id,
                        if (selection.sending) selection.peer.id else identity.id)
                    synchronized(sessionLock) {
                        checkLive(selection)
                        val held = localSession?.takeIf { it.anchor == anchor && sameMembership(it.membership, selection.membership) &&
                            it.candidate.sessionId == result.session.sessionId }
                        // Legacy LTX cannot omit earlier/offline participants, even in an empty roster.
                        if ((result.session.used || held?.roster != null) && held?.participants != context.recipients) {
                            selection.textFailure = GroupTextFailure.ROSTER_REQUIRED
                            error("Authenticated session roster required")
                        }
                        localSession = LocalSession(anchor, selection.membership, result.session, context.recipients, held?.roster)
                        textState.value = GroupTextState.Transferring(selection.peer)
                    }
                    context
                }, outgoing = ::outgoing, incoming = ::incoming, completed = ::completed))
        }
    }

    private fun synchronizeRoster(selection: Selection, bootstrap: HandshakeV1Connection) {
        val exchange = RosterExchange(selection)
        checkNotNull(bootstrap.synchronizeRoster(exchange.membership, checkNotNull(selection.sessionOffer),
            exchange::verifyRemote, exchange::propose, exchange::mergeVerified,
            completed = { roster ->
                exchange.install(roster)
                synchronized(sessionLock) {
                    checkLive(selection)
                    check(selection.phase.compareAndSet(Phase.LIVE, Phase.FINISHED))
                    rosterState.value = GroupRosterState.Synchronized(selection.peer, roster.anchor.groupId, roster.sessionId, roster.participants.sorted())
                }
            }))
    }

    /** Same proof, union and install rules for diagnostic roster and the live text continuation. */
    private inner class RosterExchange(private val selection: Selection) {
        private val store = checkNotNull(repository)
        private val anchor = checkNotNull(selection.anchor)
        private val offer = checkNotNull(selection.sessionOffer)
        val membership = prepareLocalMembership(identity, store)
        private val certificate = GroupAdmissionCertificate(identity.id, Base64.getEncoder().encodeToString(identity.certificate.encoded))
        private var candidate: SessionCandidate? = null
        private var requiredParticipants = emptySet<String>()

        private fun checkContext() {
            checkLive(selection)
            checkMembership(selection, store)
        }

        fun verifyRemote(proof: GroupMembershipEvidence): Boolean {
            checkContext()
            val valid = verifyPeerMembership(proof, anchor, selection.peer.id)
            checkContext()
            return valid
        }

        fun propose(remote: GroupSessionOffer): GroupSessionRoster {
            checkContext()
            val decision = offer.select(anchor, remote)
            if (decision !is SessionSelection.Join) {
                selection.rosterFailure = GroupRosterFailure.SESSION_CHOICE_REQUIRED
                selection.textFailure = GroupTextFailure.SESSION_CHOICE_REQUIRED
                error("Explicit session choice required")
            }
            candidate = decision.session
            val held = synchronized(sessionLock) {
                checkLive(selection)
                localSession?.takeIf { it.anchor == anchor && sameMembership(it.membership, selection.membership) &&
                    it.candidate.sessionId == decision.session.sessionId }
            }
            requiredParticipants = held?.participants.orEmpty()
            val bytes = GroupSessionRosterCodec.signingBytes(decision.session.sessionId, membership, certificate)
            val own = GroupSessionJoin(decision.session.sessionId, membership, certificate, identity.sign(bytes))
            val proposal = GroupSessionRoster(anchor, decision.session.sessionId, listOf(own), held?.participants != null)
            val result = held?.roster?.let { proposal.merge(it) } ?: proposal
            checkContext()
            return result
        }

        fun mergeVerified(local: GroupSessionRoster, remote: GroupSessionRoster): GroupSessionRoster {
            checkContext()
            if (checkNotNull(candidate).used && !local.retainedSnapshot && !remote.retainedSnapshot) missing()
            GroupRootAdoptionJournalInspector.withVerifier { verify ->
                fun verifyCurrent(cert: GroupAdmissionCertificate, bytes: ByteArray, signature: String): Boolean {
                    checkContext()
                    val valid = verify(cert, bytes, signature)
                    checkContext()
                    return valid
                }
                check(local.verify(::verifyCurrent))
                check(remote.verify(::verifyCurrent))
            }
            val merged = local.merge(remote)
            if (!merged.participants.containsAll(requiredParticipants)) missing()
            checkContext()
            return merged
        }

        private fun missing(): Nothing {
            selection.rosterFailure = GroupRosterFailure.MISSING_PARTICIPANTS
            selection.textFailure = GroupTextFailure.ROSTER_REQUIRED
            error("Known session participants lack signed joins or retained snapshot")
        }

        fun install(roster: GroupSessionRoster) {
            checkContext()
            synchronized(sessionLock) {
                checkLive(selection)
                localSession = LocalSession(anchor, selection.membership, checkNotNull(candidate), roster.participants, roster)
            }
        }
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

    private fun sameMembership(a: PendingGroupAdoption?, b: PendingGroupAdoption?) =
        if (a == null) b == null else b != null && a.sameRecord(b)

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
        when (selection.mode) {
            GroupSelectionMode.ADMISSION -> publish(selection, GroupAdmissionState.Failed(selection.peer, reason))
            GroupSelectionMode.MEMBERSHIP_CHECK ->
                membershipCheck.update { if (current(selection)) GroupMembershipCheckState.Failed(selection.peer, reason) else it }
            GroupSelectionMode.SESSION -> synchronized(sessionLock) {
                // Checking selection inside a Flow CAS is not enough: cancelling then selecting
                // the same peer can restore an equal presentation value (ABA). Order publication
                // with the exact selection identity, just like successful session installation.
                if (current(selection)) sessionState.value = GroupSessionState.Failed(selection.peer, reason)
            }
            GroupSelectionMode.TEXT, GroupSelectionMode.ROSTER_TEXT -> synchronized(sessionLock) {
                if (current(selection)) textState.value = GroupTextState.Failed(selection.peer,
                    if (reason == GroupAdmissionFailure.UNAVAILABLE) GroupTextFailure.UNAVAILABLE else selection.textFailure,
                    selection.attemptedMessageId)
            }
            GroupSelectionMode.ROSTER -> synchronized(sessionLock) {
                if (current(selection)) rosterState.value = GroupRosterState.Failed(selection.peer,
                    if (reason == GroupAdmissionFailure.UNAVAILABLE) GroupRosterFailure.UNAVAILABLE else selection.rosterFailure)
            }
        }
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
        resetSessions()
        scheduler.shutdownNow()
    }

    private fun now() = System.nanoTime() / 1_000_000

    private companion object {
        const val ADMISSION_FEATURE = "group-admission"
        const val ISSUER_FEATURE = "group-issuer"
        const val CANDIDATE_FEATURE = "group-candidate"
    }
}
