package lantern.connectivity

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import lantern.domain.DeviceRepository
import lantern.domain.DiscoveryService
import lantern.domain.GroupAdmissionRole
import lantern.domain.GroupAdmissionFailure
import lantern.domain.GroupAdmissionState
import lantern.domain.GroupMembershipCheckState
import lantern.domain.GroupSessionState
import lantern.domain.GroupAdoptionRepository
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupState
import lantern.domain.Peer
import lantern.domain.PendingGroupAdoption
import lantern.persistence.openDesktopRepository
import lantern.protocol.GroupRootAdoptionJournalCodec
import lantern.protocol.GroupRootAdoptionJournalInspectionResult
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Three actual app Nodes; real TLS/P-256/SQLite and no live founder for the second admission. */
class DelegatedGroupAdmissionServiceTest {
    @Test
    fun reopenedMemberInvitesThirdDeviceWithFounderOfflineInBothTlsOrders() {
        for (issuerInitiates in listOf(true, false)) withDirectory { directory ->
            val ids = List(3) { createDesktopIdentity().identity() }.sortedBy { it.id }
            val founder = ids[1]
            val issuer = ids[if (issuerInitiates) 0 else 2]
            val candidate = ids[if (issuerInitiates) 2 else 0]
            val anchor = GroupTrustAnchor(randomNonce(), founder.id)
            val firstCode = adoptFirst(directory, founder, issuer, anchor)
            // Both original Nodes and databases have closed before the delegated issuer restarts.
            openDesktopRepository(directory.resolve("issuer.db")).use { issuerStore ->
                val original = assertNotNull(issuerStore.committedGroupAdoption())
                openDesktopRepository(directory.resolve("candidate.db")).use { candidateStore ->
                    node(issuer, issuerStore).use { issuing -> node(candidate, candidateStore).use { receiving ->
                        issuing.start()
                        receiving.start()
                        select(issuing, receiving)
                        val (offer, accept) = comparisons(issuing, receiving)
                        assertNotEquals(firstCode, accept.code)
                        assertEquals(GroupAdmissionRole.ISSUER, offer.role)
                        receiving.confirmGroup(accept)
                        awaitState(receiving) { it is GroupAdmissionState.AwaitingPeer }
                        assertNull(candidateStore.localGroup())
                        assertNull(candidateStore.pendingGroupAdoption())
                        issuing.confirmGroup(offer)
                        assertTrue((awaitState(receiving) { it is GroupAdmissionState.Completed } as GroupAdmissionState.Completed).adoptedLocally)
                        assertFalse((awaitState(issuing) { it is GroupAdmissionState.Completed } as GroupAdmissionState.Completed).adoptedLocally)
                        val record = assertNotNull(candidateStore.committedGroupAdoption())
                        assertEquals(anchor, record.anchor)
                        assertEquals(GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid,
                            GroupRootAdoptionJournalInspector.inspect(record, candidate.id))
                        val journal = GroupRootAdoptionJournalCodec.decode(record.payload())
                        assertEquals(listOf(founder.id, issuer.id), journal.evidence.proof.admissions.map { it.claim.issuerId })
                        assertEquals(listOf(issuer.id, candidate.id), journal.evidence.proof.admissions.map { it.claim.memberId })
                        assertTrue(original.sameRecord(assertNotNull(issuerStore.committedGroupAdoption())))
                        // Already adopted members authenticate their OWN paths, not a fresh
                        // issuer->candidate credential or another comparison/commit.
                        val candidateMarker = assertNotNull(candidateStore.committedGroupAdoption())
                        verifyMembers(issuing, receiving)
                        // Founder remains offline. A fresh live proof is required even after B4.
                        val session = negotiateSession(issuing, receiving)
                        assertEquals(anchor.groupId, session.session.groupId)
                        assertTrue(original.sameRecord(assertNotNull(issuerStore.committedGroupAdoption())))
                        assertTrue(candidateMarker.sameRecord(assertNotNull(candidateStore.committedGroupAdoption())))
                        assertEquals(0L, issuing.membershipRevision.value)
                        assertEquals(1L, receiving.membershipRevision.value)
                        for (store in listOf(issuerStore, candidateStore)) {
                            assertTrue(store.trusted().isEmpty())
                            assertTrue(store.history().isEmpty())
                            assertNull(store.pendingGroupAdoption())
                        }
                    } }
                }
            }
            openDesktopRepository(directory.resolve("candidate.db")).use { reopened ->
                LocalGroupService(candidate, reopened).use { display ->
                    val state = runBlocking { withTimeout(5_000) { display.state.first { it != LocalGroupState.Loading } } }
                    assertEquals(LocalGroupState.Adopted(anchor), state)
                }
                // The newly admitted third member can in turn prepare a complete next delegation.
                val next = prepareLocalGroupAdmission(candidate, reopened, createDesktopIdentity().identity().id)
                assertEquals(3, next.proof.admissions.size)
                assertEquals(3, next.certificates.size)
            }
        }
    }

    @Test
    fun founderAndReopenedMemberAuthenticateWithoutNewInviteInBothTlsOrders() {
        for (founderInitiates in listOf(true, false)) withDirectory { directory ->
            val identities = List(2) { createDesktopIdentity().identity() }.sortedBy { it.id }
            val founder = identities[if (founderInitiates) 0 else 1]
            val member = identities[if (founderInitiates) 1 else 0]
            val anchor = GroupTrustAnchor(randomNonce(), founder.id)
            adoptFirst(directory, founder, member, anchor)
            openDesktopRepository(directory.resolve("founder.db")).use { founderStore ->
                openDesktopRepository(directory.resolve("issuer.db")).use { memberStore ->
                    val original = assertNotNull(memberStore.committedGroupAdoption())
                    node(founder, founderStore).use { a -> node(member, memberStore).use { b ->
                        a.start()
                        b.start()
                        verifyMembers(a, b)
                        assertTrue(original.sameRecord(assertNotNull(memberStore.committedGroupAdoption())))
                        assertEquals(0L, a.membershipRevision.value)
                        assertEquals(0L, b.membershipRevision.value)
                        assertTrue(founderStore.trusted().isEmpty())
                        assertTrue(memberStore.trusted().isEmpty())
                        assertTrue(a.state.value.connected.isEmpty())
                        assertTrue(b.state.value.connected.isEmpty())
                        b.cancelGroup()
                        assertEquals(GroupMembershipCheckState.Idle, b.membershipCheckState.value)
                    } }
                }
            }
        }
    }

    @Test
    fun reopenedMembersNegotiateKeepEmptySessionAndForgetItOnServiceRestartInBothTlsOrders() {
        for (founderInitiates in listOf(true, false)) withDirectory { directory ->
            val ids = List(2) { createDesktopIdentity().identity() }.sortedBy { it.id }
            val founder = ids[if (founderInitiates) 0 else 1]
            val member = ids[if (founderInitiates) 1 else 0]
            val anchor = GroupTrustAnchor(randomNonce(), founder.id)
            adoptFirst(directory, founder, member, anchor)
            openDesktopRepository(directory.resolve("founder.db")).use { aStore ->
                openDesktopRepository(directory.resolve("issuer.db")).use { bStore ->
                    val original = assertNotNull(bStore.committedGroupAdoption())
                    val archivedSession = randomNonce()
                    // Historical SQL fixture, intentionally not a live authenticated observation.
                    aStore.save("archived-a", founder.id, archivedSession, "solo cronologia A", "test-fixture")
                    bStore.save("archived-b", member.id, archivedSession, "solo cronologia B", "test-fixture")
                    val historyA = aStore.history()
                    val historyB = bStore.history()
                    val forbidHistory = AtomicBoolean()
                    val boundaryA = object : DeviceRepository by aStore, GroupAdoptionRepository by aStore {
                        override fun history(): List<lantern.domain.ChatLine> {
                            check(!forbidHistory.get()) { "Negotiation must not read history" }
                            return aStore.history()
                        }
                    }
                    val boundaryB = object : DeviceRepository by bStore, GroupAdoptionRepository by bStore {
                        override fun history(): List<lantern.domain.ChatLine> {
                            check(!forbidHistory.get()) { "Negotiation must not read history" }
                            return bStore.history()
                        }
                    }
                    node(founder, boundaryA).use { a -> node(member, boundaryB).use { b ->
                        forbidHistory.set(true) // Node startup presentation already loaded history once.
                        a.start()
                        b.start()
                        awaitPorts(a, b)
                        val first = negotiateSession(a, b).session
                        assertEquals(anchor.groupId, first.groupId)
                        assertFalse(first.used)
                        assertEquals(64, first.sessionId.length)
                        assertNotEquals(archivedSession, first.sessionId)
                        assertEquals(first, negotiateSession(a, b).session)
                        // An unsuccessful new negotiation does not erase the running local session.
                        a.cancelGroup()
                        b.cancelGroup()
                        a.negotiateGroupSession(peer(b))
                        b.verifyGroupPeer(peer(a))
                        awaitSession(a) { it is GroupSessionState.Failed }
                        awaitMembership(b) { it is GroupMembershipCheckState.Failed }
                        assertEquals(first, negotiateSession(a, b).session)
                        // Returning one participant joins the session still held by the other.
                        b.stop()
                        b.start()
                        awaitPorts(a, b)
                        assertEquals(first, negotiateSession(a, b).session)
                        a.stop()
                        b.stop()
                        assertEquals(GroupSessionState.Idle, a.groupSessionState.value)
                        assertEquals(GroupSessionState.Idle, b.groupSessionState.value)
                        a.start()
                        b.start()
                        awaitPorts(a, b)
                        val fresh = negotiateSession(a, b).session
                        assertNotEquals(first.sessionId, fresh.sessionId)
                        assertTrue(original.sameRecord(assertNotNull(bStore.committedGroupAdoption())))
                        assertEquals(0L, a.membershipRevision.value)
                        assertEquals(0L, b.membershipRevision.value)
                        for (store in listOf(aStore, bStore)) {
                            assertEquals(anchor, store.localGroup())
                            assertTrue(store.trusted().isEmpty())
                            assertEquals(if (store === aStore) historyA else historyB, store.history())
                            assertNull(store.pendingGroupAdoption())
                        }
                        assertTrue(a.state.value.connected.isEmpty())
                        assertTrue(b.state.value.connected.isEmpty())
                    } }
                }
            }
        }
    }

    @Test
    fun exactMembershipChangeCannotRevivePreviousSessionEvenWithSameGroup() = withDirectory { directory ->
        val founder = createDesktopIdentity().identity()
        val member = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), founder.id)
        adoptFirst(directory, founder, member, anchor)
        openDesktopRepository(directory.resolve("founder.db")).use { aStore ->
            openDesktopRepository(directory.resolve("issuer.db")).use { bStore ->
                val original = assertNotNull(bStore.committedGroupAdoption())
                val current = AtomicReference(original)
                val boundary = object : DeviceRepository by bStore, GroupAdoptionRepository by bStore {
                    override fun committedGroupAdoption() = current.get()
                }
                node(founder, aStore).use { a -> node(member, boundary).use { b ->
                    a.start()
                    b.start()
                    awaitPorts(a, b)
                    val previous = negotiateSession(a, b).session
                    a.stop()
                    // Independent boundary change: same group and historical proof, different
                    // exact durable marker. Not a production migration/recovery operation.
                    current.set(PendingGroupAdoption(randomNonce(), original.localIdentity,
                        original.peerIdentity, original.anchor, original.payload()))
                    a.start()
                    awaitPorts(a, b)
                    val fresh = negotiateSession(a, b).session
                    assertNotEquals(previous.sessionId, fresh.sessionId)
                    assertEquals(anchor.groupId, fresh.groupId)
                    assertTrue(original.sameRecord(assertNotNull(bStore.committedGroupAdoption())))
                    assertTrue(aStore.trusted().isEmpty())
                    assertTrue(bStore.trusted().isEmpty())
                    assertNull(aStore.pendingGroupAdoption())
                    assertNull(bStore.pendingGroupAdoption())
                } }
            }
        }
    }

    @Test
    fun cancelledSlowSessionPreflightCannotPublishOrPreventFreshNegotiation() = withDirectory { directory ->
        val founder = createDesktopIdentity().identity()
        val member = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), founder.id)
        adoptFirst(directory, founder, member, anchor)
        openDesktopRepository(directory.resolve("founder.db")).use { aStore ->
            openDesktopRepository(directory.resolve("issuer.db")).use { bStore ->
                val entered = CountDownLatch(1)
                val released = CountDownLatch(1)
                val armed = AtomicBoolean(true)
                val caller = Thread.currentThread()
                val boundary = object : DeviceRepository by aStore, GroupAdoptionRepository by aStore {
                    override fun localGroup(): GroupTrustAnchor? {
                        if (armed.compareAndSet(true, false)) {
                            assertNotEquals(caller, Thread.currentThread())
                            entered.countDown()
                            check(released.await(5, TimeUnit.SECONDS))
                        }
                        return aStore.localGroup()
                    }
                    override fun pendingGroupAdoption(): PendingGroupAdoption? = error("Session never reads pending")
                }
                node(founder, boundary).use { a -> node(member, bStore).use { b ->
                    a.start()
                    b.start()
                    awaitPorts(a, b)
                    try {
                        a.negotiateGroupSession(peer(b))
                        assertTrue(entered.await(5, TimeUnit.SECONDS))
                        // Must return while SQLite/provider work is still pending off the UI thread.
                        a.cancelGroup()
                        assertEquals(GroupSessionState.Idle, a.groupSessionState.value)
                        a.stop()
                        assertEquals(GroupSessionState.Idle, a.groupSessionState.value)
                    } finally { released.countDown() }
                    a.start()
                    awaitPorts(a, b)
                    val selected = negotiateSession(a, b)
                    assertEquals(anchor.groupId, selected.session.groupId)
                    assertEquals(anchor, aStore.localGroup())
                    assertTrue(aStore.trusted().isEmpty())
                    assertTrue(bStore.trusted().isEmpty())
                    assertNull(aStore.pendingGroupAdoption())
                    assertNull(bStore.pendingGroupAdoption())
                } }
            }
        }
    }

    @Test
    fun sessionRejectsDifferentGroupsAndEmptyLocalMembershipWithoutWriting() = withDirectory { directory ->
        val left = createDesktopIdentity().identity()
        val right = createDesktopIdentity().identity()
        openDesktopRepository(directory.resolve("left.db")).use { aStore ->
            openDesktopRepository(directory.resolve("right.db")).use { bStore ->
                val aRoot = GroupTrustAnchor(randomNonce(), left.id)
                val bRoot = GroupTrustAnchor(randomNonce(), right.id)
                aStore.foundLocalGroup(aRoot, left.id)
                node(left, aStore).use { a -> node(right, bStore).use { b ->
                    a.start()
                    b.start()
                    awaitPorts(a, b)
                    b.negotiateGroupSession(peer(a))
                    val empty = awaitSession(b) { it is GroupSessionState.Failed } as GroupSessionState.Failed
                    assertEquals(GroupAdmissionFailure.UNAVAILABLE, empty.reason)
                    b.cancelGroup()
                    bStore.foundLocalGroup(bRoot, right.id)
                    a.negotiateGroupSession(peer(b))
                    b.negotiateGroupSession(peer(a))
                    awaitSession(a) { it is GroupSessionState.Failed }
                    awaitSession(b) { it is GroupSessionState.Failed }
                    assertEquals(aRoot, aStore.localGroup())
                    assertEquals(bRoot, bStore.localGroup())
                    for (store in listOf(aStore, bStore)) {
                        assertTrue(store.trusted().isEmpty())
                        assertTrue(store.history().isEmpty())
                        assertNull(store.pendingGroupAdoption())
                        assertNull(store.committedGroupAdoption())
                    }
                } }
            }
        }
    }

    @Test
    fun differentGroupsAndAdmissionModeMismatchFailWithoutCreatingTrust() = withDirectory { directory ->
        val aIdentity = createDesktopIdentity().identity()
        val bIdentity = createDesktopIdentity().identity()
        openDesktopRepository(directory.resolve("a.db")).use { aStore ->
            openDesktopRepository(directory.resolve("b.db")).use { bStore ->
                val aAnchor = GroupTrustAnchor(randomNonce(), aIdentity.id)
                val bAnchor = GroupTrustAnchor(randomNonce(), bIdentity.id)
                aStore.foundLocalGroup(aAnchor, aIdentity.id)
                bStore.foundLocalGroup(bAnchor, bIdentity.id)
                node(aIdentity, aStore).use { a -> node(bIdentity, bStore).use { b ->
                    a.start()
                    b.start()
                    selectMembership(a, b)
                    awaitMembership(a) { it is GroupMembershipCheckState.Failed }
                    awaitMembership(b) { it is GroupMembershipCheckState.Failed }
                    a.cancelGroup()
                    b.cancelGroup()
                    a.verifyGroupPeer(peer(b))
                    b.selectGroupPeer(peer(a))
                    awaitMembership(a) { it is GroupMembershipCheckState.Failed }
                    awaitState(b) { it is GroupAdmissionState.Failed }
                    assertEquals(aAnchor, aStore.localGroup())
                    assertEquals(bAnchor, bStore.localGroup())
                    for (store in listOf(aStore, bStore)) {
                        assertTrue(store.trusted().isEmpty())
                        assertTrue(store.history().isEmpty())
                        assertNull(store.pendingGroupAdoption())
                        assertNull(store.committedGroupAdoption())
                    }
                } }
            }
        }
    }

    @Test
    fun corruptCommittedProofCannotInviteOrModifyEitherDatabase() = withDirectory { directory ->
        val founder = createDesktopIdentity().identity()
        val issuer = createDesktopIdentity().identity()
        val candidate = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), founder.id)
        adoptFirst(directory, founder, issuer, anchor)
        openDesktopRepository(directory.resolve("issuer.db")).use { store ->
            val original = assertNotNull(store.committedGroupAdoption())
            val altered = original.payload().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            val corrupt = PendingGroupAdoption(original.attemptId, original.localIdentity, original.peerIdentity, anchor, altered)
            val boundary = object : DeviceRepository by store, GroupAdoptionRepository by store {
                override fun committedGroupAdoption() = corrupt
            }
            openDesktopRepository(directory.resolve("candidate.db")).use { receivingStore ->
                node(issuer, boundary).use { issuing -> node(candidate, receivingStore).use { receiving ->
                    issuing.start()
                    receiving.start()
                    select(issuing, receiving)
                    awaitState(issuing) { it is GroupAdmissionState.Failed }
                    awaitState(receiving) { it is GroupAdmissionState.Failed }
                    assertNull(receivingStore.localGroup())
                    assertNull(receivingStore.pendingGroupAdoption())
                    assertNull(receivingStore.committedGroupAdoption())
                    assertTrue(original.sameRecord(assertNotNull(store.committedGroupAdoption())))
                    assertTrue(store.trusted().isEmpty())
                    assertTrue(receivingStore.trusted().isEmpty())
                    // A check also rejects corruption, never infers membership from the root alone.
                    issuing.cancelGroup()
                    receiving.cancelGroup()
                    issuing.verifyGroupPeer(peer(receiving))
                    awaitMembership(issuing) { it is GroupMembershipCheckState.Failed }
                    assertTrue(original.sameRecord(assertNotNull(store.committedGroupAdoption())))
                } }
            }
        }
    }

    @Test
    fun changedExactMembershipAfterDisplayInvalidatesIssuerClickEvenWithSameAnchor() = withDirectory { directory ->
        val founder = createDesktopIdentity().identity()
        val issuer = createDesktopIdentity().identity()
        val candidate = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), founder.id)
        adoptFirst(directory, founder, issuer, anchor)
        openDesktopRepository(directory.resolve("issuer.db")).use { store ->
            val original = assertNotNull(store.committedGroupAdoption())
            val replacement = AtomicReference(original)
            val boundary = object : DeviceRepository by store, GroupAdoptionRepository by store {
                override fun committedGroupAdoption() = replacement.get()
            }
            openDesktopRepository(directory.resolve("candidate.db")).use { receivingStore ->
                node(issuer, boundary).use { issuing -> node(candidate, receivingStore).use { receiving ->
                    issuing.start()
                    receiving.start()
                    select(issuing, receiving)
                    val (offer, accept) = comparisons(issuing, receiving)
                    receiving.confirmGroup(accept)
                    awaitState(receiving) { it is GroupAdmissionState.AwaitingPeer }
                    replacement.set(PendingGroupAdoption(randomNonce(), original.localIdentity,
                        original.peerIdentity, original.anchor, original.payload()))
                    issuing.confirmGroup(offer)
                    awaitState(issuing) { it is GroupAdmissionState.Failed }
                    awaitState(receiving) { it is GroupAdmissionState.Failed }
                    assertNull(receivingStore.localGroup())
                    assertNull(receivingStore.pendingGroupAdoption())
                    assertTrue(original.sameRecord(assertNotNull(store.committedGroupAdoption())))
                } }
            }
        }
    }

    @Test
    fun membershipWithoutLocalGroupFailsOffUiWithoutReadingPendingOrWriting() = withDirectory { directory ->
        val identity = createDesktopIdentity().identity()
        openDesktopRepository(directory.resolve("empty.db")).use { store ->
            val boundary = object : DeviceRepository by store, GroupAdoptionRepository by store {
                override fun pendingGroupAdoption(): PendingGroupAdoption? = error("Must not read pending")
            }
            node(identity, boundary).use { owner ->
                owner.start()
                owner.verifyGroupPeer(Peer(createDesktopIdentity().identity().id, "unknown", "127.0.0.1", 1))
                val failure = awaitMembership(owner) { it is GroupMembershipCheckState.Failed } as GroupMembershipCheckState.Failed
                assertEquals(GroupAdmissionFailure.UNAVAILABLE, failure.reason)
                assertNull(store.localGroup())
                assertNull(store.committedGroupAdoption())
                assertTrue(store.trusted().isEmpty())
                owner.cancelGroup()
                assertEquals(GroupMembershipCheckState.Idle, owner.membershipCheckState.value)
            }
        }
    }

    private fun adoptFirst(directory: Path, founder: Identity, issuer: Identity, anchor: GroupTrustAnchor): String =
        openDesktopRepository(directory.resolve("founder.db")).use { founderStore ->
            openDesktopRepository(directory.resolve("issuer.db")).use { issuerStore ->
                assertTrue(founderStore.foundLocalGroup(anchor, founder.id))
                node(founder, founderStore).use { a -> node(issuer, issuerStore).use { b ->
                    a.start()
                    b.start()
                    select(a, b)
                    val (offer, accept) = comparisons(a, b)
                    a.confirmGroup(offer)
                    b.confirmGroup(accept)
                    awaitState(b) { it is GroupAdmissionState.Completed }
                    awaitState(a) { it is GroupAdmissionState.Completed }
                    accept.code
                } }
            }
        }

    private fun node(identity: Identity, repository: DeviceRepository) =
        Node(identity, repository, object : DiscoveryService {
            override fun start(name: String, id: String, port: Int, onPeer: (Peer) -> Unit, onLost: (String) -> Unit) = Unit
            override fun stop() = Unit
        }, InetAddress.getLoopbackAddress())

    private fun select(a: Node, b: Node) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (a.port == 0 || b.port == 0) {
            check(System.nanoTime() < deadline)
            Thread.sleep(10)
        }
        a.selectGroupPeer(Peer(b.identity.id, "candidate", "127.0.0.1", b.port))
        b.selectGroupPeer(Peer(a.identity.id, "issuer", "127.0.0.1", a.port))
    }

    private fun peer(node: Node) = Peer(node.identity.id, "member", "127.0.0.1", node.port)

    private fun selectMembership(a: Node, b: Node) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (a.port == 0 || b.port == 0) {
            check(System.nanoTime() < deadline)
            Thread.sleep(10)
        }
        a.verifyGroupPeer(peer(b))
        b.verifyGroupPeer(peer(a))
    }

    private fun verifyMembers(a: Node, b: Node) {
        a.cancelGroup()
        b.cancelGroup()
        selectMembership(a, b)
        val verifiedA = awaitMembership(a) { it is GroupMembershipCheckState.Verified } as GroupMembershipCheckState.Verified
        val verifiedB = awaitMembership(b) { it is GroupMembershipCheckState.Verified } as GroupMembershipCheckState.Verified
        assertEquals(verifiedA.groupId, verifiedB.groupId)
        assertEquals(b.identity.id, verifiedA.peer.id)
        assertEquals(a.identity.id, verifiedB.peer.id)
        assertEquals(GroupAdmissionState.Idle, a.admissionState.value)
        assertEquals(GroupAdmissionState.Idle, b.admissionState.value)
    }

    private fun awaitMembership(node: Node, predicate: (GroupMembershipCheckState) -> Boolean) = runBlocking {
        withTimeout(12_000) { node.membershipCheckState.first(predicate) }
    }

    private fun awaitPorts(a: Node, b: Node) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (a.port == 0 || b.port == 0) {
            check(System.nanoTime() < deadline)
            Thread.sleep(10)
        }
    }

    private fun negotiateSession(a: Node, b: Node): GroupSessionState.Selected {
        a.cancelGroup()
        b.cancelGroup()
        awaitPorts(a, b)
        a.negotiateGroupSession(peer(b))
        b.negotiateGroupSession(peer(a))
        val local = awaitSession(a) { it is GroupSessionState.Selected } as GroupSessionState.Selected
        val remote = awaitSession(b) { it is GroupSessionState.Selected } as GroupSessionState.Selected
        assertEquals(local.session, remote.session)
        assertEquals(b.identity.id, local.peer.id)
        assertEquals(a.identity.id, remote.peer.id)
        assertEquals(GroupMembershipCheckState.Idle, a.membershipCheckState.value)
        assertEquals(GroupMembershipCheckState.Idle, b.membershipCheckState.value)
        assertEquals(GroupAdmissionState.Idle, a.admissionState.value)
        assertEquals(GroupAdmissionState.Idle, b.admissionState.value)
        return local
    }

    private fun awaitSession(node: Node, predicate: (GroupSessionState) -> Boolean) = runBlocking {
        withTimeout(12_000) { node.groupSessionState.first(predicate) }
    }

    private fun comparisons(a: Node, b: Node): Pair<GroupAdmissionState.Comparing, GroupAdmissionState.Comparing> {
        val offer = awaitState(a) { it is GroupAdmissionState.Comparing } as GroupAdmissionState.Comparing
        val accept = awaitState(b) { it is GroupAdmissionState.Comparing } as GroupAdmissionState.Comparing
        assertEquals(offer.code, accept.code)
        assertEquals(64, accept.code.length)
        return offer to accept
    }

    private fun awaitState(node: Node, predicate: (GroupAdmissionState) -> Boolean) = runBlocking {
        withTimeout(12_000) { node.admissionState.first(predicate) }
    }

    private fun withDirectory(block: (Path) -> Unit) {
        val directory = Files.createTempDirectory("lantern-delegated-service-")
        try { block(directory) } finally {
            Files.walk(directory).use { files -> files.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
