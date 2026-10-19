package lantern.connectivity

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import lantern.domain.DeviceRepository
import lantern.domain.DiscoveryService
import lantern.domain.GroupAdmissionRole
import lantern.domain.GroupAdmissionState
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
