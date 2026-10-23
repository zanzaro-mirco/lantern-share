package lantern.connectivity

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import lantern.domain.DeviceRepository
import lantern.domain.DiscoveryService
import lantern.domain.GroupAdmissionState
import lantern.domain.GroupAdoptionRepository
import lantern.domain.GroupTextRepository
import lantern.domain.GroupTextState
import lantern.domain.GroupTextFailure
import lantern.domain.GroupSessionState
import lantern.domain.GroupTrustAnchor
import lantern.domain.Peer
import lantern.domain.SignedGroupText
import lantern.persistence.openDesktopRepository
import lantern.persistence.SqliteDeviceRepository
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Actual Nodes, mutual TLS, delegated group admission, P-256 and reopened SQLite, not wire-0 trust. */
class GroupTextTransferServiceTest {
    @Test
    fun reopenedMembersTransferBothDirectionsAndPreserveUsedScopeAndHistoryInBothTlsOrders() {
        for (senderFirst in listOf(true, false)) withMembers { f ->
            f.stores { leftStore, rightStore ->
                leftStore.save("poc", f.a.id, "old-connection", "PoC preservato", "test-fixture")
                node(f.a, leftStore).use { left -> node(f.b, rightStore).use { right ->
                    left.start(); right.start(); ports(left, right)
                    val sender = if (senderFirst) left else right
                    val receiver = if (senderFirst) right else left
                    val first = transfer(sender, receiver, "Primo testo ☕")
                    assertEquals(f.anchor.groupId, first.content.groupId)
                    assertEquals(setOf(f.a.id, f.b.id), first.content.recipients.toSet())
                    assertEquals(1L, first.content.authorSequence)
                    val senderStore = if (senderFirst) leftStore else rightStore
                    val receiverStore = if (senderFirst) rightStore else leftStore
                    assertEquals(setOf(f.a.id, f.b.id), assertNotNull(senderStore.groupText(first.content.id)).receivedBy)
                    assertEquals(setOf(receiver.identity.id), assertNotNull(receiverStore.groupText(first.content.id)).receivedBy)
                    assertTrue(senderStore.groupSessionWasUsed(f.anchor.groupId, first.content.sessionId))
                    assertTrue(receiverStore.groupSessionWasUsed(f.anchor.groupId, first.content.sessionId))
                    // Diagnostic B5 must preserve the authenticated scope, not grant new authority.
                    left.negotiateGroupSession(peer(right)); right.negotiateGroupSession(peer(left))
                    val selectedA = awaitSession(left)
                    val selectedB = awaitSession(right)
                    assertEquals(selectedA.session, selectedB.session)
                    assertEquals(first.content.sessionId, selectedA.session.sessionId)
                    assertTrue(selectedA.session.used)
                    val reverse = transfer(receiver, sender, "Risposta")
                    assertEquals(first.content.sessionId, reverse.content.sessionId)
                    assertTrue(reverse.content.logicalTime > first.content.logicalTime)
                    val second = transfer(sender, receiver, "Secondo testo")
                    assertEquals(2L, second.content.authorSequence)
                    assertEquals(first.content.sessionId, second.content.sessionId)
                    assertEquals(3, leftStore.groupTextHistory(f.anchor.groupId, first.content.sessionId).size)
                    assertEquals("PoC preservato", leftStore.history().single().text)
                    assertTrue(rightStore.history().isEmpty())
                    for (store in listOf(leftStore, rightStore)) {
                        assertEquals(f.anchor, store.localGroup())
                        assertTrue(store.trusted().isEmpty())
                        assertNull(store.pendingGroupAdoption())
                    }
                    left.stop(); right.stop(); left.start(); right.start(); ports(left, right)
                    val fresh = transfer(sender, receiver, "Nuova sessione")
                    assertNotEquals(first.content.sessionId, fresh.content.sessionId)
                    assertEquals(3L, fresh.content.authorSequence)
                    assertEquals(3, leftStore.groupTextHistory(f.anchor.groupId, first.content.sessionId).size)
                } }
            }
            f.stores { left, right ->
                assertEquals(1, left.history().size)
                assertTrue(right.trusted().isEmpty())
                assertNotNull(right.committedGroupAdoption())
            }
        }
    }

    @Test
    fun sameRolesOrDiagnosticModeCannotSendTextAndCorrectRetryStillWorks() = withMembers { f ->
        f.stores { aStore, bStore -> node(f.a, aStore).use { a -> node(f.b, bStore).use { b ->
            a.start(); b.start(); ports(a, b)
            a.sendGroupText(peer(b), "a"); b.sendGroupText(peer(a), "b")
            assertIs<GroupTextState.Failed>(awaitText(a))
            assertIs<GroupTextState.Failed>(awaitText(b))
            a.receiveGroupText(peer(b)); b.negotiateGroupSession(peer(a))
            assertIs<GroupTextState.Failed>(awaitText(a))
            runBlocking { withTimeout(12_000) { b.groupSessionState.first { it is GroupSessionState.Failed } } }
            val valid = transfer(a, b, "Riprova corretta")
            assertEquals(1L, valid.content.authorSequence)
        } } }
    }

    @Test
    fun receiverCommitFaultProducesNoAckAndDoesNotEraseSenderCopy() = withMembers { f ->
        f.stores { aStore, bStore ->
            JdbcSqliteDriver("jdbc:sqlite:${f.directory.resolve("b.db")}").use { fault ->
                fault.execute(null, "CREATE TRIGGER reject_text AFTER INSERT ON group_text_recipient BEGIN SELECT RAISE(FAIL, 'test fault'); END", 0)
                node(f.a, aStore).use { a -> node(f.b, bStore).use { b ->
                    a.start(); b.start(); ports(a, b)
                    b.receiveGroupText(peer(a)); a.sendGroupText(peer(b), "Nessun falso ACK")
                    val sending = assertIs<GroupTextState.Failed>(awaitText(a))
                    assertIs<GroupTextState.Failed>(awaitText(b))
                    val id = assertNotNull(sending.attemptedMessageId)
                    val local = assertNotNull(aStore.groupText(id))
                    assertEquals(setOf(f.a.id), local.receivedBy)
                    assertNull(bStore.groupText(id))
                    assertFalse(bStore.groupSessionWasUsed(f.anchor.groupId, local.message.content.sessionId))
                } }
            }
        }
    }

    @Test
    fun receivedIsDurableBeforeTransportCleanupAndSurvivesSenderCancellationAfterAck() = withMembers { f ->
        f.stores { aStore, bStore ->
            val ackEntered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val boundary = object : DeviceRepository by aStore, GroupAdoptionRepository by aStore, GroupTextRepository by aStore {
                override fun acknowledgeGroupText(message: SignedGroupText, recipientId: String): Boolean {
                    ackEntered.countDown()
                    check(release.await(8, TimeUnit.SECONDS))
                    return aStore.acknowledgeGroupText(message, recipientId)
                }
            }
            node(f.a, boundary).use { a -> node(f.b, bStore).use { b ->
                try {
                    a.start()
                    b.start()
                    ports(a, b)
                    b.receiveGroupText(peer(a))
                    a.sendGroupText(peer(b), "Salvato prima del cleanup")
                    assertTrue(ackEntered.await(8, TimeUnit.SECONDS))
                    // Sender has consumed the ACK but cannot close yet. Receiver must already
                    // report its own durable fact, without waiting for EOF as another ACK.
                    val received = assertIs<GroupTextState.Received>(awaitText(b))
                    assertNotNull(bStore.groupText(received.message.content.id))
                    a.cancelGroup()
                    assertEquals(GroupTextState.Idle, a.groupTextState.value)
                    assertEquals(received, b.groupTextState.value)
                } finally { release.countDown() }
            } }
        }
    }

    @Test
    fun cancellationDuringEnteredCommitHasNoLateAckOrPresentationAndCloseDrainsWorker() = withMembers { f ->
        f.stores { aStore, bStore ->
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val boundary = object : DeviceRepository by bStore, GroupAdoptionRepository by bStore, GroupTextRepository by bStore {
                override fun saveGroupText(message: SignedGroupText, localIdentity: String): Boolean {
                    entered.countDown()
                    check(release.await(8, TimeUnit.SECONDS))
                    return bStore.saveGroupText(message, localIdentity)
                }
            }
            node(f.a, aStore).use { a -> node(f.b, boundary).use { b ->
                try {
                    a.start(); b.start(); ports(a, b)
                    b.receiveGroupText(peer(a)); a.sendGroupText(peer(b), "Commit in corso")
                    assertTrue(entered.await(8, TimeUnit.SECONDS))
                    b.cancelGroup()
                    assertEquals(GroupTextState.Idle, b.groupTextState.value)
                    assertIs<GroupTextState.Failed>(awaitText(a))
                } finally { release.countDown() }
            } }
            assertEquals(0, bStore.trusted().size)
            // The already-entered local commit may finish, but never produces an ACK after cancel.
        }
    }

    @Test
    fun usedSessionWithoutKnownScopeRefusesNewSnapshotInsteadOfDroppingRecipients() = withMembers { f ->
        f.stores { aStore, bStore -> node(f.a, aStore).use { a -> node(f.b, bStore).use { b ->
            a.start(); b.start(); ports(a, b)
            val first = transfer(a, b, "Sessione utilizzata")
            b.stop(); b.start(); ports(a, b)
            // B5 may join the retained session, but cannot reconstruct its authenticated roster.
            a.negotiateGroupSession(peer(b)); b.negotiateGroupSession(peer(a))
            awaitSession(a); awaitSession(b)
            b.receiveGroupText(peer(a)); a.sendGroupText(peer(b), "Non inventare destinatari")
            val failedA = assertIs<GroupTextState.Failed>(awaitText(a))
            val failedB = assertIs<GroupTextState.Failed>(awaitText(b))
            assertEquals(GroupTextFailure.ROSTER_REQUIRED, failedB.reason)
            assertNull(failedA.attemptedMessageId)
            assertEquals(1, aStore.groupTextHistory(f.anchor.groupId, first.content.sessionId).size)
            assertEquals(1, bStore.groupTextHistory(f.anchor.groupId, first.content.sessionId).size)
        } } }
    }

    @Test
    fun delegatedMembersTransferWithFounderOfflineAndIndependentGroupCannotJoin() = withMembers { f ->
        val third = createDesktopIdentity().identity()
        val outsider = createDesktopIdentity().identity()
        openDesktopRepository(f.directory.resolve("third.db")).use { thirdStore ->
            f.stores { _, bStore ->
                // The founder Node is not running: an adopted member admits the third identity.
                node(f.b, bStore).use { b -> node(third, thirdStore).use { c ->
                    b.start()
                    c.start()
                    ports(b, c)
                    admit(b, c)
                } }
            }
        }
        openDesktopRepository(f.directory.resolve("third.db")).use { thirdStore ->
            openDesktopRepository(f.directory.resolve("outsider.db")).use { otherStore ->
                otherStore.foundLocalGroup(GroupTrustAnchor(randomNonce(), outsider.id), outsider.id)
                f.stores { _, bStore -> node(f.b, bStore).use { b -> node(third, thirdStore).use { c ->
                    b.start()
                    c.start()
                    ports(b, c)
                    val sent = transfer(b, c, "Senza fondatore online")
                    assertEquals(f.anchor.groupId, sent.content.groupId)
                    assertEquals(setOf(f.b.id, third.id), sent.content.recipients.toSet())
                    // Admission to the group does not silently admit the offline founder to this
                    // initial text session. Its diagnostic B5 observation is not a session roster.
                    node(outsider, otherStore).use { other ->
                        other.start()
                        ports(c, other)
                        c.receiveGroupText(peer(other))
                        other.sendGroupText(peer(c), "Altro gruppo")
                        val failed = assertIs<GroupTextState.Failed>(awaitText(other))
                        assertNull(failed.attemptedMessageId)
                        assertIs<GroupTextState.Failed>(awaitText(c))
                        assertTrue(otherStore.groupTextHistory(f.anchor.groupId, sent.content.sessionId).isEmpty())
                    }
                    assertEquals(1, thirdStore.groupTextHistory(f.anchor.groupId, sent.content.sessionId).size)
                    assertTrue(bStore.trusted().isEmpty())
                    assertTrue(thirdStore.trusted().isEmpty())
                } } }
            }
        }
    }

    private fun transfer(sender: Node, receiver: Node, text: String): SignedGroupText {
        receiver.receiveGroupText(peer(sender))
        sender.sendGroupText(peer(receiver), text)
        val sent = assertIs<GroupTextState.Sent>(awaitText(sender))
        val received = assertIs<GroupTextState.Received>(awaitText(receiver))
        assertTrue(sent.message.sameMessage(received.message))
        return sent.message
    }

    private fun awaitText(node: Node) = runBlocking { withTimeout(12_000) {
        node.groupTextState.first { it is GroupTextState.Sent || it is GroupTextState.Received || it is GroupTextState.Failed }
    } }
    private fun awaitSession(node: Node) = runBlocking { withTimeout(12_000) {
        assertIs<GroupSessionState.Selected>(node.groupSessionState.first { it is GroupSessionState.Selected || it is GroupSessionState.Failed })
    } }
    private fun peer(node: Node) = Peer(node.identity.id, "member", "127.0.0.1", node.port)
    private fun ports(a: Node, b: Node) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(6)
        while (a.port == 0 || b.port == 0) { check(System.nanoTime() < until); Thread.sleep(10) }
    }
    private fun node(identity: Identity, repository: DeviceRepository) = Node(identity, repository, object : DiscoveryService {
        override fun start(name: String, id: String, port: Int, onPeer: (Peer) -> Unit, onLost: (String) -> Unit) = Unit
        override fun stop() = Unit
    }, InetAddress.getLoopbackAddress())

    private fun admit(a: Node, b: Node) {
        a.selectGroupPeer(peer(b))
        b.selectGroupPeer(peer(a))
        val ca = runBlocking { withTimeout(12_000) { a.admissionState.first { it is GroupAdmissionState.Comparing } } }
        val cb = runBlocking { withTimeout(12_000) { b.admissionState.first { it is GroupAdmissionState.Comparing } } }
        a.confirmGroup(ca as GroupAdmissionState.Comparing)
        b.confirmGroup(cb as GroupAdmissionState.Comparing)
        runBlocking { withTimeout(12_000) {
            a.admissionState.first { it is GroupAdmissionState.Completed }
            b.admissionState.first { it is GroupAdmissionState.Completed }
        } }
    }

    private class Members(val directory: Path, val a: Identity, val b: Identity, val anchor: GroupTrustAnchor) {
        fun stores(block: (SqliteDeviceRepository, SqliteDeviceRepository) -> Unit) {
            openDesktopRepository(directory.resolve("a.db")).use { left ->
                openDesktopRepository(directory.resolve("b.db")).use { right -> block(left, right) }
            }
        }
    }
    private fun withMembers(block: (Members) -> Unit) {
        val directory = Files.createTempDirectory("lantern-group-text-service-")
        try {
            val identities = List(2) { createDesktopIdentity().identity() }.sortedBy { it.id }
            val fixture = Members(directory, identities[0], identities[1], GroupTrustAnchor(randomNonce(), identities[0].id))
            fixture.stores { left, right ->
                left.foundLocalGroup(fixture.anchor, fixture.a.id)
                node(fixture.a, left).use { a -> node(fixture.b, right).use { b ->
                    a.start(); b.start(); ports(a, b)
                    admit(a, b)
                } }
            }
            block(fixture)
        } finally { Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }
}
