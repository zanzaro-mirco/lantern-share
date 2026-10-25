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
import lantern.domain.GroupRosterState
import lantern.domain.GroupRosterFailure
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
    fun rosterTextDeliversSameSignedCopyToThreeRecipientsIncludingReturningFounderAndPersistsExactReceipts() = withMembers { f ->
        val third = createDesktopIdentity().identity()
        var deliveredId = ""
        openDesktopRepository(f.directory.resolve("third.db")).use { cStore ->
            f.stores { aStore, bStore -> node(f.a, aStore).use { a -> node(f.b, bStore).use { b -> node(third, cStore).use { c ->
                a.start(); b.start(); c.start(); ports(a, b); ports(b, c)
                val pair = synchronize(a, b)
                a.stop()
                admit(b, c)
                // No standalone roster action: this text owner verifies and expands it itself.
                val sent = rosterTransfer(b, c, "Anche al fondatore offline")
                deliveredId = sent.content.id
                assertEquals(pair.sessionId, sent.content.sessionId)
                assertEquals(setOf(f.a.id, f.b.id, third.id), sent.content.recipients.toSet())
                assertNull(aStore.groupText(deliveredId))
                assertEquals(setOf(f.b.id, third.id), assertNotNull(bStore.groupText(deliveredId)).receivedBy)
                assertEquals(setOf(third.id), assertNotNull(cStore.groupText(deliveredId)).receivedBy)
                assertEquals(setOf(f.b.id, third.id), assertNotNull(b.lastRosterTextDelivery.value).receivedBy)
                openDesktopRepository(f.directory.resolve("a.db")).use { reopened -> node(f.a, reopened).use { returning ->
                    returning.start(); ports(b, returning)
                    // A lost run memory and really reopened its database. Fresh proofs restore
                    // from B; the exact old UUID/signature/counters go to this recipient too.
                    deliverCopy(b, returning, deliveredId, sent)
                    assertEquals(setOf(f.a.id, f.b.id, third.id), assertNotNull(b.lastRosterTextDelivery.value).receivedBy)
                    deliverCopy(b, returning, deliveredId, sent)
                    assertEquals(1, reopened.groupTextHistory(f.anchor.groupId, pair.sessionId).size)
                    assertEquals(1, bStore.groupTextHistory(f.anchor.groupId, pair.sessionId).size)
                    val next = rosterTransfer(b, returning, "Un altro testo, stessi partecipanti")
                    assertEquals(2L, next.content.authorSequence)
                    assertEquals(sent.content.recipients, next.content.recipients)
                    assertEquals(setOf(f.a.id, f.b.id), assertNotNull(bStore.groupText(next.content.id)).receivedBy)
                    val reverse = rosterTransfer(returning, b, "Risposta con delegato offline")
                    assertEquals(1L, reverse.content.authorSequence)
                    assertEquals(sent.content.recipients, reverse.content.recipients)
                    for (store in listOf(reopened, bStore, cStore)) {
                        assertTrue(store.trusted().isEmpty()); assertTrue(store.history().isEmpty()); assertNull(store.pendingGroupAdoption())
                    }
                } }
            } } } }
        }
        f.stores { aStore, bStore ->
            val local = assertNotNull(bStore.groupText(deliveredId))
            assertEquals(setOf(f.a.id, f.b.id, third.id), local.receivedBy)
            assertTrue(local.message.sameMessage(assertNotNull(aStore.groupText(deliveredId)).message))
            assertEquals(setOf(f.a.id), assertNotNull(aStore.groupText(deliveredId)).receivedBy)
        }
    }

    @Test
    fun laterAdmissionKeepsOldCopyForFrozenRecipientsWithoutResigningOrConsumingCounters() = withMembers { f ->
        val third = createDesktopIdentity().identity()
        openDesktopRepository(f.directory.resolve("third.db")).use { cStore ->
            f.stores { aStore, bStore -> node(f.a, aStore).use { a -> node(f.b, bStore).use { b -> node(third, cStore).use { c ->
                a.start(); b.start(); c.start(); ports(a, b); ports(b, c)
                val original = rosterTransfer(b, a, "Solo i due ammessi ora")
                admit(b, c)
                val newer = rosterTransfer(b, c, "Tre partecipanti adesso")
                assertEquals(3, newer.content.recipients.size)
                assertEquals(original.content.sessionId, newer.content.sessionId)
                b.deliverRosterText(peer(c), original.content.id)
                val refused = assertIs<GroupTextState.Failed>(awaitText(b)) // C was not a frozen recipient.
                assertNull(refused.attemptedMessageId)
                assertNull(cStore.groupText(original.content.id))
                // Negotiated copy scope: same signed bytes to the original recipient, C never added.
                deliverCopy(b, a, original.content.id, original)
                assertEquals(setOf(f.a.id, f.b.id), assertNotNull(bStore.groupText(original.content.id)).receivedBy)
                assertTrue(original.sameMessage(assertNotNull(bStore.groupText(original.content.id)).message))
                assertTrue(original.sameMessage(assertNotNull(aStore.groupText(original.content.id)).message))
                assertEquals(setOf(f.a.id, f.b.id), assertNotNull(b.lastRosterTextDelivery.value).message.content.recipients.toSet())
                assertNull(cStore.groupText(original.content.id))
                val next = rosterTransfer(b, a, "Nessun contatore usato dalla copia")
                assertEquals(3L, next.content.authorSequence)
                assertEquals(3, next.content.recipients.size)
            } } } }
        }
    }

    @Test
    fun copyAfterLaterAdmissionReachesReturningOriginalRecipientThatNeverHadIt() = withMembers { f ->
        val third = createDesktopIdentity().identity()
        val fourth = createDesktopIdentity().identity()
        openDesktopRepository(f.directory.resolve("third.db")).use { cStore ->
            openDesktopRepository(f.directory.resolve("fourth.db")).use { dStore ->
                f.stores { aStore, bStore -> node(f.a, aStore).use { a -> node(f.b, bStore).use { b ->
                    node(third, cStore).use { c -> node(fourth, dStore).use { d ->
                        a.start(); b.start(); c.start(); d.start(); ports(a, b); ports(c, d)
                        val roster = synchronize(a, b)
                        a.stop() // A is an offline original recipient from now on.
                        admit(b, d)
                        val sent = rosterTransfer(b, d, "Per A, B e D")
                        assertEquals(roster.sessionId, sent.content.sessionId)
                        assertEquals(setOf(f.a.id, f.b.id, fourth.id), sent.content.recipients.toSet())
                        admit(b, c)
                        val expanded = rosterTransfer(b, c, "Ora anche C")
                        assertEquals(setOf(f.a.id, f.b.id, third.id, fourth.id), expanded.content.recipients.toSet())
                        b.deliverRosterText(peer(c), sent.content.id)
                        assertIs<GroupTextState.Failed>(awaitText(b))
                        assertNull(cStore.groupText(sent.content.id))
                        a.start(); ports(a, b) // Run memory lost; B retains the expanded live roster.
                        assertNull(aStore.groupText(sent.content.id))
                        deliverCopy(b, a, sent.content.id, sent)
                        assertEquals(setOf(f.a.id), assertNotNull(aStore.groupText(sent.content.id)).receivedBy)
                        assertEquals(setOf(f.a.id, f.b.id, fourth.id), assertNotNull(bStore.groupText(sent.content.id)).receivedBy)
                        deliverCopy(b, a, sent.content.id, sent) // Exact duplicate stays idempotent.
                        assertEquals(1, aStore.groupTextHistory(f.anchor.groupId, sent.content.sessionId).size)
                        assertNull(cStore.groupText(sent.content.id))
                        val next = rosterTransfer(b, a, "Contatore dopo le copie")
                        assertEquals(3L, next.content.authorSequence)
                        assertEquals(expanded.content.recipients, next.content.recipients)
                        for (store in listOf(aStore, bStore, cStore, dStore)) {
                            assertTrue(store.trusted().isEmpty()); assertNull(store.pendingGroupAdoption())
                        }
                    } }
                } } }
            }
        }
    }

    @Test
    fun rosterTextCannotFallBackToLegacyTextOrDiagnosticsAndStopCannotRestoreSessionFromSavedCopy() = withMembers { f ->
        f.stores { aStore, bStore -> node(f.a, aStore).use { a -> node(f.b, bStore).use { b ->
            a.start(); b.start(); ports(a, b)
            a.sendRosterText(peer(b), "Modalità diverse"); b.receiveGroupText(peer(a))
            assertIs<GroupTextState.Failed>(awaitText(a)); assertIs<GroupTextState.Failed>(awaitText(b))
            a.sendRosterText(peer(b), "Non è diagnostica"); b.synchronizeGroupRoster(peer(a))
            assertIs<GroupTextState.Failed>(awaitText(a)); assertIs<GroupRosterState.Failed>(awaitRoster(b))
            val original = rosterTransfer(a, b, "Primo contatore")
            assertEquals(1L, original.content.authorSequence)
            a.stop(); b.stop(); a.start(); b.start(); ports(a, b)
            b.receiveRosterText(peer(a)); a.deliverRosterText(peer(b), original.content.id)
            assertEquals(GroupTextFailure.ROSTER_REQUIRED, assertIs<GroupTextState.Failed>(awaitText(a)).reason)
            assertIs<GroupTextState.Failed>(awaitText(b))
            val fresh = rosterTransfer(a, b, "Sessione nuova")
            assertNotEquals(original.content.sessionId, fresh.content.sessionId)
            assertEquals(2L, fresh.content.authorSequence)
            assertNotNull(aStore.groupText(original.content.id)); assertNotNull(bStore.groupText(original.content.id))
            // A received copy cannot be forwarded as if it were authored by B.
            b.deliverRosterText(peer(a), original.content.id)
            assertIs<GroupTextState.Failed>(awaitText(b))
            assertNull(b.lastRosterTextDelivery.value)
        } } }
    }

    private fun rosterTransfer(sender: Node, receiver: Node, text: String): SignedGroupText {
        receiver.receiveRosterText(peer(sender)); sender.sendRosterText(peer(receiver), text)
        val sent = assertIs<GroupTextState.Sent>(awaitText(sender))
        val received = assertIs<GroupTextState.Received>(awaitText(receiver))
        assertTrue(sent.message.sameMessage(received.message))
        return sent.message
    }

    private fun startText(sender: Node, receiver: Node, text: String, roster: Boolean) {
        if (roster) {
            receiver.receiveRosterText(peer(sender)); sender.sendRosterText(peer(receiver), text)
        } else {
            receiver.receiveGroupText(peer(sender)); sender.sendGroupText(peer(receiver), text)
        }
    }

    private fun deliverCopy(sender: Node, receiver: Node, id: String, expected: SignedGroupText) {
        receiver.receiveRosterText(peer(sender)); sender.deliverRosterText(peer(receiver), id)
        assertTrue(expected.sameMessage(assertIs<GroupTextState.Sent>(awaitText(sender)).message))
        assertTrue(expected.sameMessage(assertIs<GroupTextState.Received>(awaitText(receiver)).message))
    }

    @Test
    fun signedRosterRestoresRetainedUsedPairAfterEitherPeerReopensWithoutHistoryOrCounterReuse() {
        for (restartFounder in listOf(false, true)) withMembers { f ->
            f.stores { aStore, bStore ->
                val keeperIdentity = if (restartFounder) f.b else f.a
                val returningIdentity = if (restartFounder) f.a else f.b
                val keeperStore = if (restartFounder) bStore else aStore
                val returningStore = if (restartFounder) aStore else bStore
                node(keeperIdentity, keeperStore).use { keeper ->
                    keeper.start()
                    val first = node(returningIdentity, returningStore).use { returning ->
                        returning.start(); ports(keeper, returning)
                        transfer(keeper, returning, "Prima del rientro")
                    }
                    openDesktopRepository(f.directory.resolve(if (restartFounder) "a.db" else "b.db")).use { reopened ->
                        val marker = reopened.committedGroupAdoption()
                        node(returningIdentity, reopened).use { returning ->
                            returning.start(); ports(keeper, returning)
                            val restored = synchronize(keeper, returning)
                            assertEquals(first.content.sessionId, restored.sessionId)
                            assertEquals(setOf(f.a.id, f.b.id), restored.participants.toSet())
                            assertEquals(1, reopened.groupTextHistory(f.anchor.groupId, restored.sessionId).size)
                            assertEquals(1, keeperStore.groupTextHistory(f.anchor.groupId, restored.sessionId).size)
                            if (marker != null) assertTrue(marker.sameRecord(assertNotNull(reopened.committedGroupAdoption())))
                            val next = transfer(keeper, returning, "Stessa sessione ripristinata")
                            assertEquals(first.content.sessionId, next.content.sessionId)
                            assertEquals(2L, next.content.authorSequence)
                            assertTrue(reopened.trusted().isEmpty())
                            assertTrue(reopened.history().isEmpty())
                            assertNull(reopened.pendingGroupAdoption())
                            // Old B5/text paths preserve a signed roster only for the exact session.
                            keeper.negotiateGroupSession(peer(returning)); returning.negotiateGroupSession(peer(keeper))
                            awaitSession(keeper); awaitSession(returning)
                            assertEquals(restored.participants, synchronize(returning, keeper).participants)
                        }
                    }
                }
            }
        }
    }

    @Test
    fun threeMemberRosterRetainsOfflineFounderThenOfflineDelegateWithoutRetroactiveRecipients() = withMembers { f ->
        val third = createDesktopIdentity().identity()
        openDesktopRepository(f.directory.resolve("third.db")).use { cStore ->
            f.stores { aStore, bStore -> node(f.a, aStore).use { a -> node(f.b, bStore).use { b -> node(third, cStore).use { c ->
                a.start(); b.start(); c.start(); ports(a, b); ports(b, c)
                val initialRoster = synchronize(a, b)
                val first = transfer(a, b, "Non destinato retroattivamente a C")
                assertEquals(initialRoster.sessionId, first.content.sessionId)
                a.stop() // Founder really offline; B has a complete signed snapshot.
                admit(b, c)
                val expanded = synchronize(b, c)
                assertEquals(first.content.sessionId, expanded.sessionId)
                assertEquals(setOf(f.a.id, f.b.id, third.id), expanded.participants.toSet())
                b.stop() // Now only C retains the expanded session, including both offline peers.
                a.start(); ports(a, c)
                val restored = synchronize(a, c)
                assertEquals(expanded.sessionId, restored.sessionId)
                assertEquals(expanded.participants, restored.participants)
                // The old LTX format cannot express this snapshot: refuse, never omit offline B.
                a.sendGroupText(peer(c), "Non ridurre lo snapshot"); c.receiveGroupText(peer(a))
                for (side in listOf(a, c)) {
                    val failure = assertIs<GroupTextState.Failed>(awaitText(side))
                    assertEquals(GroupTextFailure.ROSTER_REQUIRED, failure.reason)
                    assertNull(failure.attemptedMessageId)
                }
                assertEquals(setOf(f.a.id, f.b.id), assertNotNull(aStore.groupText(first.content.id)).message.content.recipients.toSet())
                assertTrue(cStore.groupTextHistory(f.anchor.groupId, expanded.sessionId).isEmpty())
                assertEquals(expanded.participants, synchronize(c, a).participants)
            } } } }
        }
    }

    @Test
    fun unsignedLegacyOfflineParticipantCannotDisappearWhenThirdMemberJoins() = withMembers { f ->
        val third = createDesktopIdentity().identity()
        openDesktopRepository(f.directory.resolve("third.db")).use { cStore ->
            f.stores { aStore, bStore -> node(f.a, aStore).use { a -> node(f.b, bStore).use { b -> node(third, cStore).use { c ->
                a.start(); b.start(); c.start(); ports(a, b); ports(b, c)
                val first = transfer(a, b, "Scope precedente senza prove roster")
                a.stop()
                admit(b, c)
                b.synchronizeGroupRoster(peer(c)); c.synchronizeGroupRoster(peer(b))
                val refused = assertIs<GroupRosterState.Failed>(awaitRoster(b))
                assertEquals(GroupRosterFailure.MISSING_PARTICIPANTS, refused.reason)
                assertIs<GroupRosterState.Failed>(awaitRoster(c))
                assertTrue(cStore.groupTextHistory(f.anchor.groupId, first.content.sessionId).isEmpty())
                // Failure did not replace the previous pair scope or consume author counters.
                a.start(); ports(a, b)
                assertEquals(first.content.sessionId, synchronize(a, b).sessionId)
                val expanded = synchronize(b, c)
                assertEquals(3, expanded.participants.size)
                assertEquals(first.content.sessionId, expanded.sessionId)
            } } } }
        }
    }

    @Test
    fun usedSessionWithAllSnapshotsLostCannotBeReinventedFromTwoFreshJoins() = withMembers { f ->
        f.stores { aStore, bStore -> node(f.a, aStore).use { a -> node(f.b, bStore).use { b ->
            a.start(); b.start(); ports(a, b)
            val first = transfer(a, b, "Preservare lo scope")
            b.stop(); b.start(); ports(a, b)
            a.negotiateGroupSession(peer(b)); b.negotiateGroupSession(peer(a))
            awaitSession(a); awaitSession(b)
            a.stop(); a.start(); ports(a, b)
            a.negotiateGroupSession(peer(b)); b.negotiateGroupSession(peer(a))
            awaitSession(a); awaitSession(b)
            a.synchronizeGroupRoster(peer(b)); b.synchronizeGroupRoster(peer(a))
            for (side in listOf(a, b)) assertEquals(GroupRosterFailure.MISSING_PARTICIPANTS,
                assertIs<GroupRosterState.Failed>(awaitRoster(side)).reason)
            assertNotNull(aStore.groupText(first.content.id))
            a.stop(); b.stop(); a.start(); b.start(); ports(a, b)
            val fresh = synchronize(a, b)
            assertNotEquals(first.content.sessionId, fresh.sessionId)
            val next = transfer(a, b, "Nuova sessione, non ripristinata dalla storia")
            assertEquals(fresh.sessionId, next.content.sessionId)
            assertEquals(2L, next.content.authorSequence)
        } } }
    }

    @Test
    fun rosterCannotFallbackToDiagnosticOrTextModeAndCancellationCannotPublishOldResult() = withMembers { f ->
        f.stores { aStore, bStore -> node(f.a, aStore).use { a -> node(f.b, bStore).use { b ->
            a.start(); b.start(); ports(a, b)
            a.synchronizeGroupRoster(peer(b)); b.negotiateGroupSession(peer(a))
            assertIs<GroupRosterState.Failed>(awaitRoster(a))
            runBlocking { withTimeout(12_000) { b.groupSessionState.first { it is GroupSessionState.Failed } } }
            a.synchronizeGroupRoster(peer(b)); b.receiveGroupText(peer(a))
            assertIs<GroupRosterState.Failed>(awaitRoster(a)); assertIs<GroupTextState.Failed>(awaitText(b))
            a.synchronizeGroupRoster(peer(b)); a.cancelGroup()
            assertEquals(GroupRosterState.Idle, a.groupRosterState.value)
            assertEquals(2, synchronize(a, b).participants.size)
            assertTrue(aStore.groupTextHistory(f.anchor.groupId, assertIs<GroupRosterState.Synchronized>(a.groupRosterState.value).sessionId).isEmpty())
        } } }
    }

    @Test
    fun rosterRejectsIndependentRootOrMissingMembershipWithoutAdoptingOrWritingHistory() = withMembers { f ->
        val outsider = createDesktopIdentity().identity()
        openDesktopRepository(f.directory.resolve("other.db")).use { otherStore ->
            f.stores { aStore, _ -> node(f.a, aStore).use { a -> node(outsider, otherStore).use { other ->
                a.start(); other.start(); ports(a, other)
                other.synchronizeGroupRoster(peer(a))
                assertEquals(GroupRosterFailure.UNAVAILABLE, assertIs<GroupRosterState.Failed>(awaitRoster(other)).reason)
                val independent = GroupTrustAnchor(randomNonce(), outsider.id)
                otherStore.foundLocalGroup(independent, outsider.id)
                a.synchronizeGroupRoster(peer(other)); other.synchronizeGroupRoster(peer(a))
                assertIs<GroupRosterState.Failed>(awaitRoster(a))
                assertIs<GroupRosterState.Failed>(awaitRoster(other))
                assertEquals(f.anchor, aStore.localGroup())
                assertEquals(independent, otherStore.localGroup())
                for (store in listOf(aStore, otherStore)) {
                    assertTrue(store.trusted().isEmpty())
                    assertTrue(store.history().isEmpty())
                    assertNull(store.pendingGroupAdoption())
                }
            } } }
        }
    }

    private fun synchronize(a: Node, b: Node): GroupRosterState.Synchronized {
        a.synchronizeGroupRoster(peer(b)); b.synchronizeGroupRoster(peer(a))
        val local = assertIs<GroupRosterState.Synchronized>(awaitRoster(a))
        val remote = assertIs<GroupRosterState.Synchronized>(awaitRoster(b))
        assertEquals(local.sessionId, remote.sessionId)
        assertEquals(local.participants, remote.participants)
        return local
    }

    private fun awaitRoster(node: Node) = runBlocking { withTimeout(12_000) {
        node.groupRosterState.first { it is GroupRosterState.Synchronized || it is GroupRosterState.Failed }
    } }

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
    fun receiverCommitFaultProducesNoAckAndDoesNotEraseSenderCopy() {
        for (roster in listOf(false, true)) withMembers { f ->
            f.stores { aStore, bStore ->
                JdbcSqliteDriver("jdbc:sqlite:${f.directory.resolve("b.db")}").use { fault ->
                    fault.execute(null, "CREATE TRIGGER reject_text AFTER INSERT ON group_text_recipient BEGIN SELECT RAISE(FAIL, 'test fault'); END", 0)
                    node(f.a, aStore).use { a -> node(f.b, bStore).use { b ->
                        a.start(); b.start(); ports(a, b)
                        startText(a, b, "Nessun falso ACK", roster)
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
    }

    @Test
    fun receivedIsDurableBeforeTransportCleanupAndSurvivesSenderCancellationAfterAck() {
        for (roster in listOf(false, true)) withMembers { f ->
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
                        startText(a, b, "Salvato prima del cleanup", roster)
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
    }

    @Test
    fun cancellationDuringEnteredCommitHasNoLateAckOrPresentationAndCloseDrainsWorker() {
        for (roster in listOf(false, true)) withMembers { f ->
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
                        startText(a, b, "Commit in corso", roster)
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
