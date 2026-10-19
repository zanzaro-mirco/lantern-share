package lantern.connectivity

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import lantern.domain.DeviceRepository
import lantern.domain.DiscoveryService
import lantern.domain.GroupAdmissionFailure
import lantern.domain.GroupAdmissionRole
import lantern.domain.GroupAdmissionState
import lantern.domain.GroupAdoptionRepository
import lantern.domain.LocalGroupState
import lantern.domain.Peer
import lantern.domain.PendingGroupAdoption
import lantern.persistence.openDesktopRepository
import lantern.protocol.GroupRootAdoptionJournalInspectionResult
import java.io.IOException
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Actual Node ingress, selected mutual TLS, P-256 signatures and reopened SQLite. */
class GroupAdmissionServiceTest {
    @Test
    fun founderInviteCommitsOnlyAfterBothClicksAndReopensAsAdoptedWithoutPocTrust() {
        for (issuerInitiates in listOf(true, false)) {
            withFixture(issuerInitiates = issuerInitiates, block = ::verifySuccessfulReopen)
        }
    }

    private fun verifySuccessfulReopen(fixture: Fixture) {
        val saved = fixture.use { f ->
            f.select()
            val (issuer, member) = f.comparisons()
            assertEquals(GroupAdmissionRole.FOUNDER, issuer.role)
            assertEquals(GroupAdmissionRole.NEW_MEMBER, member.role)
            assertEquals(issuer.code, member.code)
            assertEquals(64, member.code.length)
            assertEquals(f.anchor.groupId, member.groupId)
            // Even equal presentation values cannot stand in for the retained snapshot.
            f.member.confirmGroup(member.copy())
            assertEquals(member, f.member.admissionState.value)
            f.member.confirmGroup(member)
            f.await(f.member) { it is GroupAdmissionState.AwaitingPeer }
            assertNull(f.memberStore.localGroup())
            assertNull(f.memberStore.pendingGroupAdoption())
            f.issuer.confirmGroup(issuer)
            val completed = f.await(f.member) { it is GroupAdmissionState.Completed } as GroupAdmissionState.Completed
            assertTrue(completed.adoptedLocally)
            val offered = f.await(f.issuer) { it is GroupAdmissionState.Completed } as GroupAdmissionState.Completed
            assertFalse(offered.adoptedLocally)
            val record = assertNotNull(f.memberStore.committedGroupAdoption())
            assertEquals(GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid,
                GroupRootAdoptionJournalInspector.inspect(record, f.member.identity.id))
            f.memberGroup.refreshMembership()
            assertEquals(LocalGroupState.Adopted(f.anchor), f.awaitGroup { it is LocalGroupState.Adopted })
            assertTrue(f.member.state.value.connected.isEmpty())
            assertTrue(f.issuer.state.value.connected.isEmpty())
            assertTrue(f.memberStore.trusted().isEmpty())
            assertTrue(f.issuerStore.trusted().isEmpty())
            assertTrue(f.memberStore.history().isEmpty())
            assertEquals(f.anchor, f.issuerStore.localGroup())
            f.member.cancelGroup() // Closing the screen does not leave the durable group.
            record
        }
        openDesktopRepository(fixture.memberPath).use { store ->
            assertTrue(saved.sameRecord(assertNotNull(store.committedGroupAdoption())))
            assertNull(store.pendingGroupAdoption())
            LocalGroupService(fixture.memberIdentity, store).use { service ->
                val state = runBlocking { withTimeout(5_000) { service.state.first { it != LocalGroupState.Loading } } }
                assertEquals(LocalGroupState.Adopted(saved.anchor), state)
            }
        }
    }

    @Test
    fun cancellationAndRestartRequireNewComparisonAndCannotReplayOldClicks() = withFixture { f ->
        f.select()
        val (oldIssuer, oldMember) = f.comparisons()
        f.issuer.confirmGroup(oldIssuer)
        f.await(f.issuer) { it is GroupAdmissionState.AwaitingPeer }
        f.member.cancelGroup()
        f.member.confirmGroup(oldMember)
        assertEquals(GroupAdmissionState.Idle, f.member.admissionState.value)
        assertNull(f.memberStore.localGroup())
        f.issuer.stop()
        f.member.stop()
        f.issuer.start()
        f.member.start()
        f.awaitPorts()
        f.select()
        val (issuer, member) = f.comparisons()
        assertNotEquals(oldMember.code, member.code)
        assertEquals(issuer.code, member.code)
        f.member.confirmGroup(oldMember)
        assertEquals(member, f.member.admissionState.value)
        f.member.stop()
        f.member.confirmGroup(member)
        assertEquals(GroupAdmissionState.Idle, f.member.admissionState.value)
        assertNull(f.memberStore.localGroup())
        assertNull(f.memberStore.pendingGroupAdoption())
    }

    @Test
    fun noFounderAndTwoFoundersFailWithoutChangingEitherGroup() {
        for (founder in listOf(false, true)) withFixture(founder = founder) { f ->
            if (founder) LocalGroupService(f.memberIdentity, f.memberStore).use { service ->
                await { service.state.value == LocalGroupState.Empty }
                service.create()
                await { service.state.value is LocalGroupState.Founded }
            }
            val previous = f.memberStore.localGroup()
            f.select()
            f.await(f.member) { it is GroupAdmissionState.Failed }
            f.await(f.issuer) { it is GroupAdmissionState.Failed }
            assertEquals(previous, f.memberStore.localGroup())
            assertNull(f.memberStore.committedGroupAdoption())
            assertNull(f.memberStore.pendingGroupAdoption())
        }
    }

    @Test
    fun uncertainCommitIsNotReplayedAndExplicitRetryReplacesOnlyInterruptedRecord() {
        val calls = AtomicInteger()
        withFixture(commit = { store, record, identity ->
            if (calls.incrementAndGet() == 1) throw IOException("Test lost response before commit")
            store.commitGroupAdoption(record, identity)
        }) { f ->
            f.select()
            val (issuer, member) = f.comparisons()
            f.issuer.confirmGroup(issuer)
            f.member.confirmGroup(member)
            val failed = f.await(f.member) { it is GroupAdmissionState.Failed } as GroupAdmissionState.Failed
            assertEquals(GroupAdmissionFailure.COMMIT_OUTCOME_UNKNOWN, failed.reason)
            assertEquals(1, calls.get())
            val pending = assertNotNull(f.memberStore.pendingGroupAdoption())
            assertNull(f.memberStore.localGroup())
            f.member.confirmGroup(member)
            assertEquals(1, calls.get())
            f.select()
            val interrupted = f.await(f.member) { it is GroupAdmissionState.Failed } as GroupAdmissionState.Failed
            assertEquals(GroupAdmissionFailure.INTERRUPTED, interrupted.reason)
            assertTrue(pending.sameRecord(assertNotNull(f.memberStore.pendingGroupAdoption())))
            f.select(replaceInterrupted = true)
            val (freshIssuer, freshMember) = f.comparisons()
            assertNotEquals(member.code, freshMember.code)
            assertTrue(pending.sameRecord(assertNotNull(f.memberStore.pendingGroupAdoption())))
            f.issuer.confirmGroup(freshIssuer)
            f.member.confirmGroup(freshMember)
            f.await(f.member) { it is GroupAdmissionState.Completed }
            assertEquals(2, calls.get())
            assertNull(f.memberStore.pendingGroupAdoption())
            assertFalse(pending.sameRecord(assertNotNull(f.memberStore.committedGroupAdoption())))
        }
    }

    @Test
    fun lostCommitAcknowledgementRereadsMembershipWithoutSecondWrite() {
        val calls = AtomicInteger()
        withFixture(commit = { store, record, identity ->
            calls.incrementAndGet()
            store.commitGroupAdoption(record, identity)
            throw IOException("Test lost response after commit")
        }) { f ->
            f.select()
            val (issuer, member) = f.comparisons()
            f.member.confirmGroup(member)
            f.issuer.confirmGroup(issuer)
            val failed = f.await(f.member) { it is GroupAdmissionState.Failed } as GroupAdmissionState.Failed
            assertEquals(GroupAdmissionFailure.COMMIT_OUTCOME_UNKNOWN, failed.reason)
            f.memberGroup.refreshMembership()
            assertEquals(LocalGroupState.Adopted(f.anchor), f.awaitGroup { it is LocalGroupState.Adopted })
            f.member.confirmGroup(member)
            assertEquals(1, calls.get())
            assertNull(f.memberStore.pendingGroupAdoption())
        }
    }

    @Test
    fun cancellationAfterCommitHandoffStillSignalsDurableMembershipRefresh() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        withFixture(commit = { store, record, identity ->
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            store.commitGroupAdoption(record, identity)
        }) { f ->
            f.select()
            val (issuer, member) = f.comparisons()
            f.issuer.confirmGroup(issuer)
            f.member.confirmGroup(member)
            try {
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                f.member.cancelGroup() // Nonblocking; the in-flight transaction may complete.
                assertEquals(GroupAdmissionState.Idle, f.member.admissionState.value)
            } finally { release.countDown() }
            await { f.member.membershipRevision.value == 1L }
            assertEquals(GroupAdmissionState.Idle, f.member.admissionState.value)
            assertNotNull(f.memberStore.committedGroupAdoption())
            f.memberGroup.refreshMembership()
            assertEquals(LocalGroupState.Adopted(f.anchor), f.awaitGroup { it is LocalGroupState.Adopted })
        }
    }

    @Test
    fun selectionReadsOffCallerAndLateReadCannotReviveCancelledAttempt() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val callingThread = Thread.currentThread()
        withFixture(beforeRead = {
            assertNotEquals(callingThread, Thread.currentThread())
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
        }) { f ->
            try {
                f.member.selectGroupPeer(f.issuerPeer())
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                f.member.cancelGroup() // Must return while the read is still blocked.
                assertEquals(GroupAdmissionState.Idle, f.member.admissionState.value)
            } finally { release.countDown() }
            f.member.close() // Joins the late read; no stale publication or database use after close.
            assertEquals(GroupAdmissionState.Idle, f.member.admissionState.value)
            assertNull(f.memberStore.localGroup())
        }
    }

    @Test
    fun localBlockRevokesComparisonAndClosingAdmissionCanReturnToExplicitPocPairing() = withFixture { f ->
        f.select()
        val (issuer, member) = f.comparisons()
        f.member.block(f.issuer.identity.id)
        f.member.confirmGroup(member)
        f.issuer.confirmGroup(issuer)
        assertEquals(GroupAdmissionState.Idle, f.member.admissionState.value)
        assertNull(f.memberStore.localGroup())
        assertNull(f.memberStore.pendingGroupAdoption())
        f.issuer.cancelGroup()
        f.issuer.pair(Peer(f.member.identity.id, "membro", "127.0.0.1", f.member.port))
        f.member.pair(f.issuerPeer())
        await { f.member.state.value.comparisonCode != null && f.issuer.state.value.comparisonCode != null }
        assertEquals(f.member.state.value.comparisonCode, f.issuer.state.value.comparisonCode)
        f.member.confirm()
        f.issuer.confirm()
        await { f.member.state.value.connected.isNotEmpty() && f.issuer.state.value.connected.isNotEmpty() }
        f.member.send(f.issuer.identity.id, "regressione PoC")
        await { f.issuerStore.history().isNotEmpty() }
        assertEquals("regressione PoC", f.issuerStore.history().single().text)
        assertNull(f.memberStore.localGroup()) // PoC trust is not group membership.
    }

    private class ManualDiscovery : DiscoveryService {
        override fun start(name: String, id: String, port: Int, onPeer: (Peer) -> Unit, onLost: (String) -> Unit) = Unit
        override fun stop() = Unit
    }

    private class Fixture(
        directory: Path,
        founder: Boolean,
        issuerInitiates: Boolean,
        commit: ((GroupAdoptionRepository, PendingGroupAdoption, String) -> Boolean)?,
        beforeRead: (() -> Unit)?,
    ) : AutoCloseable {
        private val closed = AtomicBoolean()
        val memberPath = directory.resolve("member.db")
        val issuerStore = openDesktopRepository(directory.resolve("issuer.db"))
        val memberStore = openDesktopRepository(memberPath)
        private val identities = listOf(createDesktopIdentity().identity(), createDesktopIdentity().identity()).sortedBy { it.id }
        val memberIdentity = identities[if (issuerInitiates) 1 else 0]
        private val issuerIdentity = identities[if (issuerInitiates) 0 else 1]
        val anchor = lantern.domain.GroupTrustAnchor(randomNonce(), issuerIdentity.id)
        private val memberBoundary = object : DeviceRepository by memberStore, GroupAdoptionRepository by memberStore {
            override fun localGroup(): lantern.domain.GroupTrustAnchor? {
                beforeRead?.invoke()
                return memberStore.localGroup()
            }
            override fun commitGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean =
                commit?.invoke(memberStore, record, currentIdentityId) ?: memberStore.commitGroupAdoption(record, currentIdentityId)
        }
        val issuer = Node(issuerIdentity, issuerStore, ManualDiscovery(), InetAddress.getLoopbackAddress())
        val member = Node(memberIdentity, memberBoundary, ManualDiscovery(), InetAddress.getLoopbackAddress())
        val memberGroup = LocalGroupService(memberIdentity, memberStore)

        init {
            if (founder) issuerStore.foundLocalGroup(anchor, issuerIdentity.id)
            issuer.start()
            member.start()
            awaitPorts()
        }

        fun awaitPorts() = await { issuer.port > 0 && member.port > 0 }
        fun issuerPeer() = Peer(issuer.identity.id, "fondatore", "127.0.0.1", issuer.port)
        fun select(replaceInterrupted: Boolean = false) {
            issuer.selectGroupPeer(Peer(member.identity.id, "nuovo membro", "127.0.0.1", member.port))
            member.selectGroupPeer(issuerPeer(), replaceInterrupted)
        }
        fun comparisons(): Pair<GroupAdmissionState.Comparing, GroupAdmissionState.Comparing> =
            (await(issuer) { it is GroupAdmissionState.Comparing } as GroupAdmissionState.Comparing) to
                (await(member) { it is GroupAdmissionState.Comparing } as GroupAdmissionState.Comparing)
        fun await(node: Node, predicate: (GroupAdmissionState) -> Boolean): GroupAdmissionState = runBlocking {
            withTimeout(12_000) { node.admissionState.first(predicate) }
        }
        fun awaitGroup(predicate: (LocalGroupState) -> Boolean): LocalGroupState = runBlocking {
            withTimeout(5_000) { memberGroup.state.first(predicate) }
        }

        override fun close() {
            if (!closed.compareAndSet(false, true)) return
            try { member.close() } finally {
                try { issuer.close() } finally {
                    try { memberGroup.close() } finally {
                        try { memberStore.close() } finally { issuerStore.close() }
                    }
                }
            }
        }
    }

    private fun withFixture(
        founder: Boolean = true,
        issuerInitiates: Boolean = true,
        commit: ((GroupAdoptionRepository, PendingGroupAdoption, String) -> Boolean)? = null,
        beforeRead: (() -> Unit)? = null,
        block: (Fixture) -> Unit,
    ) {
        val directory = Files.createTempDirectory("lantern-group-service-")
        try { Fixture(directory, founder, issuerInitiates, commit, beforeRead).use(block) } finally {
            Files.walk(directory).use { files -> files.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private companion object {
        fun await(predicate: () -> Boolean) {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (!predicate()) {
                check(System.nanoTime() < deadline) { "Node did not reach expected state" }
                Thread.sleep(10)
            }
        }
    }
}
