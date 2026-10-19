package lantern.connectivity

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupFailure
import lantern.domain.LocalGroupRepository
import lantern.domain.LocalGroupState
import lantern.persistence.openDesktopRepository
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LocalGroupServiceTest {
    @Test
    fun membershipRefreshDuringInitialReadIsNotLostAndNeverWrites() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val reads = AtomicInteger()
        openDesktopRepository(path).use { repository ->
            val boundary = object : LocalGroupRepository by repository {
                override fun localGroup(): GroupTrustAnchor? {
                    val snapshot = repository.localGroup()
                    if (reads.incrementAndGet() == 1) {
                        entered.countDown()
                        check(release.await(5, TimeUnit.SECONDS))
                    }
                    return snapshot
                }
                override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean =
                    error("Refresh must never write")
            }
            LocalGroupService(identity, boundary).use { service ->
                try {
                    assertTrue(entered.await(5, TimeUnit.SECONDS))
                    val anchor = GroupTrustAnchor(randomNonce(), identity.id)
                    repository.foundLocalGroup(anchor, identity.id)
                    service.refreshMembership()
                    release.countDown()
                    assertEquals(LocalGroupState.Founded(anchor), await(service) { it is LocalGroupState.Founded })
                    assertEquals(2, reads.get())
                } finally { release.countDown() }
            }
        }
    }

    @Test
    fun openingDoesNotCreateAndExplicitCreationSurvivesReopenWithoutTrust() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val saved = openDesktopRepository(path).use { repository ->
            repository.rename("preservato")
            LocalGroupService(identity, repository).use { service ->
                assertEquals(LocalGroupState.Empty, await(service) { it != LocalGroupState.Loading })
                assertNull(repository.localGroup())
                service.create()
                val founded = await(service) { it is LocalGroupState.Founded } as LocalGroupState.Founded
                assertEquals(identity.id, founded.anchor.founderId)
                assertTrue(repository.trusted().isEmpty())
                service.create()
                assertEquals(founded.anchor, repository.localGroup())
                founded.anchor
            }
        }
        openDesktopRepository(path).use { repository ->
            LocalGroupService(identity, repository).use { service ->
                assertEquals(LocalGroupState.Founded(saved), await(service) { it != LocalGroupState.Loading })
                assertEquals("preservato", repository.name())
                assertTrue(repository.trusted().isEmpty())
            }
        }
    }

    @Test
    fun readsAndWritesRunOffTheCallingThreadAndRepeatedClicksDoNotQueueWrites() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val callingThread = Thread.currentThread()
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val writes = AtomicInteger()
        openDesktopRepository(path).use { repository ->
            val observed = object : LocalGroupRepository by repository {
                override fun localGroup(): GroupTrustAnchor? {
                    assertNotEquals(callingThread, Thread.currentThread())
                    return repository.localGroup()
                }
                override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean {
                    assertNotEquals(callingThread, Thread.currentThread())
                    writes.incrementAndGet()
                    started.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                    return repository.foundLocalGroup(anchor, currentIdentityId)
                }
            }
            LocalGroupService(identity, observed).use { service ->
                await(service) { it == LocalGroupState.Empty }
                service.create()
                try {
                    assertTrue(started.await(5, TimeUnit.SECONDS))
                    repeat(20) { service.create(); service.reload() }
                    assertEquals(LocalGroupState.Creating, service.state.value)
                    assertEquals(1, writes.get())
                } finally { release.countDown() }
                await(service) { it is LocalGroupState.Founded }
                assertEquals(1, writes.get())
            }
        }
    }

    @Test
    fun missingRootAfterAcknowledgementNeverLooksLikeSuccessfulCreationOrEmptyRecovery() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        openDesktopRepository(path).use { repository ->
            // Deliberately violates the repository contract, confined to this regression fixture.
            val broken = object : LocalGroupRepository by repository {
                override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String) = true
            }
            LocalGroupService(identity, broken).use { service ->
                await(service) { it == LocalGroupState.Empty }
                service.create()
                assertEquals(LocalGroupState.Failed(LocalGroupFailure.STORAGE), await(service) { it is LocalGroupState.Failed })
                service.create()
                assertEquals(LocalGroupState.Failed(LocalGroupFailure.STORAGE), service.state.value)
                assertNull(repository.localGroup())
            }
        }
    }

    @Test
    fun failedWriteDisablesCreationUntilExplicitReadOnlyRecovery() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val writes = AtomicInteger()
        openDesktopRepository(path).use { repository ->
            val failing = object : LocalGroupRepository by repository {
                override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean {
                    writes.incrementAndGet()
                    error("fixture write failure")
                }
            }
            LocalGroupService(identity, failing).use { service ->
                await(service) { it == LocalGroupState.Empty }
                service.create()
                assertEquals(LocalGroupState.Failed(LocalGroupFailure.STORAGE), await(service) { it is LocalGroupState.Failed })
                repeat(20) { service.create() }
                assertEquals(1, writes.get())
                assertNull(repository.localGroup())
                service.reload()
                await(service) { it == LocalGroupState.Empty }
                assertEquals(1, writes.get())
            }
        }
    }

    @Test
    fun uncertainWriteAcknowledgementRecoversThePersistedRootWithoutAnotherWrite() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val writes = AtomicInteger()
        openDesktopRepository(path).use { repository ->
            val uncertain = object : LocalGroupRepository by repository {
                override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean {
                    writes.incrementAndGet()
                    assertTrue(repository.foundLocalGroup(anchor, currentIdentityId))
                    error("fixture acknowledgement lost after commit")
                }
            }
            LocalGroupService(identity, uncertain).use { service ->
                await(service) { it == LocalGroupState.Empty }
                service.create()
                await(service) { it is LocalGroupState.Failed }
                val persisted = repository.localGroup()
                assertTrue(persisted != null)
                service.create()
                service.reload()
                assertEquals(LocalGroupState.Founded(persisted), await(service) { it is LocalGroupState.Founded })
                assertEquals(1, writes.get())
            }
        }
    }

    @Test
    fun changedIdentityCannotReplaceThePersistedRoot() = withDatabase { path ->
        val original = createDesktopIdentity().identity()
        val changed = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor("a".repeat(64), original.id)
        openDesktopRepository(path).use { repository ->
            assertTrue(repository.foundLocalGroup(anchor, original.id))
            LocalGroupService(changed, repository).use { service ->
                assertEquals(LocalGroupState.Failed(LocalGroupFailure.IDENTITY_MISMATCH), await(service) { it != LocalGroupState.Loading })
                service.create()
                service.reload()
                await(service) { it != LocalGroupState.Loading }
                assertEquals(anchor, repository.localGroup())
            }
        }
    }

    @Test
    fun invalidPersistedRootDoesNotOfferCreationOrNormalizeData() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor("INVALID", identity.id)
        openDesktopRepository(path).use { repository ->
            assertTrue(repository.foundLocalGroup(anchor, identity.id))
            LocalGroupService(identity, repository).use { service ->
                assertEquals(LocalGroupState.Failed(LocalGroupFailure.INVALID_ROOT), await(service) { it != LocalGroupState.Loading })
                service.create()
                assertEquals(anchor, repository.localGroup())
            }
        }
    }

    @Test
    fun initialReadFailureCanOnlyRecoverThroughExplicitReload() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val unreadable = java.util.concurrent.atomic.AtomicBoolean(true)
        val writes = AtomicInteger()
        openDesktopRepository(path).use { repository ->
            val observed = object : LocalGroupRepository by repository {
                override fun localGroup(): GroupTrustAnchor? {
                    if (unreadable.get()) error("fixture storage unreadable")
                    return repository.localGroup()
                }
                override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean {
                    writes.incrementAndGet()
                    return repository.foundLocalGroup(anchor, currentIdentityId)
                }
            }
            LocalGroupService(identity, observed).use { service ->
                await(service) { it is LocalGroupState.Failed }
                service.create()
                assertEquals(0, writes.get())
                unreadable.set(false)
                service.reload()
                await(service) { it == LocalGroupState.Empty }
                assertNull(repository.localGroup())
                assertEquals(0, writes.get())
            }
        }
    }

    @Test
    fun competingFoundationIsRereadInsteadOfPublishingTheLosingDraft() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val winner = GroupTrustAnchor("c".repeat(64), identity.id)
        openDesktopRepository(path).use { repository ->
            openDesktopRepository(path).use { competitor ->
                val observed = object : LocalGroupRepository by repository {
                    override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean {
                        assertTrue(competitor.foundLocalGroup(winner, identity.id))
                        return repository.foundLocalGroup(anchor, currentIdentityId)
                    }
                }
                LocalGroupService(identity, observed).use { service ->
                    await(service) { it == LocalGroupState.Empty }
                    service.create()
                    assertEquals(LocalGroupState.Founded(winner), await(service) { it is LocalGroupState.Founded })
                    assertEquals(winner, repository.localGroup())
                }
            }
        }
    }

    @Test
    fun closeBeforeCommitHandoffPreventsAnyWrite() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val reads = AtomicInteger()
        val writes = AtomicInteger()
        val preparing = CountDownLatch(1)
        val release = CountDownLatch(1)
        val finished = CountDownLatch(1)
        openDesktopRepository(path).use { repository ->
            val observed = object : LocalGroupRepository by repository {
                override fun localGroup(): GroupTrustAnchor? {
                    if (reads.incrementAndGet() == 2) {
                        preparing.countDown()
                        check(release.await(5, TimeUnit.SECONDS))
                    }
                    return repository.localGroup()
                }
                override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean {
                    writes.incrementAndGet()
                    return repository.foundLocalGroup(anchor, currentIdentityId)
                }
            }
            val service = LocalGroupService(identity, observed)
            try {
                await(service) { it == LocalGroupState.Empty }
                service.create()
                assertTrue(preparing.await(5, TimeUnit.SECONDS))
                val closer = Thread { service.close(); finished.countDown() }
                closer.start()
                try { await(service) { it == LocalGroupState.Closed } }
                finally { release.countDown() }
                assertTrue(finished.await(5, TimeUnit.SECONDS))
                closer.join(5000)
                assertEquals(0, writes.get())
                assertNull(repository.localGroup())
                assertEquals(LocalGroupState.Closed, service.state.value)
            } finally { release.countDown(); service.close() }
        }
    }

    @Test
    fun closeDuringCommitWaitsForTheDriverAndPreventsLateStateRevival() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val closed = CountDownLatch(2)
        openDesktopRepository(path).use { repository ->
            val slow = object : LocalGroupRepository by repository {
                override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean {
                    started.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                    return repository.foundLocalGroup(anchor, currentIdentityId)
                }
            }
            val service = LocalGroupService(identity, slow)
            try {
                await(service) { it == LocalGroupState.Empty }
                service.create()
                assertTrue(started.await(5, TimeUnit.SECONDS))
                val closer = Thread { service.close(); closed.countDown() }
                val secondCloser = Thread { service.close(); closed.countDown() }
                closer.start()
                secondCloser.start()
                try {
                    await(service) { it == LocalGroupState.Closed }
                    assertEquals(2L, closed.count)
                    service.create()
                    service.reload()
                } finally { release.countDown() }
                assertTrue(closed.await(5, TimeUnit.SECONDS))
                closer.join(5000)
                secondCloser.join(5000)
                assertFalse(closer.isAlive)
                assertFalse(secondCloser.isAlive)
                assertEquals(LocalGroupState.Closed, service.state.value)
                // The already handed-off synchronous transaction is allowed to finish.
                assertTrue(repository.localGroup() != null)
            } finally { release.countDown(); service.close() }
        }
    }

    private fun await(service: LocalGroupService, predicate: (LocalGroupState) -> Boolean): LocalGroupState =
        runBlocking { withTimeout(5000) { service.state.first(predicate) } }

    private fun withDatabase(test: (Path) -> Unit) {
        val directory = Files.createTempDirectory("lantern-group-service-test-")
        try { test(directory.resolve("lantern.db")) }
        finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
