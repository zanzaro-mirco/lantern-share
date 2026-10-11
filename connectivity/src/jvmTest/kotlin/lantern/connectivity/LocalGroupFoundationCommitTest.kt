package lantern.connectivity

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository
import lantern.persistence.SqliteDeviceRepository
import lantern.persistence.openDesktopRepository
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LocalGroupFoundationCommitTest {
    @Test
    fun committedMeansSavedBeforeReturnAndSurvivesReopen() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val owner = LocalGroupFoundation(identity)
        val ticket = assertNotNull(owner.prepare(null))
        val saved = openDesktopRepository(path).use { repository ->
            assertEquals(LocalGroupFoundationCommit.Committed, owner.commit(ticket, identity, repository))
            assertTrue(repository.trusted().isEmpty())
            assertEquals(LocalGroupFoundationCommit.Invalidated, owner.commit(ticket, identity, repository))
            assertNotNull(repository.localGroup())
        }
        openDesktopRepository(path).use { assertEquals(saved, it.localGroup()) }
        assertEquals(identity.id, saved.founderId)
    }

    @Test
    fun competingPreparedRequestsCannotReplaceTheFirstCommit() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val first = LocalGroupFoundation(identity)
        val second = LocalGroupFoundation(identity)
        val firstTicket = assertNotNull(first.prepare(null))
        val secondTicket = assertNotNull(second.prepare(null))
        openDesktopRepository(path).use { repository ->
            assertEquals(LocalGroupFoundationCommit.Committed, first.commit(firstTicket, identity, repository))
            val saved = repository.localGroup()
            assertEquals(LocalGroupFoundationCommit.AlreadyInGroup, second.commit(secondTicket, identity, repository))
            assertEquals(saved, repository.localGroup())
        }
    }

    @Test
    fun cancelledOrLeftOwnerDoesNotEvenReadStorage() {
        val identity = createDesktopIdentity().identity()
        val mustNotAccess = object : LocalGroupRepository {
            override fun localGroup(): GroupTrustAnchor? = error("cancelled request must not read")
            override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean =
                error("cancelled request must not write")
        }
        for (leave in listOf(false, true)) {
            val owner = LocalGroupFoundation(identity)
            val ticket = assertNotNull(owner.prepare(null))
            if (leave) owner.leaveGroup() else owner.cancel()
            assertEquals(LocalGroupFoundationCommit.Invalidated, owner.commit(ticket, identity, mustNotAccess))
        }
    }

    @Test
    fun changedIdentityAndForeignTicketDoNotPersist() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val otherIdentity = createDesktopIdentity().identity()
        val first = LocalGroupFoundation(identity)
        val second = LocalGroupFoundation(identity)
        val firstTicket = assertNotNull(first.prepare(null))
        val secondTicket = assertNotNull(second.prepare(null))
        openDesktopRepository(path).use { repository ->
            assertEquals(LocalGroupFoundationCommit.Invalidated, second.commit(firstTicket, identity, repository))
            assertNull(repository.localGroup())
            assertEquals(LocalGroupFoundationCommit.Invalidated, first.commit(firstTicket, otherIdentity, repository))
            assertNull(repository.localGroup())
            assertEquals(LocalGroupFoundationCommit.Committed, second.commit(secondTicket, identity, repository))
        }
    }

    @Test
    fun failureAfterHandoffDoesNotReturnCommittedOrReplayTheTicket() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val owner = LocalGroupFoundation(identity)
        val ticket = assertNotNull(owner.prepare(null))
        openDesktopRepository(path).use { assertNull(it.localGroup()) }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            driver.execute(null, "CREATE TRIGGER reject_foundation BEFORE INSERT ON local_group BEGIN SELECT RAISE(ABORT, 'test commit failure'); END", 0)
            val repository = SqliteDeviceRepository(driver)
            assertFails { owner.commit(ticket, identity, repository) }
            assertNull(repository.localGroup())
            driver.execute(null, "DROP TRIGGER reject_foundation", 0)
            assertEquals(LocalGroupFoundationCommit.Invalidated, owner.commit(ticket, identity, repository))
            assertNull(repository.localGroup())
            val recovery = LocalGroupFoundation(identity)
            val freshTicket = assertNotNull(recovery.prepare(repository.localGroup()))
            assertEquals(LocalGroupFoundationCommit.Committed, recovery.commit(freshTicket, identity, repository))
        }
        openDesktopRepository(path).use { assertEquals(identity.id, it.localGroup()?.founderId) }
    }

    @Test
    fun membershipInsertedAfterSnapshotIsStillNotReplaced() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val owner = LocalGroupFoundation(identity)
        val ticket = assertNotNull(owner.prepare(null))
        val competing = GroupTrustAnchor(randomNonce(), identity.id)
        openDesktopRepository(path).use { repository ->
            openDesktopRepository(path).use { otherConnection ->
                val racing = object : LocalGroupRepository {
                    override fun localGroup(): GroupTrustAnchor? {
                        val snapshot = repository.localGroup()
                        assertTrue(otherConnection.foundLocalGroup(competing, identity.id))
                        return snapshot
                    }
                    override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean =
                        repository.foundLocalGroup(anchor, currentIdentityId)
                }
                assertEquals(LocalGroupFoundationCommit.AlreadyInGroup, owner.commit(ticket, identity, racing))
                assertEquals(competing, repository.localGroup())
            }
        }
    }

    @Test
    fun cancellationDuringSnapshotReadPreventsTheWrite() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val owner = LocalGroupFoundation(identity)
        val ticket = assertNotNull(owner.prepare(null))
        openDesktopRepository(path).use { repository ->
            val cancelling = object : LocalGroupRepository {
                override fun localGroup(): GroupTrustAnchor? {
                    owner.cancel()
                    return repository.localGroup()
                }
                override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean =
                    error("must not write after cancellation")
            }
            assertEquals(LocalGroupFoundationCommit.Invalidated, owner.commit(ticket, identity, cancelling))
            assertNull(repository.localGroup())
        }
    }

    private fun withDatabase(test: (Path) -> Unit) {
        val directory = Files.createTempDirectory("lantern-foundation-commit-test-")
        try {
            test(directory.resolve("lantern.db"))
        } finally {
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::delete)
            }
        }
    }
}
