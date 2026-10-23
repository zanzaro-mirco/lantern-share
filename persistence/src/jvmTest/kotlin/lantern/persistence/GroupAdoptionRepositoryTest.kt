package lantern.persistence

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GroupAdoptionRepositoryTest {
    private val local = "a".repeat(64)
    private val peer = "b".repeat(64)
    private val record = PendingGroupAdoption("d".repeat(64), local, peer,
        GroupTrustAnchor("c".repeat(64), peer), byteArrayOf(1, 2, 3))

    @Test
    fun commitReopenAndExactRetryPreserveMembershipWithoutPoCTrust() = withDatabase { path ->
        openDesktopRepository(path).use {
            it.rename("preservato")
            assertTrue(it.stageGroupAdoption(record, local))
            assertTrue(it.commitGroupAdoption(record, local))
            assertNull(it.pendingGroupAdoption())
            assertEquals(record.anchor, it.localGroup())
        }
        openDesktopRepository(path).use {
            assertTrue(record.sameRecord(assertNotNull(it.committedGroupAdoption())))
            assertFalse(it.commitGroupAdoption(record, local))
            assertFalse(it.foundLocalGroup(GroupTrustAnchor("e".repeat(64), local), local))
            assertFails { it.stageGroupAdoption(record, local) }
            assertFalse(it.removeGroupAdoption(record))
            assertEquals(record.anchor, it.localGroup())
            assertTrue(it.trusted().isEmpty())
            assertTrue(it.history().isEmpty())
            assertEquals("preservato", it.name())
        }
    }

    @Test
    fun unstagedMismatchIdentityAndFoundationCannotCommit() = withDatabase { path ->
        openDesktopRepository(path).use {
            assertFails { it.commitGroupAdoption(record, local) }
            assertTrue(it.stageGroupAdoption(record, local))
            assertFails { it.commitGroupAdoption(record, peer) }
            val changed = PendingGroupAdoption(record.attemptId, local, peer, record.anchor, byteArrayOf(4))
            assertFails { it.commitGroupAdoption(changed, local) }
            val foundation = GroupTrustAnchor("e".repeat(64), local)
            assertTrue(it.foundLocalGroup(foundation, local))
            assertFails { it.commitGroupAdoption(record, local) }
            assertNull(it.committedGroupAdoption())
            assertTrue(record.sameRecord(assertNotNull(it.pendingGroupAdoption())))
            assertEquals(foundation, it.localGroup())
        }
    }

    @Test
    fun faultsAfterInsertAndJournalDeleteRollBackBothChanges() = withDatabase { path ->
        openDesktopRepository(path).use { assertTrue(it.stageGroupAdoption(record, local)) }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val store = SqliteDeviceRepository(driver)
            for (fault in listOf("BEFORE INSERT ON group_adoption", "AFTER INSERT ON group_adoption",
                "AFTER DELETE ON group_adoption_journal")) {
                driver.execute(null, "CREATE TRIGGER fail_commit $fault BEGIN SELECT RAISE(FAIL, 'test commit failure'); END", 0)
                assertFails { store.commitGroupAdoption(record, local) }
                assertNull(store.committedGroupAdoption())
                assertNull(store.localGroup())
                assertTrue(record.sameRecord(assertNotNull(store.pendingGroupAdoption())))
                driver.execute(null, "DROP TRIGGER fail_commit", 0)
            }
            assertTrue(store.commitGroupAdoption(record, local))
        }
        openDesktopRepository(path).use {
            assertTrue(record.sameRecord(assertNotNull(it.committedGroupAdoption())))
            assertNull(it.pendingGroupAdoption())
        }
    }

    @Test
    fun independentFoundationAndAdoptionHaveExactlyOneWinner() = withDatabase { path ->
        openDesktopRepository(path).use { assertTrue(it.stageGroupAdoption(record, local)) }
        openDesktopRepository(path).use { left ->
            openDesktopRepository(path).use { right ->
                val start = CountDownLatch(1)
                val workers = Executors.newFixedThreadPool(2)
                try {
                    val adopt = workers.submit<Result<Boolean>> { start.await(); runCatching { left.commitGroupAdoption(record, local) } }
                    val found = workers.submit<Boolean> { start.await(); right.foundLocalGroup(GroupTrustAnchor("e".repeat(64), local), local) }
                    start.countDown()
                    val adopted = adopt.get(10, TimeUnit.SECONDS)
                    val founded = found.get(10, TimeUnit.SECONDS)
                    assertEquals(1, listOf(adopted.getOrNull() == true, founded).count { it })
                    assertEquals(left.localGroup(), right.localGroup())
                    if (founded) { assertTrue(adopted.isFailure); assertNull(left.committedGroupAdoption()) }
                    else assertEquals(record.anchor, left.localGroup())
                } finally { workers.shutdownNow(); assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS)) }
            }
        }
    }

    @Test
    fun versionThreeMigrationPreservesPendingJournalAndEarlierData() = withDatabase { path ->
        openDesktopRepository(path).use {
            it.rename("schema tre")
            it.trust("peer", "admission")
            it.save("m", "peer", "s", "testo preservato", "sig")
            assertTrue(it.stageGroupAdoption(record, local))
        }
        JdbcSqliteDriver("jdbc:sqlite:$path").use {
            it.execute(null, "DROP TABLE group_adoption", 0)
            for (table in listOf("group_text", "group_text_recipient", "group_text_clock", "group_text_used_session")) {
                it.execute(null, "DROP TABLE $table", 0)
            }
            it.execute(null, "PRAGMA user_version=3", 0)
        }
        openDesktopRepository(path).use {
            assertNull(it.committedGroupAdoption())
            assertTrue(record.sameRecord(assertNotNull(it.pendingGroupAdoption())))
            assertEquals("schema tre", it.name())
            assertEquals(setOf("peer"), it.trusted())
            assertEquals("testo preservato", it.history().single().text)
            assertTrue(it.commitGroupAdoption(record, local))
        }
    }

    @Test
    fun migrationFailurePreservesVersionAndExistingData() = withDatabase { path ->
        openDesktopRepository(path).use { it.rename("non resettare") }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { it.execute(null, "PRAGMA user_version=3", 0) }
        assertFails { openDesktopRepository(path).close() }
        JdbcSqliteDriver("jdbc:sqlite:$path").use {
            val version = it.executeQuery(null, "PRAGMA user_version", { cursor ->
                check(cursor.next().value); QueryResult.Value(cursor.getLong(0))
            }, 0).value
            assertEquals(3L, version)
            assertEquals("non resettare", SqliteDeviceRepository(it).name())
        }
    }

    @Test
    fun readOnlyCommitAndCorruptDurableDataNeverLookLikeSuccessOrAbsence() = withDatabase { path ->
        openDesktopRepository(path).use { assertTrue(it.stageGroupAdoption(record, local)) }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val store = SqliteDeviceRepository(driver)
            assertFails {
                LanternDatabase(driver).transaction {
                    driver.execute(null, "PRAGMA query_only=ON", 0)
                    store.commitGroupAdoption(record, local)
                }
            }
            assertNull(store.committedGroupAdoption())
            assertTrue(record.sameRecord(assertNotNull(store.pendingGroupAdoption())))
        }
        openDesktopRepository(path).use { assertTrue(it.commitGroupAdoption(record, local)) }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val store = SqliteDeviceRepository(driver)
            driver.execute(null, "PRAGMA ignore_check_constraints=ON", 0)
            for (assignment in listOf("singleton=2", "payload='text'", "payload=X''", "local_identity='alias'")) {
                assertFails {
                    LanternDatabase(driver).transaction {
                        driver.execute(null, "UPDATE group_adoption SET $assignment", 0)
                        store.localGroup()
                    }
                }
                assertTrue(record.sameRecord(assertNotNull(store.committedGroupAdoption())))
            }
        }
    }

    private fun withDatabase(test: (Path) -> Unit) {
        val directory = Files.createTempDirectory("lantern-adoption-commit-")
        try { test(directory.resolve("lantern.db")) }
        finally { Files.walk(directory).use { files -> files.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
