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
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GroupAdoptionJournalRepositoryTest {
    private val local = "a".repeat(64)
    private val peer = "b".repeat(64)
    private val record = PendingGroupAdoption("d".repeat(64), local, peer,
        GroupTrustAnchor("c".repeat(64), peer), byteArrayOf(0, 1, -1, 3))

    @Test
    fun stageReopenAndExactRetryNeverPublishMembershipOrTrust() = withDatabase { path ->
        openDesktopRepository(path).use {
            assertNull(it.pendingGroupAdoption())
            it.rename("preservato")
            assertTrue(it.stageGroupAdoption(record, local))
            assertFalse(it.stageGroupAdoption(record, local))
        }
        openDesktopRepository(path).use {
            val restored = assertNotNull(it.pendingGroupAdoption())
            assertTrue(record.sameRecord(restored))
            restored.payload().fill(0)
            assertContentEquals(record.payload(), assertNotNull(it.pendingGroupAdoption()).payload())
            assertNull(it.localGroup())
            assertTrue(it.trusted().isEmpty())
            assertTrue(it.history().isEmpty())
            assertEquals("preservato", it.name())
        }
    }

    @Test
    fun conflictsAndIdentityChangesDoNotReplaceTheOriginal() = withDatabase { path ->
        openDesktopRepository(path).use {
            assertFails { it.stageGroupAdoption(record, peer) }
            assertNull(it.pendingGroupAdoption())
            assertTrue(it.stageGroupAdoption(record, local))
            for (other in listOf(changed(), changed(id = record.attemptId))) {
                assertFails { it.stageGroupAdoption(other, local) }
                assertTrue(record.sameRecord(assertNotNull(it.pendingGroupAdoption())))
                assertFalse(it.removeGroupAdoption(other))
            }
        }
    }

    @Test
    fun exactRemovalCannotDeleteANewerOrDifferentRecord() = withDatabase { path ->
        openDesktopRepository(path).use {
            assertFalse(it.removeGroupAdoption(record))
            assertTrue(it.stageGroupAdoption(record, local))
            assertTrue(it.removeGroupAdoption(record))
            assertNull(it.pendingGroupAdoption())
            val replacement = changed()
            assertTrue(it.stageGroupAdoption(replacement, local))
            assertFalse(it.removeGroupAdoption(record))
            assertTrue(replacement.sameRecord(assertNotNull(it.pendingGroupAdoption())))
            assertNull(it.localGroup())
        }
    }

    @Test
    fun membershipPreventsStagingButStagingIsNotAGroupReservation() = withDatabase { path ->
        val foundation = GroupTrustAnchor("e".repeat(64), local)
        openDesktopRepository(path).use {
            assertTrue(it.stageGroupAdoption(record, local))
            assertTrue(it.foundLocalGroup(foundation, local))
            assertFails { it.stageGroupAdoption(record, local) }
            assertTrue(record.sameRecord(assertNotNull(it.pendingGroupAdoption())))
            assertTrue(it.removeGroupAdoption(record))
            assertEquals(foundation, it.localGroup())
            assertFails { it.stageGroupAdoption(changed(), local) }
            assertNull(it.pendingGroupAdoption())
        }
    }

    @Test
    fun independentConnectionsArbitrateExactRetriesAndConflictsAtomically() = withDatabase { path ->
        for (second in listOf(record, changed())) {
            openDesktopRepository(path).use { left ->
                openDesktopRepository(path).use { right ->
                    val start = CountDownLatch(1)
                    val workers = Executors.newFixedThreadPool(2)
                    try {
                        val attempts = listOf(left to record, right to second).map { (repository, candidate) ->
                            workers.submit<Result<Boolean>> {
                                check(start.await(5, TimeUnit.SECONDS))
                                runCatching { repository.stageGroupAdoption(candidate, local) }
                            }
                        }
                        start.countDown()
                        val results = attempts.map { it.get(10, TimeUnit.SECONDS) }
                        assertEquals(1, results.count { it.getOrNull() == true })
                        if (second === record) assertEquals(1, results.count { it.getOrNull() == false })
                        else assertEquals(1, results.count { it.isFailure })
                        val restored = assertNotNull(left.pendingGroupAdoption())
                        assertTrue(restored.sameRecord(assertNotNull(right.pendingGroupAdoption())))
                        assertTrue(left.removeGroupAdoption(restored))
                    } finally {
                        workers.shutdownNow()
                        check(workers.awaitTermination(5, TimeUnit.SECONDS))
                    }
                }
            }
        }
    }

    @Test
    fun failuresBeforeAndAfterInsertRollBackWithoutHidingErrors() = withDatabase { path ->
        openDesktopRepository(path).use { it.rename("preservato") }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val repository = SqliteDeviceRepository(driver)
            for ((timing, action) in listOf("BEFORE" to "ABORT", "AFTER" to "FAIL")) {
                driver.execute(null, "CREATE TRIGGER reject_journal $timing INSERT ON group_adoption_journal BEGIN SELECT RAISE($action, 'test write failure'); END", 0)
                assertFails { repository.stageGroupAdoption(record, local) }
                assertNull(repository.pendingGroupAdoption())
                assertNull(repository.localGroup())
                assertEquals("preservato", repository.name())
                driver.execute(null, "DROP TRIGGER reject_journal", 0)
            }
            assertTrue(repository.stageGroupAdoption(record, local))
            driver.execute(null, "CREATE TRIGGER reject_remove AFTER DELETE ON group_adoption_journal BEGIN SELECT RAISE(FAIL, 'test delete failure'); END", 0)
            assertFails { repository.removeGroupAdoption(record) }
            assertTrue(record.sameRecord(assertNotNull(repository.pendingGroupAdoption())))
        }
        openDesktopRepository(path).use { assertTrue(record.sameRecord(assertNotNull(it.pendingGroupAdoption()))) }
    }

    @Test
    fun readOnlyAndCorruptStorageNeverBecomeAbsenceOrSuccess() = withDatabase { path ->
        openDesktopRepository(path).close()
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val repository = SqliteDeviceRepository(driver)
            assertFails {
                LanternDatabase(driver).transaction {
                    driver.execute(null, "PRAGMA query_only=ON", 0)
                    repository.stageGroupAdoption(record, local)
                }
            }
            assertNull(repository.pendingGroupAdoption())
        }
        openDesktopRepository(path).use { assertTrue(it.stageGroupAdoption(record, local)) }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val repository = SqliteDeviceRepository(driver)
            driver.execute(null, "PRAGMA ignore_check_constraints=ON", 0)
            for (assignment in listOf("payload=X''", "payload='text'", "singleton=2", "attempt_id='alias'",
                "local_identity=upper(local_identity)", "peer_identity=local_identity")) {
                assertFails {
                    LanternDatabase(driver).transaction {
                        driver.execute(null, "UPDATE group_adoption_journal SET $assignment", 0)
                        repository.pendingGroupAdoption()
                    }
                }
                assertTrue(record.sameRecord(assertNotNull(repository.pendingGroupAdoption())))
            }
            driver.execute(null, "DROP TABLE group_adoption_journal", 0)
            assertFails { repository.pendingGroupAdoption() }
        }
    }

    @Test
    fun schemaTwoMigratesAdditivelyAndMigrationFailureDoesNotResetData() = withDatabase { path ->
        val foundation = GroupTrustAnchor("e".repeat(64), local)
        openDesktopRepository(path).use {
            it.rename("legacy")
            it.trust("peer", "admission")
            it.save("m", "peer", "session", "Caffè ☕", "signature")
            it.acknowledge("m")
            assertTrue(it.foundLocalGroup(foundation, local))
        }
        JdbcSqliteDriver("jdbc:sqlite:$path").use {
            it.execute(null, "DROP TABLE group_adoption_journal", 0)
            it.execute(null, "PRAGMA user_version=2", 0)
        }
        openDesktopRepository(path).use {
            assertEquals("legacy", it.name())
            assertEquals(setOf("peer"), it.trusted())
            assertEquals("Caffè ☕", it.history().single().text)
            assertTrue(it.history().single().received)
            assertEquals(foundation, it.localGroup())
            assertNull(it.pendingGroupAdoption())
        }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { it.execute(null, "PRAGMA user_version=2", 0) }
        assertFails { openDesktopRepository(path).close() } // Existing new table deliberately conflicts.
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val version = driver.executeQuery(null, "PRAGMA user_version", { cursor ->
                check(cursor.next().value)
                QueryResult.Value(cursor.getLong(0))
            }, 0).value
            assertEquals(2L, version)
            assertEquals("legacy", SqliteDeviceRepository(driver).name())
        }
    }

    @Test
    fun maximumBlobAndSqlConstraintsMatchTheStorageContract() = withDatabase { path ->
        val maximum = PendingGroupAdoption(record.attemptId, local, peer, record.anchor,
            ByteArray(PendingGroupAdoption.MAX_PAYLOAD_BYTES) { (it % 256).toByte() })
        openDesktopRepository(path).use { assertTrue(it.stageGroupAdoption(maximum, local)) }
        openDesktopRepository(path).use {
            assertTrue(maximum.sameRecord(assertNotNull(it.pendingGroupAdoption())))
            assertTrue(it.removeGroupAdoption(maximum))
        }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            for (payload in listOf("X''", "'text'", "zeroblob(${PendingGroupAdoption.MAX_PAYLOAD_BYTES + 1})")) assertFails {
                driver.execute(null, "INSERT INTO group_adoption_journal VALUES (1, '${record.attemptId}', '$local', '$peer', '${record.anchor.groupId}', '${record.anchor.founderId}', $payload)", 0)
            }
            assertNull(SqliteDeviceRepository(driver).pendingGroupAdoption())
        }
    }

    @Test
    fun failureInSecondMigrationRollsBackTheEarlierCreateAndVersion() = withDatabase { path ->
        openDesktopRepository(path).use { it.rename("versione uno preservata") }
        JdbcSqliteDriver("jdbc:sqlite:$path").use {
            // Version-1 fixture with a conflicting future table: 1.sqm succeeds, 2.sqm fails.
            it.execute(null, "DROP TABLE local_group", 0)
            it.execute(null, "PRAGMA user_version=1", 0)
        }
        assertFails { openDesktopRepository(path).close() }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val version = driver.executeQuery(null, "PRAGMA user_version", { cursor ->
                check(cursor.next().value)
                QueryResult.Value(cursor.getLong(0))
            }, 0).value
            val localGroupTables = driver.executeQuery(null,
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='local_group'", { cursor ->
                    check(cursor.next().value)
                    QueryResult.Value(cursor.getLong(0))
                }, 0).value
            assertEquals(1L, version)
            assertEquals(0L, localGroupTables)
            assertEquals("versione uno preservata", SqliteDeviceRepository(driver).name())
        }
    }

    private fun changed(id: String = "e".repeat(64)) = PendingGroupAdoption(id, local, peer, record.anchor, byteArrayOf(4))

    private fun withDatabase(block: (Path) -> Unit) {
        val directory = Files.createTempDirectory("lantern-adoption-journal-test-")
        try { block(directory.resolve("lantern.db")) }
        finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
