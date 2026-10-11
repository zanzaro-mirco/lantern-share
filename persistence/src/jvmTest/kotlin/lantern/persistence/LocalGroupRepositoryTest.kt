package lantern.persistence

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import app.cash.sqldelight.db.QueryResult
import lantern.domain.GroupTrustAnchor
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LocalGroupRepositoryTest {
    private val founder = "a".repeat(64)
    private val first = GroupTrustAnchor("b".repeat(64), founder)
    private val other = GroupTrustAnchor("c".repeat(64), founder)

    @Test
    fun foundationSurvivesReopenWithoutAuthorizingPeers() = withDatabase { path ->
        openDesktopRepository(path).use { repository ->
            assertNull(repository.localGroup())
            repository.rename("PC di prova")
            assertTrue(repository.foundLocalGroup(first, founder))
            assertEquals(first, repository.localGroup())
            assertTrue(repository.trusted().isEmpty())
        }
        openDesktopRepository(path).use { repository ->
            assertEquals(first, repository.localGroup())
            assertEquals("PC di prova", repository.name())
            assertTrue(repository.trusted().isEmpty())
            assertFalse(repository.foundLocalGroup(first, founder))
            assertFalse(repository.foundLocalGroup(other, founder))
            assertEquals(first, repository.localGroup())
        }
    }

    @Test
    fun identityMismatchFailsWithoutInsertingOrReplacing() = withDatabase { path ->
        openDesktopRepository(path).use { repository ->
            assertFails { repository.foundLocalGroup(first, "d".repeat(64)) }
            assertNull(repository.localGroup())
            assertTrue(repository.foundLocalGroup(first, founder))
            assertFails { repository.foundLocalGroup(other, "") }
            assertEquals(first, repository.localGroup())
        }
    }

    @Test
    fun independentConnectionsCannotBothFoundAGroup() = withDatabase { path ->
        openDesktopRepository(path).use { left ->
            openDesktopRepository(path).use { right ->
                val start = CountDownLatch(1)
                val workers = Executors.newFixedThreadPool(2)
                try {
                    val attempts = listOf(left to first, right to other).map { (repository, anchor) ->
                        workers.submit<Boolean> {
                            check(start.await(5, TimeUnit.SECONDS))
                            repository.foundLocalGroup(anchor, founder)
                        }
                    }
                    start.countDown()
                    val results = attempts.map { it.get(10, TimeUnit.SECONDS) }
                    assertEquals(1, results.count { it })
                    val winner = if (results[0]) first else other
                    assertEquals(winner, left.localGroup())
                    assertEquals(winner, right.localGroup())
                } finally {
                    workers.shutdownNow()
                    check(workers.awaitTermination(5, TimeUnit.SECONDS))
                }
            }
        }
    }

    @Test
    fun failedInsertDoesNotPublishMembershipAndCanBeRetriedAsANewRequest() = withDatabase { path ->
        openDesktopRepository(path).use { repository -> repository.rename("preservato") }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            driver.execute(null, "CREATE TRIGGER reject_foundation BEFORE INSERT ON local_group BEGIN SELECT RAISE(ABORT, 'test write failure'); END", 0)
            SqliteDeviceRepository(driver).let { repository ->
                assertFails { repository.foundLocalGroup(first, founder) }
                assertNull(repository.localGroup())
                assertEquals("preservato", repository.name())
                driver.execute(null, "DROP TRIGGER reject_foundation", 0)
                assertTrue(repository.foundLocalGroup(other, founder))
            }
        }
        openDesktopRepository(path).use { assertEquals(other, it.localGroup()) }
    }

    @Test
    fun failureAfterInsertRollsBackTheWholeTransactionAndDoesNotAuthorizePeers() = withDatabase { path ->
        openDesktopRepository(path).use { repository ->
            repository.rename("preservato")
            repository.trust("peer", "existing admission")
        }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            driver.execute(null, "CREATE TRIGGER reject_after_foundation AFTER INSERT ON local_group BEGIN SELECT RAISE(FAIL, 'test after insert failure'); END", 0)
            val repository = SqliteDeviceRepository(driver)
            assertFails { repository.foundLocalGroup(first, founder) }
            // RAISE(FAIL) by itself retains the statement's earlier writes. The repository's
            // surrounding transaction must roll back the inserted row, not only skip an ack.
            assertNull(repository.localGroup())
            assertEquals("preservato", repository.name())
            assertEquals(setOf("peer"), repository.trusted())
        }
        openDesktopRepository(path).use { repository ->
            assertNull(repository.localGroup())
            assertEquals(setOf("peer"), repository.trusted())
        }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            driver.execute(null, "DROP TRIGGER reject_after_foundation", 0)
        }
        openDesktopRepository(path).use { assertTrue(it.foundLocalGroup(other, founder)) }
    }

    @Test
    fun readOnlyDatabaseFailureDoesNotBecomeAbsenceOrSuccess() = withDatabase { path ->
        openDesktopRepository(path).use { it.rename("preservato") }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val repository = SqliteDeviceRepository(driver)
            // JDBC can use different connections for transactions and standalone statements.
            // Set the connection-local pragma on the transaction that attempts the insert.
            assertFails {
                LanternDatabase(driver).transaction {
                    driver.execute(null, "PRAGMA query_only=ON", 0)
                    repository.foundLocalGroup(first, founder)
                }
            }
            assertNull(repository.localGroup())
            assertEquals("preservato", repository.name())
        }
        openDesktopRepository(path).use { repository ->
            assertNull(repository.localGroup())
            assertTrue(repository.foundLocalGroup(first, founder))
        }
    }

    @Test
    fun legacyVersionOneMigratesWithoutLosingExistingData() = withDatabase { path ->
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            // The actual old schema, not Schema.create() from the new version.
            driver.execute(null, "CREATE TABLE trusted(id TEXT NOT NULL PRIMARY KEY, admission TEXT NOT NULL)", 0)
            driver.execute(null, "CREATE TABLE setting(key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)", 0)
            driver.execute(null, "CREATE TABLE message(id TEXT NOT NULL PRIMARY KEY, sender TEXT NOT NULL, session TEXT NOT NULL, body TEXT NOT NULL, signature TEXT NOT NULL, received INTEGER NOT NULL DEFAULT 0)", 0)
            driver.execute(null, "INSERT INTO setting VALUES ('name', 'legacy')", 0)
            driver.execute(null, "INSERT INTO trusted VALUES ('peer', 'existing admission')", 0)
            driver.execute(null, "INSERT INTO message VALUES ('message', 'peer', 'session', 'Caffè ☕', 'signature', 1)", 0)
            driver.execute(null, "PRAGMA user_version=1", 0)
        }
        openDesktopRepository(path).use { repository ->
            assertEquals("legacy", repository.name())
            assertEquals(setOf("peer"), repository.trusted())
            assertEquals("Caffè ☕", repository.history().single().text)
            assertTrue(repository.history().single().received)
            assertNull(repository.localGroup())
            assertTrue(repository.foundLocalGroup(first, founder))
        }
        openDesktopRepository(path).use { assertEquals(first, it.localGroup()) }
    }

    @Test
    fun corruptOriginDoesNotLookLikeAnEmptyDatabase() = withDatabase { path ->
        openDesktopRepository(path).use { assertNull(it.localGroup()) }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            driver.execute(null, "INSERT INTO local_group VALUES (1, ' ', 'founder')", 0)
        }
        openDesktopRepository(path).use { repository ->
            assertFails { repository.localGroup() }
            assertFalse(repository.foundLocalGroup(first, founder))
            assertFails { repository.localGroup() }
        }
    }

    @Test
    fun migrationFailurePreservesVersionAndDoesNotResetExistingDatabase() = withDatabase { path ->
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            driver.execute(null, "CREATE TABLE local_group(existing TEXT)", 0)
            driver.execute(null, "INSERT INTO local_group VALUES ('preserved')", 0)
            driver.execute(null, "PRAGMA user_version=1", 0)
        }
        assertFails { openDesktopRepository(path).close() }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val version = driver.executeQuery(null, "PRAGMA user_version", { cursor ->
                check(cursor.next().value)
                QueryResult.Value(cursor.getLong(0))
            }, 0).value
            assertEquals(1L, version)
            val existing = driver.executeQuery(null, "SELECT existing FROM local_group", { cursor ->
                check(cursor.next().value)
                QueryResult.Value(cursor.getString(0))
            }, 0).value
            assertEquals("preserved", existing)
        }
    }

    @Test
    fun newerDatabaseVersionIsRejectedInsteadOfDowngraded() = withDatabase { path ->
        val newer = LanternDatabase.Schema.version + 1
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            driver.execute(null, "PRAGMA user_version=$newer", 0)
        }
        assertFails { openDesktopRepository(path).close() }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val version = driver.executeQuery(null, "PRAGMA user_version", { cursor ->
                check(cursor.next().value)
                QueryResult.Value(cursor.getLong(0))
            }, 0).value
            assertEquals(newer, version)
        }
    }

    private fun withDatabase(test: (Path) -> Unit) {
        val directory = Files.createTempDirectory("lantern-local-group-test-")
        try {
            test(directory.resolve("lantern.db"))
        } finally {
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::delete)
            }
        }
    }
}
