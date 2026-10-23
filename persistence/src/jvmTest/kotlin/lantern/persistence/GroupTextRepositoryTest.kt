package lantern.persistence

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import lantern.domain.GroupTextContent
import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption
import lantern.domain.SignedGroupText
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

class GroupTextRepositoryTest {
    private val a = "a".repeat(64)
    private val b = "b".repeat(64)
    private val g = "c".repeat(64)
    private val s = "d".repeat(64)
    private val anchor = GroupTrustAnchor(g, a)
    private fun message(number: Int = 1, author: String = a, sequence: Long = number.toLong(), logical: Long = number.toLong(),
        session: String = s, body: String = "Caffè ☕", recipients: List<String> = listOf(a, b)) =
        SignedGroupText(GroupTextContent("00000000-0000-0000-0000-${number.toString().padStart(12, '0')}",
            g, session, author, sequence, logical, recipients, body), "AQ==")

    @Test
    fun textRecipientsReceiptsAndUsedFactSurviveReopenSeparateFromPoc() = withDatabase { path ->
        val message = message()
        openDesktopRepository(path).use {
            it.rename("preservato")
            it.save("old", "peer", "connection", "vecchio PoC", "sig")
            assertTrue(it.foundLocalGroup(anchor, a))
            assertTrue(it.saveGroupText(message, a))
            assertFalse(it.saveGroupText(message, a))
            assertTrue(it.groupSessionWasUsed(g, s))
            assertFalse(it.groupSessionWasUsed(g, a))
            assertEquals(setOf(a), assertNotNull(it.groupText(message.content.id)).receivedBy)
            assertTrue(it.acknowledgeGroupText(message, b))
            assertFalse(it.acknowledgeGroupText(message, b))
        }
        openDesktopRepository(path).use {
            val saved = assertNotNull(it.groupText(message.content.id))
            assertTrue(message.sameMessage(saved.message))
            assertEquals(setOf(a, b), saved.receivedBy)
            assertTrue(it.groupSessionWasUsed(g, s))
            assertEquals(message.content.id, it.groupTextHistory(g, s).single().message.content.id)
            assertTrue(it.groupTextHistory(g, a).isEmpty())
            assertEquals("vecchio PoC", it.history().single().text)
            assertFalse(it.history().single().received)
            assertTrue(it.trusted().isEmpty())
            assertEquals(anchor, it.localGroup())
            assertEquals("preservato", it.name())
        }
    }

    @Test
    fun conflictsAndUnknownReceiptsRollbackWithoutChangingOriginal() = withDatabase { path ->
        openDesktopRepository(path).use {
            it.foundLocalGroup(anchor, a)
            val original = message()
            it.saveGroupText(original, a)
            for (conflict in listOf(message(body = "alterato"), message(recipients = listOf(a)),
                message(session = a), message(number = 2, sequence = 1), SignedGroupText(original.content, "Ag=="))) {
                assertFails { it.saveGroupText(conflict, a) }
                assertFails { it.acknowledgeGroupText(conflict, b) }
            }
            assertFails { it.acknowledgeGroupText(original, g) }
            assertFails { it.acknowledgeGroupText(message(number = 3), b) }
            assertEquals(setOf(a), assertNotNull(it.groupText(original.content.id)).receivedBy)
            assertTrue(original.sameMessage(assertNotNull(it.groupText(original.content.id)).message))
            assertNull(it.groupText(message(number = 2).content.id))
            assertFalse(it.groupSessionWasUsed(g, a))
        }
    }

    @Test
    fun writeFaultsRollbackTextAllRecipientsAndUsedMarker() = withDatabase { path ->
        openDesktopRepository(path).use { it.foundLocalGroup(anchor, a) }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val store = SqliteDeviceRepository(driver)
            for (target in listOf("group_text_used_session", "group_text", "group_text_recipient", "group_text_clock")) {
                driver.execute(null, "CREATE TRIGGER fail_group_text AFTER INSERT ON $target BEGIN SELECT RAISE(FAIL, 'test fault'); END", 0)
                assertFails { store.saveGroupText(message(), a) }
                assertNull(store.groupText(message().content.id))
                assertFalse(store.groupSessionWasUsed(g, s))
                val count = driver.executeQuery(null, "SELECT COUNT(*) FROM group_text_recipient", { cursor ->
                    check(cursor.next().value); QueryResult.Value(cursor.getLong(0))
                }, 0).value
                assertEquals(0L, count)
                driver.execute(null, "DROP TRIGGER fail_group_text", 0)
            }
            assertTrue(store.saveGroupText(message(), a))
        }
    }

    @Test
    fun reservationsAreDurableAndFollowObservedLogicalTimesWithoutCounterReuse() = withDatabase { path ->
        openDesktopRepository(path).use {
            it.foundLocalGroup(anchor, a)
            val first = it.reserveGroupTextCounters(g, a)
            assertEquals(1L, first.authorSequence)
            assertEquals(1L, first.logicalTime)
            // Reserving without sending deliberately leaves a durable gap.
        }
        openDesktopRepository(path).use {
            it.saveGroupText(message(author = b, sequence = 50, logical = 100), a)
            val next = it.reserveGroupTextCounters(g, a)
            assertEquals(2L, next.authorSequence)
            assertEquals(101L, next.logicalTime)
            it.saveGroupText(message(number = 2, sequence = 20, logical = 200), a)
            val afterImport = it.reserveGroupTextCounters(g, a)
            assertEquals(21L, afterImport.authorSequence)
            assertEquals(201L, afterImport.logicalTime)
            // A different session does not reset the author's sequence.
            it.saveGroupText(message(number = 3, sequence = afterImport.authorSequence, logical = afterImport.logicalTime, session = a), a)
            assertEquals(22L, it.reserveGroupTextCounters(g, a).authorSequence)
        }
    }

    @Test
    fun independentConnectionsReserveDistinctCountersAndDeduplicateAtomically() = withDatabase { path ->
        openDesktopRepository(path).use { it.foundLocalGroup(anchor, a) }
        openDesktopRepository(path).use { left -> openDesktopRepository(path).use { right ->
            val start = CountDownLatch(1)
            val workers = Executors.newFixedThreadPool(2)
            try {
                val results = listOf(left, right).map { store -> workers.submit<Long> {
                    check(start.await(5, TimeUnit.SECONDS))
                    store.reserveGroupTextCounters(g, a).authorSequence
                } }
                start.countDown()
                assertEquals(setOf(1L, 2L), results.map { it.get(10, TimeUnit.SECONDS) }.toSet())
                val writes = listOf(left, right).map { store -> workers.submit<Boolean> { store.saveGroupText(message(), a) } }
                assertEquals(1, writes.map { it.get(10, TimeUnit.SECONDS) }.count { it })
            } finally { workers.shutdownNow() }
        } }
    }

    @Test
    fun historyHasStableLogicalOrderAndCounterOverflowFailsClosed() = withDatabase { path ->
        openDesktopRepository(path).use {
            it.foundLocalGroup(anchor, a)
            for (m in listOf(message(3, b, logical = 10), message(2, a, logical = 10), message(1, a, logical = 9))) it.saveGroupText(m, a)
            assertEquals(listOf(1L, 2L, 3L), it.groupTextHistory(g, s).map { row -> row.message.content.authorSequence })
            assertEquals(listOf(2L, 3L), it.groupTextHistory(g, s, 2).map { row -> row.message.content.authorSequence })
            assertFails { it.groupTextHistory(g, s, 0) }
            it.saveGroupText(message(4, b, logical = Long.MAX_VALUE), a)
            assertFails { it.reserveGroupTextCounters(g, a) }
        }
    }

    @Test
    fun removingHistoryCannotResetUsedOrAuthorAndLogicalClocks() = withDatabase { path ->
        openDesktopRepository(path).use {
            it.foundLocalGroup(anchor, a)
            it.saveGroupText(message(sequence = 10, logical = 500), a)
        }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            // Emulate only the data deletion part of future local retention, not a product cleanup API.
            driver.execute(null, "DELETE FROM group_text_recipient", 0)
            driver.execute(null, "DELETE FROM group_text", 0)
        }
        openDesktopRepository(path).use {
            assertTrue(it.groupTextHistory(g, s).isEmpty())
            assertTrue(it.groupSessionWasUsed(g, s))
            val next = it.reserveGroupTextCounters(g, a)
            assertEquals(11L, next.authorSequence)
            assertEquals(501L, next.logicalTime)
        }
    }

    @Test
    fun schemaFourMigratesAdditivelyAndFailedMigrationKeepsVersionAndData() = withDatabase { path ->
        openDesktopRepository(path).use {
            it.foundLocalGroup(anchor, a)
            it.rename("schema quattro")
            it.save("old", "peer", "s", "storico", "sig")
            it.acknowledge("old")
            it.trust("peer", "pin")
        }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            for (table in listOf("group_text", "group_text_recipient", "group_text_clock", "group_text_used_session")) driver.execute(null, "DROP TABLE $table", 0)
            driver.execute(null, "PRAGMA user_version=4", 0)
        }
        openDesktopRepository(path).use {
            assertEquals("schema quattro", it.name())
            assertEquals(anchor, it.localGroup())
            assertEquals(setOf("peer"), it.trusted())
            assertTrue(it.history().single().received)
            assertFalse(it.groupSessionWasUsed(g, s))
            assertTrue(it.saveGroupText(message(), a))
        }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { it.execute(null, "PRAGMA user_version=4", 0) }
        assertFails { openDesktopRepository(path).close() }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val version = driver.executeQuery(null, "PRAGMA user_version", { cursor ->
                check(cursor.next().value); QueryResult.Value(cursor.getLong(0))
            }, 0).value
            assertEquals(4L, version)
            assertEquals("schema quattro", SqliteDeviceRepository(driver).name())
        }
    }

    @Test
    fun noLocalGroupOrWrongRecipientCannotWriteAnything() = withDatabase { path ->
        openDesktopRepository(path).use {
            assertFails { it.saveGroupText(message(), a) }
            assertFails { it.reserveGroupTextCounters(g, a) }
            assertFalse(it.groupSessionWasUsed(g, s))
            it.foundLocalGroup(anchor, a)
            assertFails { it.saveGroupText(message(recipients = listOf(a)), b) }
            assertFails { it.saveGroupText(message(), b) }
            assertFails { it.reserveGroupTextCounters(b, a) }
            assertFails { it.reserveGroupTextCounters(g, b) }
            assertNull(it.groupText(message().content.id))
        }
    }

    @Test
    fun onlyCommittedAdoptedIdentityCanStoreAndReserveNotTheFounderOrPendingRecord() = withDatabase { path ->
        // Repository fixture, not a cryptographic admission: proof verification belongs to the live owner.
        val record = PendingGroupAdoption("e".repeat(64), b, a, anchor, byteArrayOf(1))
        openDesktopRepository(path).use {
            it.stageGroupAdoption(record, b)
            assertFails { it.saveGroupText(message(), b) }
            assertFails { it.reserveGroupTextCounters(g, b) }
            it.commitGroupAdoption(record, b)
            assertFails { it.saveGroupText(message(), a) }
            assertFails { it.reserveGroupTextCounters(g, a) }
            assertTrue(it.saveGroupText(message(), b))
            assertEquals(1L, it.reserveGroupTextCounters(g, b).authorSequence)
            assertTrue(record.sameRecord(assertNotNull(it.committedGroupAdoption())))
            assertNull(it.pendingGroupAdoption())
        }
    }

    private fun withDatabase(block: (Path) -> Unit) {
        val directory = Files.createTempDirectory("lantern-group-text-")
        try { block(directory.resolve("lantern.db")) }
        finally { Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }
}
