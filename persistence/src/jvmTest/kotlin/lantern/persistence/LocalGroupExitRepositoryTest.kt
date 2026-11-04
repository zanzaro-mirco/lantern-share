package lantern.persistence

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import lantern.domain.GroupTrustAnchor
import lantern.domain.GroupTextContent
import lantern.domain.PendingGroupAdoption
import lantern.domain.SignedGroupText
import java.nio.file.Files
import java.nio.file.Path
import java.sql.DriverManager
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.test.*

class LocalGroupExitRepositoryTest {
    private val local = "a".repeat(64)
    private val peer = "b".repeat(64)
    private val anchor = GroupTrustAnchor("c".repeat(64), local)
    private val pending = PendingGroupAdoption("d".repeat(64), local, peer, anchor, byteArrayOf(1, 2, 3))

    @Test
    fun competingConnectionCannotMakeStaleExitDeleteTheReplacementRoot() = database { path ->
        val replacement = GroupTrustAnchor("f".repeat(64), local)
        openDesktopRepository(path).use { repository ->
            assertTrue(repository.foundLocalGroup(anchor, local))
            DriverManager.getConnection("jdbc:sqlite:$path").use { writer ->
                writer.autoCommit = false
                writer.prepareStatement("UPDATE local_group SET group_id = ? WHERE singleton = 1").use {
                    it.setString(1, replacement.groupId)
                    assertEquals(1, it.executeUpdate())
                }
                val started = CountDownLatch(1)
                val worker = Executors.newSingleThreadExecutor()
                try {
                    val staleExit = worker.submit<Boolean> {
                        started.countDown()
                        repository.leaveLocalGroup(anchor, local)
                    }
                    assertTrue(started.await(5, TimeUnit.SECONDS))
                    assertFailsWith<TimeoutException> { staleExit.get(150, TimeUnit.MILLISECONDS) }
                    writer.commit()
                    assertFalse(staleExit.get(5, TimeUnit.SECONDS))
                    assertEquals(replacement, repository.localGroup())
                } finally {
                    try { writer.rollback() } finally {
                        worker.shutdownNow()
                        check(worker.awaitTermination(5, TimeUnit.SECONDS))
                    }
                }
            }
        }
        openDesktopRepository(path).use { assertEquals(replacement, it.localGroup()) }
    }

    @Test
    fun foundationExitPreservesTextReceiptsCountersAndOtherLocalDataAcrossReopen() = database { path ->
        val message = SignedGroupText(GroupTextContent("00000000-0000-0000-0000-000000000001",
            anchor.groupId, "e".repeat(64), local, 1, 1, listOf(local, peer), "Preservato"), "AQ==")
        openDesktopRepository(path).use {
            it.rename("Nome preservato")
            it.trust(peer, "PoC separato")
            it.foundLocalGroup(anchor, local)
            it.reserveGroupTextCounters(anchor.groupId, local)
            it.saveGroupText(message, local)
            it.acknowledgeGroupText(message, peer)
            assertTrue(it.leaveLocalGroup(anchor, local))
            assertFalse(it.leaveLocalGroup(anchor, local))
        }
        openDesktopRepository(path).use {
            assertNull(it.localGroup())
            assertNull(it.committedGroupAdoption())
            assertNull(it.pendingGroupAdoption())
            assertEquals("Nome preservato", it.name())
            assertEquals(setOf(peer), it.trusted())
            val stored = assertNotNull(it.groupText(message.content.id))
            assertTrue(message.sameMessage(stored.message))
            assertEquals(setOf(local, peer), stored.receivedBy)
            assertTrue(it.groupSessionWasUsed(anchor.groupId, message.content.sessionId))
            assertFails { it.reserveGroupTextCounters(anchor.groupId, local) }
            assertTrue(it.foundLocalGroup(anchor, local))
            assertEquals(2L, it.reserveGroupTextCounters(anchor.groupId, local).authorSequence)
            assertTrue(it.leaveLocalGroup(anchor, local))
            // Exit permits a new explicit foundation; it never creates one itself.
            assertTrue(it.foundLocalGroup(GroupTrustAnchor("f".repeat(64), local), local))
            assertFalse(it.leaveLocalGroup(anchor, local))
            assertNotNull(it.localGroup())
        }
    }

    @Test
    fun adoptedMemberExitRequiresCurrentIdentityAndExpectedRoot() = database { path ->
        val adopted = PendingGroupAdoption(pending.attemptId, local, peer, GroupTrustAnchor(anchor.groupId, peer), pending.payload())
        openDesktopRepository(path).use {
            it.stageGroupAdoption(adopted, local)
            it.commitGroupAdoption(adopted, local)
            assertFalse(it.leaveLocalGroup(adopted.anchor, peer))
            assertFalse(it.leaveLocalGroup(anchor, local))
            assertEquals(adopted.anchor, it.localGroup())
            assertTrue(it.leaveLocalGroup(adopted.anchor, local))
            assertNull(it.committedGroupAdoption())
            assertNull(it.localGroup())
            assertFails { it.commitGroupAdoption(adopted, local) }
        }
        openDesktopRepository(path).use { assertNull(it.localGroup()) }
    }

    @Test
    fun journalDeleteFailureRollsBackMembershipAndJournalTogether() = database { path ->
        openDesktopRepository(path).use {
            it.stageGroupAdoption(pending, local)
            it.foundLocalGroup(anchor, local)
            assertFalse(it.leaveLocalGroup(anchor, peer))
        }
        JdbcSqliteDriver("jdbc:sqlite:$path").use { driver ->
            val store = SqliteDeviceRepository(driver)
            driver.execute(null, "CREATE TRIGGER fail_exit AFTER DELETE ON group_adoption_journal BEGIN SELECT RAISE(FAIL, 'exit failure'); END", 0)
            assertFails { store.leaveLocalGroup(anchor, local) }
            assertEquals(anchor, store.localGroup())
            assertTrue(pending.sameRecord(assertNotNull(store.pendingGroupAdoption())))
            driver.execute(null, "DROP TRIGGER fail_exit", 0)
            assertTrue(store.leaveLocalGroup(anchor, local))
            assertNull(store.localGroup())
            assertNull(store.pendingGroupAdoption())
            assertFails { store.commitGroupAdoption(pending, local) }
        }
    }

    @Test
    fun unrelatedJournalIsPreservedAndRollsBackExit() = database { path ->
        val unrelated = PendingGroupAdoption(pending.attemptId, local, peer,
            GroupTrustAnchor("f".repeat(64), peer), pending.payload())
        openDesktopRepository(path).use {
            it.stageGroupAdoption(unrelated, local)
            it.foundLocalGroup(anchor, local)
            assertFails { it.leaveLocalGroup(anchor, local) }
            assertEquals(anchor, it.localGroup())
            assertTrue(unrelated.sameRecord(assertNotNull(it.pendingGroupAdoption())))
        }
    }

    private fun database(test: (Path) -> Unit) {
        val directory = Files.createTempDirectory("lantern-exit-store-")
        try { test(directory.resolve("test.db")) }
        finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
