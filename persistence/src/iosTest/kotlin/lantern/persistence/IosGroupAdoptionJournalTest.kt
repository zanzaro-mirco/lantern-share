package lantern.persistence

import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@OptIn(ExperimentalForeignApi::class)
class IosGroupAdoptionJournalTest {
    private val local = "a".repeat(64)
    private val peer = "b".repeat(64)
    private val record = PendingGroupAdoption("d".repeat(64), local, peer,
        GroupTrustAnchor("c".repeat(64), peer), byteArrayOf(0, 1, -1, 3))

    @Test
    fun stagedPayloadSurvivesNativeReopenWithoutMembershipOrTrust() = withDirectory { directory ->
        val initial = openIosRepository(directory)
        try {
            assertNull(initial.pendingGroupAdoption())
            assertTrue(initial.stageGroupAdoption(record, local))
            assertFalse(initial.stageGroupAdoption(record, local))
        } finally { initial.close() }
        val reopened = openIosRepository(directory)
        try {
            assertTrue(record.sameRecord(assertNotNull(reopened.pendingGroupAdoption())))
            val changed = PendingGroupAdoption(record.attemptId, local, peer, record.anchor, byteArrayOf(4))
            assertFails { reopened.stageGroupAdoption(changed, local) }
            assertFalse(reopened.removeGroupAdoption(changed))
            assertNull(reopened.localGroup())
            assertTrue(reopened.trusted().isEmpty())
            assertTrue(reopened.history().isEmpty())
            assertTrue(reopened.removeGroupAdoption(record))
            assertNull(reopened.pendingGroupAdoption())
        } finally { reopened.close() }
    }

    @Test
    fun nativeSchemaTwoMigrationPreservesNameGroupAndHistory() = withDirectory { directory ->
        val foundation = GroupTrustAnchor("e".repeat(64), local)
        val original = openIosRepository(directory)
        try {
            original.rename("iPhone preservato")
            original.trust("peer", "admission")
            original.save("m", "peer", "session", "Caffè ☕", "signature")
            original.acknowledge("m")
            assertTrue(original.foundLocalGroup(foundation, local))
        } finally { original.close() }
        val legacy = openFaultInjectionDriver(directory)
        try {
            legacy.execute(null, "DROP TABLE group_adoption_journal", 0)
            legacy.execute(null, "PRAGMA user_version=2", 0)
        } finally { legacy.close() }
        val migrated = openIosRepository(directory)
        try {
            assertEquals("iPhone preservato", migrated.name())
            assertEquals(foundation, migrated.localGroup())
            assertEquals(setOf("peer"), migrated.trusted())
            assertEquals("Caffè ☕", migrated.history().single().text)
            assertTrue(migrated.history().single().received)
            assertNull(migrated.pendingGroupAdoption())
            assertFails { migrated.stageGroupAdoption(record, local) }
        } finally { migrated.close() }
    }

    @Test
    fun nativeWriteFaultsRollbackAndDoNotEraseThePendingRecord() = withDirectory { directory ->
        val driver = openFaultInjectionDriver(directory)
        val repository = IosDeviceRepository(driver)
        try {
            assertFails { repository.stageGroupAdoption(record, peer) }
            for ((timing, action) in listOf("BEFORE" to "ABORT", "AFTER" to "FAIL")) {
                driver.execute(null, "CREATE TRIGGER reject_journal $timing INSERT ON group_adoption_journal BEGIN SELECT RAISE($action, 'test write failure'); END", 0)
                assertFails { repository.stageGroupAdoption(record, local) }
                assertNull(repository.pendingGroupAdoption())
                driver.execute(null, "DROP TRIGGER reject_journal", 0)
            }
            assertTrue(repository.stageGroupAdoption(record, local))
            driver.execute(null, "CREATE TRIGGER reject_delete AFTER DELETE ON group_adoption_journal BEGIN SELECT RAISE(FAIL, 'test delete failure'); END", 0)
            assertFails { repository.removeGroupAdoption(record) }
            assertTrue(record.sameRecord(assertNotNull(repository.pendingGroupAdoption())))
            assertNull(repository.localGroup())
        } finally { repository.close() }
        val reopened = openIosRepository(directory)
        try { assertTrue(record.sameRecord(assertNotNull(reopened.pendingGroupAdoption()))) }
        finally { reopened.close() }
    }

    private fun withDirectory(block: (String) -> Unit) {
        val directory = NSTemporaryDirectory() + "lantern-journal-${NSUUID().UUIDString}"
        val files = NSFileManager.defaultManager
        assertTrue(files.createDirectoryAtPath(directory, true, null, null))
        try { block(directory) } finally { files.removeItemAtPath(directory, error = null) }
    }
}
