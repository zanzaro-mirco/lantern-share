package lantern.persistence

import kotlinx.cinterop.ExperimentalForeignApi
import lantern.domain.GroupTextContent
import lantern.domain.GroupTrustAnchor
import lantern.domain.SignedGroupText
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
class IosGroupTextRepositoryTest {
    private val a = "a".repeat(64)
    private val b = "b".repeat(64)
    private val g = "c".repeat(64)
    private val s = "d".repeat(64)
    private val anchor = GroupTrustAnchor(g, a)
    private fun message() = SignedGroupText(GroupTextContent("00000000-0000-0000-0000-000000000001",
        g, s, a, 1, 1, listOf(a, b), "Caffè ☕"), "AQ==")

    @Test
    fun nativeTextReceiptsCountersAndUsedFactSurviveReopen() = withDirectory { directory ->
        val initial = openIosRepository(directory)
        try {
            initial.foundLocalGroup(anchor, a)
            assertEquals(1L, initial.reserveGroupTextCounters(g, a).authorSequence)
            assertTrue(initial.saveGroupText(message(), a))
            assertFalse(initial.saveGroupText(message(), a))
            assertTrue(initial.acknowledgeGroupText(message(), b))
            assertFalse(initial.acknowledgeGroupText(message(), b))
        } finally { initial.close() }
        val reopened = openIosRepository(directory)
        try {
            assertTrue(message().sameMessage(assertNotNull(reopened.groupText(message().content.id)).message))
            assertEquals(setOf(a, b), assertNotNull(reopened.groupText(message().content.id)).receivedBy)
            assertTrue(reopened.groupSessionWasUsed(g, s))
            assertEquals(2L, reopened.reserveGroupTextCounters(g, a).authorSequence)
            assertEquals(1, reopened.groupTextHistory(g, s).size)
            assertTrue(reopened.history().isEmpty())
            assertTrue(reopened.trusted().isEmpty())
        } finally { reopened.close() }
    }

    @Test
    fun nativeFaultRollsBackRecipientsTextAndUsedMarker() = withDirectory { directory ->
        val driver = openFaultInjectionDriver(directory)
        val store = IosDeviceRepository(driver)
        try {
            store.foundLocalGroup(anchor, a)
            driver.execute(null, "CREATE TRIGGER fail_text AFTER INSERT ON group_text_recipient BEGIN SELECT RAISE(FAIL, 'test fault'); END", 0)
            assertFails { store.saveGroupText(message(), a) }
            assertNull(store.groupText(message().content.id))
            assertFalse(store.groupSessionWasUsed(g, s))
            driver.execute(null, "DROP TRIGGER fail_text", 0)
            assertTrue(store.saveGroupText(message(), a))
            assertFails { store.acknowledgeGroupText(SignedGroupText(message().content, "Ag=="), b) }
            assertEquals(setOf(a), assertNotNull(store.groupText(message().content.id)).receivedBy)
        } finally { store.close() }
    }

    @Test
    fun nativeSchemaFourMigrationPreservesGroupAndPocWithoutRestoringSession() = withDirectory { directory ->
        val initial = openIosRepository(directory)
        try {
            initial.foundLocalGroup(anchor, a)
            initial.rename("schema quattro")
            initial.save("old", "peer", "s", "storico", "sig")
            initial.acknowledge("old")
        } finally { initial.close() }
        val legacy = openFaultInjectionDriver(directory)
        try {
            for (table in listOf("group_text", "group_text_recipient", "group_text_clock", "group_text_used_session")) {
                legacy.execute(null, "DROP TABLE $table", 0)
            }
            legacy.execute(null, "PRAGMA user_version=4", 0)
        } finally { legacy.close() }
        val migrated = openIosRepository(directory)
        try {
            assertEquals(anchor, migrated.localGroup())
            assertEquals("schema quattro", migrated.name())
            assertTrue(migrated.history().single().received)
            assertFalse(migrated.groupSessionWasUsed(g, s))
            assertTrue(migrated.saveGroupText(message(), a))
        } finally { migrated.close() }
    }

    private fun withDirectory(block: (String) -> Unit) {
        val directory = NSTemporaryDirectory() + "lantern-text-${NSUUID().UUIDString}"
        val files = NSFileManager.defaultManager
        assertTrue(files.createDirectoryAtPath(directory, true, null, null))
        try { block(directory) } finally { files.removeItemAtPath(directory, error = null) }
    }
}
