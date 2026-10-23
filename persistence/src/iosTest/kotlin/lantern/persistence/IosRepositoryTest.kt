package lantern.persistence

import lantern.domain.GroupTrustAnchor
import app.cash.sqldelight.driver.native.NativeSqliteDriver
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertFails
import kotlin.test.assertNull
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID

@OptIn(ExperimentalForeignApi::class)
class IosRepositoryTest {
    @Test
    fun legacyDatabaseMigratesToFoundationWithoutLosingData() {
        val directory = NSTemporaryDirectory() + "lantern-migration-${NSUUID().UUIDString}"
        val files = NSFileManager.defaultManager
        assertTrue(files.createDirectoryAtPath(directory, true, null, null))
        val anchor = GroupTrustAnchor("b".repeat(64), "a".repeat(64))
        try {
            val initial = openIosRepository(directory)
            try {
                initial.rename("iPhone legacy")
                initial.trust("peer", "admission")
                initial.save("message", "peer", "session", "Caffè ☕", "signature")
                initial.acknowledge("message")
            } finally { initial.close() }
            // Test fixture: remove every additive table to recreate the version-1 schema.
            val legacy = NativeSqliteDriver(
                schema = LanternDatabase.Schema,
                name = "lantern.db",
                onConfiguration = { configuration ->
                    configuration.copy(extendedConfig = configuration.extendedConfig.copy(basePath = directory))
                },
            )
            try {
                legacy.execute(null, "DROP TABLE local_group", 0)
                legacy.execute(null, "DROP TABLE group_adoption_journal", 0)
                legacy.execute(null, "DROP TABLE group_adoption", 0)
                for (table in listOf("group_text", "group_text_recipient", "group_text_clock", "group_text_used_session")) {
                    legacy.execute(null, "DROP TABLE $table", 0)
                }
                legacy.execute(null, "PRAGMA user_version=1", 0)
            } finally { legacy.close() }
            val migrated = openIosRepository(directory)
            try {
                assertEquals("iPhone legacy", migrated.name())
                assertEquals(setOf("peer"), migrated.trusted())
                assertEquals("Caffè ☕", migrated.history().single().text)
                assertTrue(migrated.history().single().received)
                assertNull(migrated.localGroup())
                assertTrue(migrated.foundLocalGroup(anchor, anchor.founderId))
            } finally { migrated.close() }
            val reopened = openIosRepository(directory)
            try { assertEquals(anchor, reopened.localGroup()) } finally { reopened.close() }
        } finally { files.removeItemAtPath(directory, error = null) }
    }

    @Test
    fun failedFoundationWriteLeavesNativeDatabaseEmpty() {
        val directory = NSTemporaryDirectory() + "lantern-foundation-failure-${NSUUID().UUIDString}"
        val files = NSFileManager.defaultManager
        assertTrue(files.createDirectoryAtPath(directory, true, null, null))
        val anchor = GroupTrustAnchor("b".repeat(64), "a".repeat(64))
        try {
            val driver = openFaultInjectionDriver(directory)
            val repository = IosDeviceRepository(driver)
            try {
                repository.rename("preservato")
                repository.trust("peer", "existing admission")
                for ((timing, action) in listOf("BEFORE" to "ABORT", "AFTER" to "FAIL")) {
                    driver.execute(null, "CREATE TRIGGER reject_foundation $timing INSERT ON local_group BEGIN SELECT RAISE($action, 'test write failure'); END", 0)
                    assertFails { repository.foundLocalGroup(anchor, anchor.founderId) }
                    assertNull(repository.localGroup())
                    assertEquals("preservato", repository.name())
                    assertEquals(setOf("peer"), repository.trusted())
                    driver.execute(null, "DROP TRIGGER reject_foundation", 0)
                }
                assertTrue(repository.foundLocalGroup(anchor, anchor.founderId))
            } finally { repository.close() }
            val reopened = openIosRepository(directory)
            try { assertEquals(anchor, reopened.localGroup()) } finally { reopened.close() }
        } finally { files.removeItemAtPath(directory, error = null) }
    }

    @Test
    fun readOnlyConnectionRejectsFoundationWithoutLosingExistingData() {
        val directory = NSTemporaryDirectory() + "lantern-foundation-readonly-${NSUUID().UUIDString}"
        val files = NSFileManager.defaultManager
        assertTrue(files.createDirectoryAtPath(directory, true, null, null))
        val anchor = GroupTrustAnchor("b".repeat(64), "a".repeat(64))
        try {
            val driver = openFaultInjectionDriver(directory)
            val repository = IosDeviceRepository(driver)
            try {
                repository.rename("preservato")
                assertFails {
                    // The pragma is connection-local; configure the actual write transaction.
                    LanternDatabase(driver).transaction {
                        driver.execute(null, "PRAGMA query_only=ON", 0)
                        repository.foundLocalGroup(anchor, anchor.founderId)
                    }
                }
                assertNull(repository.localGroup())
                assertEquals("preservato", repository.name())
            } finally { repository.close() }
            val reopened = openIosRepository(directory)
            try {
                assertNull(reopened.localGroup())
                assertEquals("preservato", reopened.name())
                assertTrue(reopened.foundLocalGroup(anchor, anchor.founderId))
            } finally { reopened.close() }
        } finally { files.removeItemAtPath(directory, error = null) }
    }

    @Test
    fun localFoundationSurvivesReopenWithoutReplacingOrAuthorizingPeers() {
        val directory = NSTemporaryDirectory() + "lantern-foundation-${NSUUID().UUIDString}"
        val files = NSFileManager.defaultManager
        assertTrue(files.createDirectoryAtPath(directory, true, null, null))
        val founder = "a".repeat(64)
        val anchor = GroupTrustAnchor("b".repeat(64), founder)
        try {
            val first = openIosRepository(directory)
            try {
                assertNull(first.localGroup())
                assertFails { first.foundLocalGroup(anchor, "c".repeat(64)) }
                assertNull(first.localGroup())
                first.rename("iPhone fondatore")
                assertTrue(first.foundLocalGroup(anchor, founder))
                assertTrue(first.trusted().isEmpty())
            } finally { first.close() }
            val reopened = openIosRepository(directory)
            try {
                assertEquals(anchor, reopened.localGroup())
                assertEquals("iPhone fondatore", reopened.name())
                assertFalse(reopened.foundLocalGroup(anchor, founder))
                assertFalse(reopened.foundLocalGroup(GroupTrustAnchor("c".repeat(64), founder), founder))
                assertEquals(anchor, reopened.localGroup())
                assertTrue(reopened.trusted().isEmpty())
            } finally { reopened.close() }
        } finally { files.removeItemAtPath(directory, error = null) }
    }

    @Test
    fun messagesAndReceiptSurviveReopenWithoutDuplicatesOrConflicts() {
        val directory = NSTemporaryDirectory() + "lantern-messages-${NSUUID().UUIDString}"
        val files = NSFileManager.defaultManager
        assertTrue(files.createDirectoryAtPath(directory, true, null, null))
        val id = "00000000-0000-0000-0000-000000000001"
        val sender = "a".repeat(64)
        val session = "b".repeat(64)
        try {
            val first = IosDeviceRepository(openFaultInjectionDriver(directory))
            try {
                assertTrue(first.save(id, sender, session, "Caffè ☕", "signature"))
                assertFalse(first.save(id, sender, session, "Caffè ☕", "signature"))
                assertFails { first.save(id, sender, session, "alterato", "signature") }
                assertEquals(1, first.history().size)
                assertFalse(first.history().single().received)
                first.acknowledge(id)
            } finally { first.close() }
            val reopened = openIosRepository(directory)
            try {
                val line = reopened.history().single()
                assertEquals(id, line.id)
                assertEquals("Caffè ☕", line.text)
                assertTrue(line.received)
                assertFalse(reopened.save(id, sender, session, "Caffè ☕", "signature"))
            } finally { reopened.close() }
        } finally { files.removeItemAtPath(directory, error = null) }
    }

    @Test
    fun deviceNameSurvivesDatabaseReopen() {
        val directory = NSTemporaryDirectory() + "lantern-persistence-${NSUUID().UUIDString}"
        val files = NSFileManager.defaultManager
        assertTrue(
            files.createDirectoryAtPath(
                path = directory,
                withIntermediateDirectories = true,
                attributes = null,
                error = null,
            ),
        )
        try {
            openIosRepository(directory).let { first ->
                try {
                    assertEquals("Dispositivo Lantern", first.name())
                    first.rename("iPhone di prova")
                } finally {
                    first.close()
                }
            }

            openIosRepository(directory).let { reopened ->
                try {
                    assertEquals("iPhone di prova", reopened.name())
                } finally {
                    reopened.close()
                }
            }
        } finally {
            files.removeItemAtPath(directory, error = null)
        }
    }
}
