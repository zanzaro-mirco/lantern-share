package lantern.persistence

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertFails
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID

@OptIn(ExperimentalForeignApi::class)
class IosRepositoryTest {
    @Test
    fun messagesAndReceiptSurviveReopenWithoutDuplicatesOrConflicts() {
        val directory = NSTemporaryDirectory() + "lantern-messages-${NSUUID().UUIDString}"
        val files = NSFileManager.defaultManager
        assertTrue(files.createDirectoryAtPath(directory, true, null, null))
        val id = "00000000-0000-0000-0000-000000000001"
        val sender = "a".repeat(64)
        val session = "b".repeat(64)
        try {
            val first = openIosRepository(directory)
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
