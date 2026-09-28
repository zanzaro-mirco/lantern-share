package lantern.persistence

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID

class IosRepositoryTest {
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
