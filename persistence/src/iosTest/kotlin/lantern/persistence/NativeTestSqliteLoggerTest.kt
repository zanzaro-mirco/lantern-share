package lantern.persistence

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeTestSqliteLoggerTest {
    @Test
    fun errorAndCompleteCauseStackUseTheSameSink() {
        val output = mutableListOf<String>()
        val logger = NativeTestSqliteLogger(output::add)
        val cause = IllegalStateException("original SQL failure")
        val error = IllegalArgumentException("transaction failure", cause)

        logger.eWrite("SQLITE_CONSTRAINT", error)

        assertTrue(logger.eActive)
        assertFalse(logger.vActive)
        assertEquals(listOf("SQLITE_CONSTRAINT", error.stackTraceToString()), output)
        assertTrue(output.last().contains("original SQL failure"))
    }

    @Test
    fun messagesWithoutExceptionAndOtherLevelsAreNotDiscarded() {
        val output = mutableListOf<String>()
        val logger = NativeTestSqliteLogger(output::add)

        logger.eWrite("SQLITE_READONLY", null)
        logger.trace("trace")
        logger.vWrite("verbose")

        assertEquals(listOf("SQLITE_READONLY", "trace", "verbose"), output)
    }
}
