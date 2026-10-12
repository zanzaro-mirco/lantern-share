package lantern.persistence

import app.cash.sqldelight.driver.native.NativeSqliteDriver
import co.touchlab.sqliter.interop.Logger

/**
 * SQLiter's default logger sends messages to stdout and stack traces to stderr.
 * Gradle 8.9's Native output collector can corrupt its index when both streams
 * deliver events concurrently. Keep the full diagnostics on the test stdout
 * stream instead; do not change production logging or swallow SQL exceptions.
 */
internal class NativeTestSqliteLogger(
    private val write: (String) -> Unit = { println(it) },
) : Logger {
    override val vActive: Boolean = false
    override val eActive: Boolean = true

    override fun trace(message: String) = write(message)
    override fun vWrite(message: String) = write(message)

    override fun eWrite(message: String, exception: Throwable?) {
        write(message)
        if (exception != null) write(exception.stackTraceToString())
    }
}

/** Only fault-injection connections use this logger; reopen uses the real app opener. */
internal fun openFaultInjectionDriver(directory: String): NativeSqliteDriver = NativeSqliteDriver(
    schema = LanternDatabase.Schema,
    name = "lantern.db",
    onConfiguration = { configuration ->
        configuration.copy(
            extendedConfig = configuration.extendedConfig.copy(basePath = directory),
            loggingConfig = configuration.loggingConfig.copy(logger = NativeTestSqliteLogger()),
        )
    },
)
