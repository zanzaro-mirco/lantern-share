package lantern.persistence

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import java.nio.file.Path

fun openDesktopRepository(path: Path): SqliteDeviceRepository {
    val driver = JdbcSqliteDriver("jdbc:sqlite:${path.toAbsolutePath()}")
    try {
        driver.execute(null, "PRAGMA busy_timeout=5000", 0)
        driver.execute(null, "PRAGMA journal_mode=WAL", 0)
        val version = driver.executeQuery(
            null,
            "PRAGMA user_version",
            { cursor ->
                check(cursor.next().value)
                QueryResult.Value(checkNotNull(cursor.getLong(0)))
            },
            0,
        ).value
        require(version in 0..LanternDatabase.Schema.version) { "Versione database non supportata" }
        if (version == 0L) {
            LanternDatabase(driver).transaction {
                LanternDatabase.Schema.create(driver)
                driver.execute(null, "PRAGMA user_version=${LanternDatabase.Schema.version}", 0)
            }
        }
        return SqliteDeviceRepository(driver)
    } catch (error: Exception) {
        driver.close()
        throw error
    }
}
