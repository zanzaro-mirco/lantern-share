package lantern.persistence

import app.cash.sqldelight.db.SqlDriver
import lantern.domain.ChatLine
import lantern.domain.DeviceRepository

/** Owns an initialized driver. Close after all repository consumers stop. */
class SqliteDeviceRepository(private val driver: SqlDriver) : DeviceRepository, AutoCloseable {
    private val database = LanternDatabase(driver)
    private val queries = database.storeQueries

    @Synchronized
    override fun trusted(): Set<String> = queries.peers().executeAsList().map { it.id }.toSet()

    @Synchronized
    override fun trust(id: String, admission: String) { queries.trust(id, admission) }

    @Synchronized
    override fun block(id: String) { queries.untrust(id) }

    @Synchronized
    override fun name(): String = queries.getSetting("name").executeAsOneOrNull() ?: "Dispositivo Lantern"

    @Synchronized
    override fun rename(name: String) { queries.putSetting("name", name) }

    @Synchronized
    override fun save(id: String, sender: String, session: String, body: String, signature: String): Boolean =
        database.transactionWithResult {
            val existing = queries.getMessage(id).executeAsOneOrNull()
            if (existing == null) {
                queries.insertMessage(id, sender, session, body, signature)
                true
            } else {
                require(
                    existing.sender == sender && existing.session == session &&
                        existing.body == body && existing.signature == signature
                ) { "ID messaggio in conflitto" }
                false
            }
        }

    @Synchronized
    override fun history(): List<ChatLine> = queries.history().executeAsList().reversed().map {
        ChatLine(id = it.id, sender = it.sender, text = it.body, received = it.received == 1L)
    }

    @Synchronized
    override fun acknowledge(id: String) { queries.ack(id) }

    @Synchronized
    override fun close() = driver.close()
}
