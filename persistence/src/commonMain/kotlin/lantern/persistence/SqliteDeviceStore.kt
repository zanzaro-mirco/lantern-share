package lantern.persistence

import app.cash.sqldelight.db.SqlDriver
import lantern.domain.ChatLine

/** Shared SQLDelight operations. Platform repositories provide their own synchronization and lifecycle. */
internal class SqliteDeviceStore(driver: SqlDriver) {
    private val database = LanternDatabase(driver)
    private val queries = database.storeQueries

    fun trusted(): Set<String> = queries.peers().executeAsList().map { it.id }.toSet()

    fun trust(id: String, admission: String) {
        queries.trust(id, admission)
    }

    fun block(id: String) {
        queries.untrust(id)
    }

    fun name(): String = queries.getSetting("name").executeAsOneOrNull() ?: "Dispositivo Lantern"

    fun rename(name: String) {
        queries.putSetting("name", name)
    }

    fun save(id: String, sender: String, session: String, body: String, signature: String): Boolean =
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

    fun history(): List<ChatLine> = queries.history().executeAsList().reversed().map {
        ChatLine(id = it.id, sender = it.sender, text = it.body, received = it.received == 1L)
    }

    fun acknowledge(id: String) {
        queries.ack(id)
    }
}
