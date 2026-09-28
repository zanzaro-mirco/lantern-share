package lantern.persistence

import app.cash.sqldelight.driver.native.NativeSqliteDriver
import lantern.domain.ChatLine
import lantern.domain.DeviceRepository
import platform.Foundation.NSLock

/** Owns the native SQLDelight driver. Call [close] after all consumers stop. */
class IosDeviceRepository internal constructor(
    private val driver: NativeSqliteDriver,
) : DeviceRepository {
    private val lock = NSLock()
    private val store = SqliteDeviceStore(driver)

    private inline fun <T> locked(operation: () -> T): T {
        lock.lock()
        return try {
            operation()
        } finally {
            lock.unlock()
        }
    }

    override fun trusted(): Set<String> = locked(store::trusted)
    override fun trust(id: String, admission: String) { locked { store.trust(id, admission) } }
    override fun block(id: String) { locked { store.block(id) } }
    override fun name(): String = locked(store::name)
    override fun rename(name: String) { locked { store.rename(name) } }
    override fun save(id: String, sender: String, session: String, body: String, signature: String): Boolean =
        locked { store.save(id, sender, session, body, signature) }
    override fun history(): List<ChatLine> = locked(store::history)
    override fun acknowledge(id: String) { locked { store.acknowledge(id) } }

    fun close() = locked(driver::close)
}

fun openIosRepository(databaseDirectory: String): IosDeviceRepository {
    require(databaseDirectory.isNotBlank()) { "Cartella database iOS vuota" }
    val driver = NativeSqliteDriver(
        schema = LanternDatabase.Schema,
        name = "lantern.db",
        onConfiguration = { configuration ->
            configuration.copy(
                extendedConfig = configuration.extendedConfig.copy(basePath = databaseDirectory),
            )
        },
    )
    return IosDeviceRepository(driver)
}
