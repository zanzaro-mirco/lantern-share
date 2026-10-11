package lantern.persistence

import app.cash.sqldelight.db.SqlDriver
import lantern.domain.DeviceRepository
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository

/** Owns an initialized driver. Close after all repository consumers stop. */
class SqliteDeviceRepository(private val driver: SqlDriver) : DeviceRepository, LocalGroupRepository, AutoCloseable {
    private val store = SqliteDeviceStore(driver)

    @Synchronized
    override fun trusted(): Set<String> = store.trusted()

    @Synchronized
    override fun trust(id: String, admission: String) { store.trust(id, admission) }

    @Synchronized
    override fun block(id: String) { store.block(id) }

    @Synchronized
    override fun name(): String = store.name()

    @Synchronized
    override fun rename(name: String) { store.rename(name) }

    @Synchronized
    override fun localGroup(): GroupTrustAnchor? = store.localGroup()

    @Synchronized
    override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean =
        store.foundLocalGroup(anchor, currentIdentityId)

    @Synchronized
    override fun save(id: String, sender: String, session: String, body: String, signature: String): Boolean =
        store.save(id, sender, session, body, signature)

    @Synchronized
    override fun history() = store.history()

    @Synchronized
    override fun acknowledge(id: String) { store.acknowledge(id) }

    @Synchronized
    override fun close() = driver.close()
}
