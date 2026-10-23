package lantern.persistence

import app.cash.sqldelight.driver.native.NativeSqliteDriver
import lantern.domain.ChatLine
import lantern.domain.DeviceRepository
import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption
import lantern.domain.GroupAdoptionRepository
import lantern.domain.GroupTextRepository
import lantern.domain.SignedGroupText
import platform.Foundation.NSLock

/** Owns the native SQLDelight driver. Call [close] after all consumers stop. */
class IosDeviceRepository internal constructor(
    private val driver: NativeSqliteDriver,
) : DeviceRepository, GroupAdoptionRepository, GroupTextRepository {
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
    override fun localGroup(): GroupTrustAnchor? = locked(store::localGroup)
    override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean =
        locked { store.foundLocalGroup(anchor, currentIdentityId) }
    override fun pendingGroupAdoption(): PendingGroupAdoption? = locked(store::pendingGroupAdoption)
    override fun stageGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean =
        locked { store.stageGroupAdoption(record, currentIdentityId) }
    override fun removeGroupAdoption(record: PendingGroupAdoption): Boolean = locked { store.removeGroupAdoption(record) }
    override fun committedGroupAdoption(): PendingGroupAdoption? = locked(store::committedGroupAdoption)
    override fun commitGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean =
        locked { store.commitGroupAdoption(record, currentIdentityId) }
    override fun save(id: String, sender: String, session: String, body: String, signature: String): Boolean =
        locked { store.save(id, sender, session, body, signature) }
    override fun history(): List<ChatLine> = locked(store::history)
    override fun acknowledge(id: String) { locked { store.acknowledge(id) } }
    override fun reserveGroupTextCounters(groupId: String, localIdentity: String) = locked { store.reserveGroupTextCounters(groupId, localIdentity) }
    override fun saveGroupText(message: SignedGroupText, localIdentity: String) = locked { store.saveGroupText(message, localIdentity) }
    override fun groupText(id: String) = locked { store.groupText(id) }
    override fun groupTextHistory(groupId: String, sessionId: String, limit: Int) = locked { store.groupTextHistory(groupId, sessionId, limit) }
    override fun acknowledgeGroupText(message: SignedGroupText, recipientId: String) = locked { store.acknowledgeGroupText(message, recipientId) }
    override fun groupSessionWasUsed(groupId: String, sessionId: String) = locked { store.groupSessionWasUsed(groupId, sessionId) }

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
