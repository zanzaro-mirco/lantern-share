package lantern.persistence

import app.cash.sqldelight.db.SqlDriver
import lantern.domain.DeviceRepository
import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption
import lantern.domain.GroupAdoptionRepository
import lantern.domain.GroupTextRepository
import lantern.domain.SignedGroupText

/** Owns an initialized driver. Close after all repository consumers stop. */
class SqliteDeviceRepository(private val driver: SqlDriver) : DeviceRepository, GroupAdoptionRepository, GroupTextRepository, AutoCloseable {
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
    override fun pendingGroupAdoption(): PendingGroupAdoption? = store.pendingGroupAdoption()

    @Synchronized
    override fun stageGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean =
        store.stageGroupAdoption(record, currentIdentityId)

    @Synchronized
    override fun removeGroupAdoption(record: PendingGroupAdoption): Boolean = store.removeGroupAdoption(record)

    @Synchronized
    override fun committedGroupAdoption(): PendingGroupAdoption? = store.committedGroupAdoption()

    @Synchronized
    override fun commitGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean =
        store.commitGroupAdoption(record, currentIdentityId)

    @Synchronized
    override fun save(id: String, sender: String, session: String, body: String, signature: String): Boolean =
        store.save(id, sender, session, body, signature)

    @Synchronized
    override fun history() = store.history()

    @Synchronized
    override fun acknowledge(id: String) { store.acknowledge(id) }

    @Synchronized
    override fun reserveGroupTextCounters(groupId: String, localIdentity: String) = store.reserveGroupTextCounters(groupId, localIdentity)
    @Synchronized
    override fun saveGroupText(message: SignedGroupText, localIdentity: String) = store.saveGroupText(message, localIdentity)
    @Synchronized
    override fun groupText(id: String) = store.groupText(id)
    @Synchronized
    override fun groupTextHistory(groupId: String, sessionId: String, limit: Int) = store.groupTextHistory(groupId, sessionId, limit)
    @Synchronized
    override fun acknowledgeGroupText(message: SignedGroupText, recipientId: String) = store.acknowledgeGroupText(message, recipientId)
    @Synchronized
    override fun groupSessionWasUsed(groupId: String, sessionId: String) = store.groupSessionWasUsed(groupId, sessionId)

    @Synchronized
    override fun close() = driver.close()
}
