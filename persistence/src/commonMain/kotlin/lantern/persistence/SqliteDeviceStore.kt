package lantern.persistence

import app.cash.sqldelight.db.SqlDriver
import lantern.domain.ChatLine
import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption

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

    fun localGroup(): GroupTrustAnchor? = queries.localGroup().executeAsOneOrNull()?.let {
        GroupTrustAnchor(it.group_id, it.founder_id)
    }

    fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean =
        database.transactionWithResult {
            require(anchor.founderId == currentIdentityId) { "Local foundation identity changed" }
            // Write first: a single conditional INSERT arbitrates independent connections too.
            // No REPLACE/IGNORE, no read-then-overwrite race, and no swallowed constraint errors.
            queries.foundLocalGroup(anchor.groupId, anchor.founderId)
            queries.lastInsertCount().executeAsOne() == 1L
        }

    fun pendingGroupAdoption(): PendingGroupAdoption? = queries.pendingAdoptionJournalRecord().executeAsOneOrNull()?.let {
        check(it.singleton == 1L) { "Invalid staged adoption singleton" }
        check(it.payload_type == "blob") { "Invalid staged adoption payload type" }
        PendingGroupAdoption(it.attempt_id, it.local_identity, it.peer_identity,
            GroupTrustAnchor(it.group_id, it.founder_id), it.payload)
    }

    fun stageGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean =
        database.transactionWithResult {
            require(record.localIdentity == currentIdentityId) { "Staged adoption identity changed" }
            queries.stageGroupAdoption(record.attemptId, record.localIdentity, record.peerIdentity,
                record.anchor.groupId, record.anchor.founderId, record.payload())
            val inserted = queries.lastInsertCount().executeAsOne() == 1L
            check(localGroup() == null) { "Cannot stage adoption while in a group" }
            check(pendingGroupAdoption()?.sameRecord(record) == true) { "Conflicting staged adoption" }
            inserted
        }

    fun removeGroupAdoption(record: PendingGroupAdoption): Boolean = database.transactionWithResult {
        queries.removeGroupAdoption(record.attemptId, record.localIdentity, record.peerIdentity,
            record.anchor.groupId, record.anchor.founderId, record.payload())
        queries.lastInsertCount().executeAsOne() == 1L
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
