package lantern.persistence

import lantern.domain.GroupTextContent
import lantern.domain.GroupTextCounters
import lantern.domain.SignedGroupText
import lantern.domain.StoredGroupText

/** One transaction includes text, its frozen recipients and the monotone used fact. */
internal class SqliteGroupTextStore(private val database: LanternDatabase) {
    private val queries = database.groupTextQueries

    private fun checkGroup(groupId: String, localIdentity: String) {
        val root = database.storeQueries.localGroup().executeAsOneOrNull()
        require(root?.group_id == groupId) {
            "No matching durable group"
        }
        val adoption = database.storeQueries.committedAdoptionRecord().executeAsOneOrNull()
        val expectedIdentity = adoption?.local_identity ?: root.founder_id
        require(expectedIdentity == localIdentity) { "Group text storage identity changed" }
    }

    fun reserve(groupId: String, authorId: String): GroupTextCounters = database.transactionWithResult {
        require(groupId.matches(Regex("[0-9a-f]{64}")) && authorId.matches(Regex("[0-9a-f]{64}")))
        // The first write arbitrates independent connections, before reading either counter.
        queries.touchClock(groupId, authorId)
        checkGroup(groupId, authorId)
        val previous = queries.clock(groupId, authorId).executeAsOne()
        val logical = checkNotNull(queries.maxClock(groupId).executeAsOne().MAX)
        val sequence = maxOf(previous.sequence, queries.maxAuthorSequence(groupId, authorId).executeAsOne().MAX ?: 0L)
        check(sequence < Long.MAX_VALUE && logical < Long.MAX_VALUE) { "Group text counters exhausted" }
        GroupTextCounters(sequence + 1, logical + 1).also {
            queries.updateClock(it.authorSequence, it.logicalTime, groupId, authorId)
        }
    }

    fun save(message: SignedGroupText, localIdentity: String): Boolean = database.transactionWithResult {
        val c = message.content
        require(localIdentity in c.recipients) { "Local identity is not a recipient" }
        // Serialize independent writers even on an idempotent retry. Not a receipt or session restore.
        queries.markUsed(c.groupId, c.sessionId)
        checkGroup(c.groupId, localIdentity)
        val existing = text(c.id)
        if (existing != null) {
            require(existing.message.sameMessage(message)) { "Conflicting group text ID" }
            check(existing.receivedBy.contains(localIdentity)) { "Group text stored by another local identity" }
            false
        } else {
            queries.insertText(c.id, c.groupId, c.sessionId, c.authorId, c.authorSequence, c.logicalTime, c.body, message.signature)
            for (recipient in c.recipients) queries.insertRecipient(c.id, recipient, if (recipient == localIdentity) 1L else 0L)
            // Keep clocks independently of history retention, for remote authors as well.
            queries.touchClock(c.groupId, c.authorId)
            val clock = queries.clock(c.groupId, c.authorId).executeAsOne()
            queries.updateClock(maxOf(clock.sequence, c.authorSequence), maxOf(clock.logical_time, c.logicalTime),
                c.groupId, c.authorId)
            true
        }
    }

    fun text(id: String): StoredGroupText? = database.transactionWithResult {
        queries.text(id).executeAsOneOrNull()?.let(::stored)
    }

    fun history(groupId: String, sessionId: String, limit: Int): List<StoredGroupText> {
        require(limit in 1..1000) { "Invalid group history page size" }
        return database.transactionWithResult {
            queries.history(groupId, sessionId, limit.toLong()).executeAsList().reversed().map(::stored)
        }
    }

    private fun stored(row: Group_text): StoredGroupText {
        val recipients = queries.recipients(row.id).executeAsList()
        check(recipients.all { it.received == 0L || it.received == 1L }) { "Invalid group receipt storage" }
        return StoredGroupText(SignedGroupText(GroupTextContent(row.id, row.group_id, row.session_id, row.author_id,
            row.author_sequence, row.logical_time, recipients.map { it.recipient_id }, row.body), row.signature),
            recipients.filter { it.received == 1L }.map { it.recipient_id }.toSet())
    }

    fun acknowledge(message: SignedGroupText, recipientId: String): Boolean = database.transactionWithResult {
        // Write first for independent writers; any mismatch rolls the receipt back as well.
        queries.acknowledgeRecipient(message.content.id, recipientId)
        val changed = database.storeQueries.lastInsertCount().executeAsOne() == 1L
        val saved = checkNotNull(text(message.content.id)) { "Unknown group text receipt" }
        require(saved.message.sameMessage(message) && recipientId in saved.message.content.recipients) {
            "Group text receipt context mismatch"
        }
        changed
    }

    fun wasUsed(groupId: String, sessionId: String) = queries.wasUsed(groupId, sessionId).executeAsOneOrNull() != null
}
