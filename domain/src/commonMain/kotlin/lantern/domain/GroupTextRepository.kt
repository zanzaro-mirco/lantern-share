package lantern.domain

/** Signed recipient snapshot, not a membership proof or a live-session authorization. */
class GroupTextContent(
    val id: String,
    val groupId: String,
    val sessionId: String,
    val authorId: String,
    val authorSequence: Long,
    val logicalTime: Long,
    recipients: Collection<String>,
    val body: String,
) {
    private val snapshot = recipients.toList().sorted()
    val recipients: List<String> get() = snapshot.toList()

    init {
        require(id.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")))
        require(listOf(groupId, sessionId, authorId).all(::isIdentity))
        require(authorSequence > 0 && logicalTime > 0)
        require(snapshot.isNotEmpty() && snapshot.all(::isIdentity) && snapshot.distinct().size == snapshot.size)
        require(authorId in snapshot) { "Author missing from recipient snapshot" }
        require(ContentLimits.isValidText(body))
        // Avoid signing lossy UTF-8 representations (including unpaired UTF-16 surrogates).
        require(body.encodeToByteArray().decodeToString(throwOnInvalidSequence = true) == body)
    }

    fun sameContent(other: GroupTextContent): Boolean = id == other.id && groupId == other.groupId &&
        sessionId == other.sessionId && authorId == other.authorId && authorSequence == other.authorSequence &&
        logicalTime == other.logicalTime && snapshot == other.snapshot && body == other.body

    private fun isIdentity(value: String) = value.matches(identityPattern)

    private companion object {
        val identityPattern = Regex("[0-9a-f]{64}")
    }
}

data class SignedGroupText(val content: GroupTextContent, val signature: String) {
    init { require(signature.length in 1..256) }

    fun sameMessage(other: SignedGroupText) = signature == other.signature && content.sameContent(other.content)
}

data class GroupTextCounters(val authorSequence: Long, val logicalTime: Long)
data class StoredGroupText(val message: SignedGroupText, val receivedBy: Set<String>)

/**
 * Blocking storage only; never authorizes traffic or revives an archived session.
 * Caller verifies the live session, OS signature and membership before save/receipt.
 */
interface GroupTextRepository {
    /** Durable reservation; gaps after cancellation are allowed, counter reuse is not. */
    fun reserveGroupTextCounters(groupId: String, localIdentity: String): GroupTextCounters
    /** Exact duplicate is idempotent; ID or author-sequence conflicts fail atomically. */
    fun saveGroupText(message: SignedGroupText, localIdentity: String): Boolean
    fun groupText(id: String): StoredGroupText?
    /** Local history only, deterministic logical ordering. No automatic republication. */
    fun groupTextHistory(groupId: String, sessionId: String, limit: Int = 200): List<StoredGroupText>
    /** Match the entire stored message and one frozen recipient; never a global ACK. */
    fun acknowledgeGroupText(message: SignedGroupText, recipientId: String): Boolean
    /** Durable monotone fact, not an active-session lookup. */
    fun groupSessionWasUsed(groupId: String, sessionId: String): Boolean
}
