package lantern.protocol

import lantern.domain.GroupTextRepository
import lantern.domain.SignedGroupText

/**
 * Narrow inbox step for the future live control owner, not a transport or permission factory.
 * The caller arbitrates admission to the durable save with revocation/stop (an entered
 * transaction may finish, but cannot produce a receipt after revocation), supplies the current authenticated
 * session and expected frozen recipient snapshot independently, and keeps the repository open
 * through completion. It must NOT substitute discovery, history or a diagnostic B5 result.
 */
class GroupTextReceiver(private val repository: GroupTextRepository) {
    @Throws(Exception::class)
    fun receive(
        message: SignedGroupText,
        groupId: String,
        sessionId: String,
        localIdentity: String,
        peerIdentity: String,
        expectedRecipients: Set<String>,
        isCurrent: () -> Boolean,
        verifySignature: (ByteArray, String) -> Boolean,
    ): GroupTextSavedReceipt = receive(message, groupId, sessionId, localIdentity, peerIdentity, expectedRecipients,
        isCurrent, false, verifySignature)

    /** [relayed] only from a negotiated relay scope; the caller verifies with the author's roster certificate. */
    @Throws(Exception::class)
    fun receive(
        message: SignedGroupText,
        groupId: String,
        sessionId: String,
        localIdentity: String,
        peerIdentity: String,
        expectedRecipients: Set<String>,
        isCurrent: () -> Boolean,
        relayed: Boolean,
        verifySignature: (ByteArray, String) -> Boolean,
    ): GroupTextSavedReceipt {
        val c = message.content
        check(isCurrent()) { "Group text context expired" }
        require(localIdentity != peerIdentity) { "Group text peer cannot be the local identity" }
        require(c.groupId == groupId && c.sessionId == sessionId)
        // A relay is another frozen recipient; the caller then verifies with the author's roster certificate.
        require(if (relayed) c.authorId != peerIdentity && c.authorId != localIdentity && peerIdentity in c.recipients
            else c.authorId == peerIdentity)
        require(localIdentity in c.recipients && c.recipients.toSet() == expectedRecipients)
        // Also enforces envelope limits/signature syntax on messages constructed by local callers.
        GroupTextCodec.encode(message)
        check(verifySignature(GroupTextCodec.signedBytes(c), message.signature)) { "Invalid group text signature" }
        check(isCurrent()) { "Group text context expired" }
        repository.saveGroupText(message, localIdentity)
        // No receipt escapes if commit throws, including an ambiguous post-commit error.
        check(isCurrent()) { "Group text context expired" }
        return GroupTextSavedReceipt(message, localIdentity)
    }
}

/** Local commit evidence only. Not signed, serialized, or accepted as a network ACK yet. */
class GroupTextSavedReceipt internal constructor(val message: SignedGroupText, val recipientId: String)
