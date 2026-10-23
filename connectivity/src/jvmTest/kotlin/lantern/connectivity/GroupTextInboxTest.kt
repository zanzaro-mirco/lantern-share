package lantern.connectivity

import lantern.domain.GroupTextContent
import lantern.domain.GroupTextRepository
import lantern.domain.GroupTrustAnchor
import lantern.domain.SignedGroupText
import lantern.persistence.openDesktopRepository
import lantern.protocol.GroupTextCodec
import lantern.protocol.GroupTextReceiver
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Inbox boundary only: real OS P-256 and SQLite; not a live TLS/Node chat test. */
class GroupTextInboxTest {
    @Test
    fun receiptFollowsDurableCommitAndDuplicateCanBeReceiptedAgainAfterReopen() = withDatabase { path ->
        val author = createDesktopIdentity().identity()
        val recipient = createDesktopIdentity().identity()
        val group = randomNonce()
        val session = randomNonce()
        val c = GroupTextContent("00000000-0000-0000-0000-000000000001", group, session, author.id, 1, 1,
            listOf(author.id, recipient.id), "Messaggio firmato ☕")
        val original = SignedGroupText(c, author.sign(GroupTextCodec.signedBytes(c)))
        val decoded = GroupTextCodec.decode(GroupTextCodec.encode(original))
        openDesktopRepository(path).use { store ->
            store.foundLocalGroup(GroupTrustAnchor(group, recipient.id), recipient.id)
            val receipt = GroupTextReceiver(store).receive(decoded, group, session, recipient.id, author.id,
                c.recipients.toSet(), { true }) { bytes, signature -> Identity.verify(author.certificate, bytes, signature) }
            assertEquals(recipient.id, receipt.recipientId)
            assertTrue(original.sameMessage(assertNotNull(store.groupText(c.id)).message))
            assertEquals(setOf(recipient.id), assertNotNull(store.groupText(c.id)).receivedBy)
            assertTrue(store.history().isEmpty())
            assertTrue(store.trusted().isEmpty())
        }
        openDesktopRepository(path).use { reopened ->
            val receipt = GroupTextReceiver(reopened).receive(original, group, session, recipient.id, author.id,
                c.recipients.toSet(), { true }) { bytes, signature -> Identity.verify(author.certificate, bytes, signature) }
            assertTrue(original.sameMessage(receipt.message))
            assertEquals(1, reopened.groupTextHistory(group, session).size)
        }
    }

    @Test
    fun signatureContextAndCancellationFailuresNeverWriteOrReturnReceipt() = withDatabase { path ->
        val author = createDesktopIdentity().identity()
        val local = createDesktopIdentity().identity()
        val g = randomNonce()
        val s = randomNonce()
        val c = GroupTextContent("00000000-0000-0000-0000-000000000001", g, s, author.id, 1, 1,
            listOf(author.id, local.id), "testo")
        val message = SignedGroupText(c, author.sign(GroupTextCodec.signedBytes(c)))
        openDesktopRepository(path).use { store ->
            store.foundLocalGroup(GroupTrustAnchor(g, local.id), local.id)
            val inbox = GroupTextReceiver(store)
            fun verify(bytes: ByteArray, signature: String) = Identity.verify(author.certificate, bytes, signature)
            val tampered = SignedGroupText(GroupTextContent(c.id, g, s, author.id, 1, 1, c.recipients, "alterato"), message.signature)
            assertFails { inbox.receive(tampered, g, s, local.id, author.id, c.recipients.toSet(), { true }, ::verify) }
            assertFails { inbox.receive(message, randomNonce(), s, local.id, author.id, c.recipients.toSet(), { true }, ::verify) }
            assertFails { inbox.receive(message, g, randomNonce(), local.id, author.id, c.recipients.toSet(), { true }, ::verify) }
            assertFails { inbox.receive(message, g, s, local.id, local.id, c.recipients.toSet(), { true }, ::verify) }
            assertFails { inbox.receive(message, g, s, local.id, author.id, c.recipients.toSet() + randomNonce(), { true }, ::verify) }
            var verificationCalled = false
            assertFails {
                inbox.receive(message, g, s, local.id, author.id, c.recipients.toSet(), { false }) { _, _ ->
                    verificationCalled = true
                    true
                }
            }
            assertTrue(!verificationCalled)
            var current = true
            assertFails {
                inbox.receive(message, g, s, local.id, author.id, c.recipients.toSet(), { current }) { bytes, signature ->
                    current = false
                    verify(bytes, signature)
                }
            }
            assertNull(store.groupText(c.id))
            assertTrue(store.groupTextHistory(g, s).isEmpty())
        }
    }

    @Test
    fun ambiguousCommitErrorReturnsNoReceiptButExactRetryDoesNotDuplicate() = withDatabase { path ->
        val author = createDesktopIdentity().identity()
        val local = createDesktopIdentity().identity()
        val g = randomNonce()
        val s = randomNonce()
        val c = GroupTextContent("00000000-0000-0000-0000-000000000001", g, s, author.id, 1, 1,
            listOf(author.id, local.id), "testo")
        val message = SignedGroupText(c, author.sign(GroupTextCodec.signedBytes(c)))
        openDesktopRepository(path).use { store ->
            store.foundLocalGroup(GroupTrustAnchor(g, local.id), local.id)
            val failing = object : GroupTextRepository by store {
                override fun saveGroupText(message: SignedGroupText, localIdentity: String): Boolean {
                    store.saveGroupText(message, localIdentity)
                    error("Test: error observed after durable commit")
                }
            }
            assertFails {
                GroupTextReceiver(failing).receive(message, g, s, local.id, author.id, c.recipients.toSet(), { true }) {
                    bytes, signature -> Identity.verify(author.certificate, bytes, signature)
                }
            }
            assertNotNull(store.groupText(c.id))
        }
        openDesktopRepository(path).use { store ->
            GroupTextReceiver(store).receive(message, g, s, local.id, author.id, c.recipients.toSet(), { true }) {
                bytes, signature -> Identity.verify(author.certificate, bytes, signature)
            }
            assertEquals(1, store.groupTextHistory(g, s).size)
        }
    }

    private fun withDatabase(block: (Path) -> Unit) {
        val directory = Files.createTempDirectory("lantern-group-inbox-")
        try { block(directory.resolve("lantern.db")) }
        finally { Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }
}
