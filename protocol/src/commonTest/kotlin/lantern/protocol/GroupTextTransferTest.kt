package lantern.protocol

import lantern.domain.GroupTextContent
import lantern.domain.SignedGroupText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GroupTextTransferTest {
    private val a = "a".repeat(64)
    private val b = "b".repeat(64)
    private val g = "c".repeat(64)
    private val s = "d".repeat(64)
    private val context = GroupTextTransferContext(g, s, a, b)
    private val features = setOf(GroupTextTransferCodec.FEATURE, GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE)
    private fun participant(id: String, sender: Boolean, required: Set<String> = features, supported: Set<String> = features) =
        ProtocolHandshakeParticipant(id, "f".repeat(64), ProtocolCapabilities(1, supported +
            if (sender) GroupTextTransferCodec.SENDER_FEATURE else GroupTextTransferCodec.RECEIVER_FEATURE, required))
    private fun message(body: String = "testo") = SignedGroupText(GroupTextContent("00000000-0000-0000-0000-000000000001",
        g, s, a, 1, 1, context.recipients, body), "AQ==")

    @Test
    fun requiredNegotiationAndOppositeRolesPrecedeProofIoInEitherOrder() {
        val sender = participant(a, true)
        val receiver = participant(b, false)
        assertTrue(GroupTextTransferCodec.sendsFirst(ProtocolHandshakeOffers(sender, receiver, 0), true))
        assertFalse(GroupTextTransferCodec.sendsFirst(ProtocolHandshakeOffers(receiver, sender, 0), false))
        for (missing in features) {
            assertFails { GroupTextTransferCodec.sendsFirst(ProtocolHandshakeOffers(participant(a, true, features - missing), receiver, 0), true) }
            assertFails { GroupTextTransferCodec.sendsFirst(ProtocolHandshakeOffers(sender, participant(b, false, features - missing), 0), true) }
        }
        assertFails { GroupTextTransferCodec.sendsFirst(ProtocolHandshakeOffers(sender, participant(b, true), 0), true) }
        val bothRoles = participant(b, false, supported = features + GroupTextTransferCodec.SENDER_FEATURE)
        assertFails { GroupTextTransferCodec.sendsFirst(ProtocolHandshakeOffers(sender, bothRoles, 0), true) }
    }

    @Test
    fun fixedScopeAndAckBindEndpointsSessionMessageAndEnvelopeDigest() {
        val scope = GroupTextTransferCodec.scope(context)
        assertEquals(GroupTextTransferCodec.SCOPE_BYTES, scope.size)
        assertContentEquals(byteArrayOf(76, 84, 88, 1) + (g + s + a + b).encodeToByteArray(), scope)
        val digest = "e".repeat(64)
        val ack = GroupTextTransferCodec.acknowledgement(context, message(), digest)
        assertEquals(GroupTextTransferCodec.ACK_BYTES, ack.size)
        assertContentEquals(byteArrayOf(76, 84, 65, 1) + (message().content.id + g + s + a + b + digest).encodeToByteArray(), ack)
        assertFalse(ack.contentEquals(GroupTextTransferCodec.acknowledgement(context, message(), a)))
        assertFails { GroupTextTransferContext(g, s, a, a) }
        assertFails { GroupTextTransferContext("ssid", s, a, b) }
        assertFails { context.copy(sessionId = a).checkMessage(message()) }
        assertFails { context.copy(senderId = b, recipientId = a).checkMessage(message()) }
        assertFails { GroupTextTransferCodec.acknowledgement(context, message(), "invalid digest") }
    }

    @Test
    fun fixedControlLengthsAndVariableTextLengthsRejectBeforeAllocation() {
        for (length in listOf(0, -1, 65537)) assertFails { GroupTextTransferCodec.header(length) }
        for (length in listOf(1, 260, 360, 65536)) {
            val header = GroupTextTransferCodec.header(length)
            assertEquals(length, GroupTextTransferCodec.payloadBytes(header))
            for (expected in listOf(GroupTextTransferCodec.SCOPE_BYTES, GroupTextTransferCodec.ACK_BYTES)) {
                if (length == expected) GroupTextTransferCodec.checkFixedHeader(header, expected)
                else assertFails { GroupTextTransferCodec.checkFixedHeader(header, expected) }
            }
        }
        for (header in listOf(byteArrayOf(0, 0, 0, 0), byteArrayOf(-1, -1, -1, -1), byteArrayOf(0, 1, 0, 1), byteArrayOf(1))) {
            assertFails { GroupTextTransferCodec.payloadBytes(header) }
        }
    }
}
