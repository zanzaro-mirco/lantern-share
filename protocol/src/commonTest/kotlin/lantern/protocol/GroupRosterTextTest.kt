package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTextContent
import lantern.domain.GroupTextCounters
import lantern.domain.GroupTextRepository
import lantern.domain.GroupTrustAnchor
import lantern.domain.SignedGroupText
import lantern.domain.StoredGroupText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GroupRosterTextTest {
    private val a = "a".repeat(64)
    private val b = "b".repeat(64)
    private val c = "c".repeat(64)
    private val anchor = GroupTrustAnchor("d".repeat(64), a)
    private val session = "e".repeat(64)
    private val digest = "f".repeat(64)
    private fun join(id: String): GroupSessionJoin {
        val evidence = if (id == a) null else GroupAdmissionEvidence(
            GroupAdmissionProof(anchor, listOf(SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, a, id), "AAAA"))),
            listOf(GroupAdmissionCertificate(a, "AA==")))
        return GroupSessionJoin(session, GroupMembershipEvidence(anchor, id, evidence), GroupAdmissionCertificate(id, "AA=="), "AQ==")
    }
    private val roster get() = GroupSessionRoster(anchor, session, listOf(join(c), join(a), join(b)), true)
    private fun message(recipients: Set<String> = setOf(a, b, c), id: String = "00000000-0000-0000-0000-000000000001") =
        SignedGroupText(GroupTextContent(id, anchor.groupId, session, a, 1, 1, recipients, "Testo ☕"), "AQ==")

    @Test
    fun exactScopeAndRecipientAckAreDistinctFromLegacyAndBindWholeEnvelope() {
        val context = GroupRosterTextContext(roster, a, b, digest)
        assertEquals(setOf(a, b, c), context.recipients)
        val exposed = context.recipients.toMutableSet().apply { remove(c) }
        assertEquals(2, exposed.size)
        assertEquals(3, context.recipients.size)
        val scope = GroupRosterTextCodec.scope(context)
        assertEquals(324, scope.size)
        assertContentEquals(byteArrayOf(76, 84, 67, 1) + (anchor.groupId + session + a + b + digest).encodeToByteArray(), scope)
        val ack = GroupRosterTextCodec.acknowledgement(context, message(), digest)
        assertEquals(360, ack.size)
        assertContentEquals(byteArrayOf(76, 71, 65, 1) + (message().content.id + anchor.groupId + session + a + b + digest).encodeToByteArray(), ack)
        assertFalse(scope.contentEquals(GroupRosterTextCodec.scope(GroupRosterTextContext(roster, a, c, digest))))
        assertFalse(scope.contentEquals(GroupRosterTextCodec.scope(GroupRosterTextContext(roster, a, b, a))))
        assertFalse(ack.contentEquals(GroupRosterTextCodec.acknowledgement(GroupRosterTextContext(roster, a, c, digest), message(), digest)))
        assertFalse(ack.contentEquals(GroupRosterTextCodec.acknowledgement(context, message(id = "00000000-0000-0000-0000-000000000002"), digest)))
        assertFalse(ack.contentEquals(GroupRosterTextCodec.acknowledgement(context, message(), a)))
        assertFails { GroupRosterTextCodec.acknowledgement(context, message(setOf(a, b)), digest) }
        assertFails { GroupRosterTextContext(roster, a, a, digest) }
        assertFails { GroupRosterTextContext(roster, a, digest, digest) }
        assertFails { GroupRosterTextContext(roster, a, b, "digest") }
        assertFails { GroupRosterTextCodec.acknowledgement(context, message(), "digest") }
        val legacy = GroupTextTransferContext(anchor.groupId, session, a, b)
        assertFails { legacy.checkMessage(message()) }
        assertFalse(ack.copyOfRange(0, 4).contentEquals(GroupTextTransferCodec.acknowledgement(legacy, message(setOf(a, b)), digest).copyOfRange(0, 4)))
    }

    @Test
    fun allCapabilitiesAreRequiredAndOppositeRolesCheckedInBothOrders() {
        val required = GroupRosterTextCodec.requiredFeatures
        fun participant(id: String, sender: Boolean, supported: Set<String> = required, demanded: Set<String> = required) =
            ProtocolHandshakeParticipant(id, digest, ProtocolCapabilities(1, supported +
                if (sender) GroupTextTransferCodec.SENDER_FEATURE else GroupTextTransferCodec.RECEIVER_FEATURE, demanded))
        val sender = participant(a, true)
        val receiver = participant(b, false)
        assertTrue(GroupRosterTextCodec.sendsFirst(ProtocolHandshakeOffers(sender, receiver, 0), true))
        assertFalse(GroupRosterTextCodec.sendsFirst(ProtocolHandshakeOffers(receiver, sender, 0), false))
        for (missing in required) {
            assertFails { GroupRosterTextCodec.sendsFirst(ProtocolHandshakeOffers(participant(a, true, demanded = required - missing), receiver, 0), true) }
            assertFails { GroupRosterTextCodec.sendsFirst(ProtocolHandshakeOffers(sender, participant(b, false, supported = required - missing), 0), true) }
        }
        assertFails { GroupRosterTextCodec.sendsFirst(ProtocolHandshakeOffers(sender, participant(b, true), 0), true) }
        assertFails { GroupRosterTextCodec.sendsFirst(ProtocolHandshakeOffers(sender,
            participant(b, false, supported = required + GroupTextTransferCodec.SENDER_FEATURE), 0), true) }
    }

    @Test
    fun savedCopyKeepsFrozenSubsetOfLiveRosterAndNeverAddsLaterJoiners() {
        val later = "9".repeat(64)
        val live = GroupSessionRoster(anchor, session, listOf(join(c), join(a), join(b), join(later)), true)
        val copy = GroupRosterTextContext(live, a, b, digest, savedCopy = true)
        val exact = GroupRosterTextContext(live, a, b, digest)
        val original = message(setOf(a, b, c))
        copy.checkMessage(original)
        assertEquals(setOf(a, b, c), copy.expectedRecipients(original))
        assertEquals(setOf(a, b, c, later), copy.recipients) // Live roster for run checks only.
        assertFails { exact.checkMessage(original) }
        assertFails { exact.expectedRecipients(original) }
        val scope = GroupRosterTextCodec.scope(copy)
        assertEquals(324, scope.size)
        assertContentEquals(byteArrayOf(76, 84, 67, 2), scope.copyOfRange(0, 4))
        assertContentEquals(GroupRosterTextCodec.scope(exact).copyOfRange(4, 324), scope.copyOfRange(4, 324))
        assertContentEquals(GroupRosterTextCodec.acknowledgement(exact, message(setOf(a, b, c, later)), digest),
            GroupRosterTextCodec.acknowledgement(copy, message(setOf(a, b, c, later)), digest))
        GroupRosterTextCodec.acknowledgement(copy, original, digest)
        // The later joiner is outside the snapshot; an outsider/other session/author never fits.
        assertFails { GroupRosterTextContext(live, a, later, digest, savedCopy = true).checkMessage(original) }
        assertFails { GroupRosterTextCodec.acknowledgement(GroupRosterTextContext(live, a, later, digest, savedCopy = true), original, digest) }
        assertFails { copy.checkMessage(message(setOf(a, b, digest))) }
        assertFails { GroupRosterTextContext(live, b, c, digest, savedCopy = true).checkMessage(message(setOf(a, b, c))) }
        val otherSession = SignedGroupText(GroupTextContent("00000000-0000-0000-0000-000000000003", anchor.groupId,
            "1".repeat(64), a, 1, 1, setOf(a, b), "Altra sessione"), "AQ==")
        assertFails { copy.checkMessage(otherSession) }
        assertFails { GroupRosterTextContext(GroupSessionRoster(anchor, session, listOf(join(a), join(b)), true), a, b, digest,
            savedCopy = true).checkMessage(original) }
    }

    @Test
    fun savedCopyModeIsAnExplicitAuthorRequirementOnly() {
        val required = GroupRosterTextCodec.requiredFeatures
        val copy = GroupRosterTextCodec.COPY_FEATURE
        fun participant(id: String, sender: Boolean, supported: Set<String> = emptySet(), demanded: Set<String> = emptySet()) =
            ProtocolHandshakeParticipant(id, digest, ProtocolCapabilities(1, required + supported +
                if (sender) GroupTextTransferCodec.SENDER_FEATURE else GroupTextTransferCodec.RECEIVER_FEATURE, required + demanded))
        val author = participant(a, true, setOf(copy), setOf(copy))
        val newText = participant(a, true)
        val receiver = participant(b, false, setOf(copy))
        val oldReceiver = participant(b, false)
        assertTrue(GroupRosterTextCodec.savedCopy(ProtocolHandshakeOffers(author, receiver, 0), true))
        assertTrue(GroupRosterTextCodec.savedCopy(ProtocolHandshakeOffers(receiver, author, 0), false))
        assertFalse(GroupRosterTextCodec.savedCopy(ProtocolHandshakeOffers(newText, receiver, 0), true))
        assertFalse(GroupRosterTextCodec.savedCopy(ProtocolHandshakeOffers(oldReceiver, newText, 0), false))
        assertFails { GroupRosterTextCodec.savedCopy(ProtocolHandshakeOffers(author, oldReceiver, 0), true) }
        assertFails { GroupRosterTextCodec.savedCopy(ProtocolHandshakeOffers(newText, participant(b, false, setOf(copy), setOf(copy)), 0), true) }
        assertFails { GroupRosterTextCodec.savedCopy(ProtocolHandshakeOffers(participant(a, true, setOf(copy)), receiver, 0), true) }
        assertFails { GroupRosterTextCodec.savedCopy(ProtocolHandshakeOffers(receiver, participant(a, true, setOf(copy)), 0), false) }
        assertTrue(GroupRosterTextCodec.sendsFirst(ProtocolHandshakeOffers(author, receiver, 0), true))
    }

    @Test
    fun relayedCopyComesFromAnotherFrozenRecipientAndUsesTheAuthorsRosterCertificate() {
        val later = "9".repeat(64)
        val live = GroupSessionRoster(anchor, session, listOf(join(c), join(a), join(b), join(later)), true)
        val relay = GroupRosterTextContext(live, b, c, digest, relayedCopy = true)
        val authorCopy = GroupRosterTextContext(live, b, c, digest, savedCopy = true)
        val original = message(setOf(a, b, c))
        relay.checkMessage(original)
        assertEquals(setOf(a, b, c), relay.expectedRecipients(original))
        assertEquals(a, relay.authorCertificate(original).identity)
        val scope = GroupRosterTextCodec.scope(relay)
        assertEquals(324, scope.size)
        assertContentEquals(byteArrayOf(76, 84, 67, 3), scope.copyOfRange(0, 4))
        assertContentEquals(GroupRosterTextCodec.scope(authorCopy).copyOfRange(4, 324), scope.copyOfRange(4, 324))
        GroupRosterTextCodec.acknowledgement(relay, original, digest)
        // Distinct modes: neither an author copy nor a new text fits a relayed envelope.
        assertFails { authorCopy.checkMessage(original) }
        assertFails { GroupRosterTextContext(live, b, c, digest).checkMessage(original) }
        assertFails { authorCopy.authorCertificate(original) }
        assertFails { GroupRosterTextContext(live, b, c, digest, savedCopy = true, relayedCopy = true) }
        // Author as relay, back to the author, later joiner, relay outside the snapshot, author unknown live.
        assertFails { GroupRosterTextContext(live, a, c, digest, relayedCopy = true).checkMessage(original) }
        assertFails { GroupRosterTextContext(live, b, a, digest, relayedCopy = true).checkMessage(original) }
        assertFails { GroupRosterTextContext(live, b, later, digest, relayedCopy = true).checkMessage(original) }
        assertFails { GroupRosterTextContext(live, later, c, digest, relayedCopy = true).checkMessage(original) }
        assertFails { relay.checkMessage(message(setOf(a, c))) }
        assertFails { GroupRosterTextContext(GroupSessionRoster(anchor, session, listOf(join(b), join(c)), true), b, c, digest,
            relayedCopy = true).checkMessage(original) }
    }

    @Test
    fun relayedCopyIsAnExplicitSenderRequirementExclusiveWithAuthorCopies() {
        val required = GroupRosterTextCodec.requiredFeatures
        val copy = GroupRosterTextCodec.COPY_FEATURE
        val relay = GroupRosterTextCodec.RELAY_FEATURE
        fun participant(id: String, sender: Boolean, supported: Set<String> = emptySet(), demanded: Set<String> = emptySet()) =
            ProtocolHandshakeParticipant(id, digest, ProtocolCapabilities(1, required + supported +
                if (sender) GroupTextTransferCodec.SENDER_FEATURE else GroupTextTransferCodec.RECEIVER_FEATURE, required + demanded))
        val relayer = participant(b, true, setOf(relay), setOf(relay))
        val receiver = participant(c, false, setOf(copy, relay))
        assertTrue(GroupRosterTextCodec.relayedCopy(ProtocolHandshakeOffers(relayer, receiver, 0), true))
        assertTrue(GroupRosterTextCodec.relayedCopy(ProtocolHandshakeOffers(receiver, relayer, 0), false))
        assertFalse(GroupRosterTextCodec.savedCopy(ProtocolHandshakeOffers(relayer, receiver, 0), true))
        val author = participant(a, true, setOf(copy), setOf(copy))
        assertFalse(GroupRosterTextCodec.relayedCopy(ProtocolHandshakeOffers(author, receiver, 0), true))
        assertTrue(GroupRosterTextCodec.savedCopy(ProtocolHandshakeOffers(author, receiver, 0), true))
        assertFalse(GroupRosterTextCodec.relayedCopy(ProtocolHandshakeOffers(participant(b, true), receiver, 0), true))
        // ADR 019 receivers lack the relay feature; supported-only, receiver-demanded and dual requests fail.
        assertFails { GroupRosterTextCodec.relayedCopy(ProtocolHandshakeOffers(relayer, participant(c, false, setOf(copy)), 0), true) }
        assertFails { GroupRosterTextCodec.relayedCopy(ProtocolHandshakeOffers(participant(b, true, setOf(relay)), receiver, 0), true) }
        assertFails { GroupRosterTextCodec.relayedCopy(ProtocolHandshakeOffers(participant(b, true),
            participant(c, false, setOf(copy, relay), setOf(relay)), 0), true) }
        assertFails { GroupRosterTextCodec.relayedCopy(ProtocolHandshakeOffers(participant(b, true, setOf(copy, relay), setOf(copy, relay)),
            receiver, 0), true) }
    }

    @Test
    fun receiverAcceptsAnotherTlsSenderOnlyAsNegotiatedRelay() {
        val saved = mutableListOf<SignedGroupText>()
        val repository = object : GroupTextRepository {
            override fun reserveGroupTextCounters(groupId: String, localIdentity: String) = GroupTextCounters(1, 1)
            override fun saveGroupText(message: SignedGroupText, localIdentity: String) = saved.add(message)
            override fun groupText(id: String): StoredGroupText? = null
            override fun groupTextHistory(groupId: String, sessionId: String, limit: Int) = emptyList<StoredGroupText>()
            override fun acknowledgeGroupText(message: SignedGroupText, recipientId: String) = false
            override fun groupSessionWasUsed(groupId: String, sessionId: String) = false
        }
        val original = message(setOf(a, b, c))
        fun receive(peer: String, local: String, relayed: Boolean) = GroupTextReceiver(repository).receive(original,
            anchor.groupId, session, local, peer, setOf(a, b, c), { true }, relayed) { _, _ -> true }
        assertFails { receive(b, c, false) } // A direct delivery still comes from the author only.
        assertFails { receive(a, c, true) }
        assertFails { receive(b, a, true) }
        assertFails { receive("9".repeat(64), c, true) }
        assertTrue(saved.isEmpty())
        assertEquals(c, receive(b, c, true).recipientId)
        assertEquals(c, receive(a, c, false).recipientId)
        assertEquals(2, saved.size)
    }

    @Test
    fun fixedControlsRejectUnsignedOrWrongLengthsBeforeAllocation() {
        for (expected in listOf(324, 360)) {
            GroupRosterTextCodec.checkFixedHeader(GroupTextTransferCodec.header(expected), expected)
            for (length in listOf(1, 260, expected - 1, expected + 1, 65536)) {
                assertFails { GroupRosterTextCodec.checkFixedHeader(GroupTextTransferCodec.header(length), expected) }
            }
            for (header in listOf(byteArrayOf(0), byteArrayOf(0, 0, 0, 0), byteArrayOf(-1, -1, -1, -1))) {
                assertFails { GroupRosterTextCodec.checkFixedHeader(header, expected) }
            }
        }
        assertFails { GroupRosterTextCodec.checkFixedHeader(GroupTextTransferCodec.header(260), 260) }
    }
}
