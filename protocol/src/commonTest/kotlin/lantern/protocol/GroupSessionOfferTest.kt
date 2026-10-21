package lantern.protocol

import lantern.domain.GroupTrustAnchor
import lantern.domain.SessionCandidate
import lantern.domain.SessionSelection
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class GroupSessionOfferTest {
    private val anchor = GroupTrustAnchor("a".repeat(64), "f".repeat(64))
    private fun offer(id: String, used: Boolean = false) =
        GroupSessionOffer(SessionCandidate(anchor.groupId, id.repeat(64), used))

    @Test fun fixedFormatRoundTripsWithoutChangingUsed() {
        for (used in listOf(false, true)) {
            val value = offer("b", used)
            val bytes = GroupSessionOfferCodec.encode(value)
            assertEquals(133, bytes.size)
            assertEquals(listOf<Byte>(76, 83, 78, 1), bytes.take(4))
            assertEquals(value, GroupSessionOfferCodec.decode(bytes))
            GroupSessionOfferCodec.checkHeader(GroupSessionOfferCodec.header())
        }
    }

    @Test fun malformedLengthsMagicFlagsAndIdentifiersAreRejected() {
        val bytes = GroupSessionOfferCodec.encode(offer("b"))
        for (bad in listOf(bytes.dropLast(1).toByteArray(), bytes + 0,
            bytes.copyOf().apply { this[0] = 0 }, bytes.copyOf().apply { this[3] = 2 },
            bytes.copyOf().apply { this[132] = 4 }, bytes.copyOf().apply { this[132] = 1 }, bytes.copyOf().apply { this[4] = -1 },
            bytes.copyOf().apply { this[68] = 65 })) {
            assertFailsWith<IllegalArgumentException> { GroupSessionOfferCodec.decode(bad) }
        }
        for (bad in listOf(byteArrayOf(), byteArrayOf(0, 0, 0, 0), byteArrayOf(-1, -1, -1, -1),
            byteArrayOf(0, 0, 0, -122), byteArrayOf(0, 0, 0, -124))) {
            assertFailsWith<IllegalArgumentException> { GroupSessionOfferCodec.checkHeader(bad) }
        }
        assertFailsWith<IllegalArgumentException> { GroupSessionOffer(SessionCandidate(anchor.groupId, "wifi", false)) }
    }

    @Test fun emptySessionsConvergeInBothDirectionsAndUsedSessionWins() {
        val low = offer("b")
        val high = offer("e")
        assertEquals(SessionSelection.Join(low.session), low.select(anchor, high))
        assertEquals(low.select(anchor, high), high.select(anchor, low))
        val used = offer("e", true)
        assertEquals(SessionSelection.Join(used.session), low.select(anchor, used))
        assertEquals(low.select(anchor, used), used.select(anchor, low))
        assertEquals(SessionSelection.Join(low.session), low.select(anchor, low))
    }

    @Test fun returningParticipantJoinsHeldEmptySessionRatherThanCompetingWithIt() {
        val held = offer("e")
        val fresh = GroupSessionOffer(offer("b").session, established = false)
        assertEquals(SessionSelection.Join(held.session), fresh.select(anchor, held))
        assertEquals(fresh.select(anchor, held), held.select(anchor, fresh))
        val otherFresh = GroupSessionOffer(offer("d").session, established = false)
        assertEquals(SessionSelection.Join(fresh.session), fresh.select(anchor, otherFresh))
        assertEquals(fresh, GroupSessionOfferCodec.decode(GroupSessionOfferCodec.encode(fresh)))
        assertFailsWith<IllegalArgumentException> { GroupSessionOffer(offer("b", true).session, established = false) }
    }

    @Test fun usedSessionsRequireChoiceAndConflictingObservationsNeverDowngrade() {
        val a = offer("b", true)
        val b = offer("e", true)
        val choice = assertIs<SessionSelection.Choose>(a.select(anchor, b))
        assertEquals(listOf(a.session, b.session), choice.sessions)
        assertEquals(choice, b.select(anchor, a))
        assertFailsWith<IllegalArgumentException> { a.select(anchor, offer("b", false)) }
        assertFailsWith<IllegalArgumentException> { a.select(anchor.copy(groupId = "d".repeat(64)), b) }
    }

    @Test fun bothHelloOffersMustRequireSessionModeBeforeItCanReadOrWrite() {
        val feature = GroupSessionOfferCodec.FEATURE
        val caps = ProtocolCapabilities(1, setOf(feature), setOf(feature))
        val optional = ProtocolCapabilities(1, setOf(feature), emptySet())
        val a = ProtocolHandshakeParticipant("a".repeat(64), "c".repeat(64), caps)
        val b = ProtocolHandshakeParticipant("b".repeat(64), "d".repeat(64), caps)
        assertTrue(offer("e").sendsFirst(ProtocolHandshakeOffers(a, b, 0)))
        assertFalse(offer("e").sendsFirst(ProtocolHandshakeOffers(b, a, 0)))
        assertFailsWith<IllegalStateException> {
            offer("e").sendsFirst(ProtocolHandshakeOffers(ProtocolHandshakeParticipant(a.identity, a.nonce, optional), b, 0))
        }
        assertFailsWith<IllegalStateException> {
            offer("e").sendsFirst(ProtocolHandshakeOffers(a, ProtocolHandshakeParticipant(b.identity, b.nonce, optional), 0))
        }
    }
}
