package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class ProtocolHandshakeTranscriptTest {
    private val a = participant("a", "1", setOf("text", "receipts"), setOf("text"))
    private val b = participant("b", "2", setOf("text"))

    @Test
    fun transcriptMatchesIndependentCanonicalVectorAndIsSymmetric() {
        val offerA = """{"version":1,"supportedFeatures":["receipts","text"],"requiredFeatures":["text"]}"""
        val offerB = """{"version":1,"supportedFeatures":["text"],"requiredFeatures":[]}"""
        assertEquals(81, offerA.encodeToByteArray().size)
        assertEquals(64, offerB.encodeToByteArray().size)
        val expected = "19:lantern-handshake-1" +
            "64:${"a".repeat(64)}64:${"1".repeat(64)}81:$offerA" +
            "64:${"b".repeat(64)}64:${"2".repeat(64)}64:$offerB"
        assertContentEquals(expected.encodeToByteArray(), ProtocolHandshakeTranscript.bytes(a, b))
        assertContentEquals(ProtocolHandshakeTranscript.bytes(a, b), ProtocolHandshakeTranscript.bytes(b, a))
    }

    @Test
    fun approvalBindsDirectionAndCompleteTranscript() {
        val transcript = ProtocolHandshakeTranscript.bytes(a, b).decodeToString()
        val expected = "27:lantern-handshake-approve-1" +
            "64:${a.identity}64:${b.identity}${transcript.encodeToByteArray().size}:$transcript"
        assertContentEquals(expected.encodeToByteArray(), ProtocolHandshakeTranscript.approvalBytes(a, b))
        assertFalse(ProtocolHandshakeTranscript.approvalBytes(a, b).contentEquals(ProtocolHandshakeTranscript.approvalBytes(b, a)))
        assertFalse(ProtocolHandshakeTranscript.approvalBytes(a, b).contentEquals(ProtocolHandshakeTranscript.bytes(a, b)))
    }

    @Test
    fun changingEitherIdentityNonceOrOfferChangesTranscriptAndApproval() {
        val changed = listOf(
            participant("c", "1", setOf("text", "receipts"), setOf("text")),
            participant("a", "3", setOf("text", "receipts"), setOf("text")),
            participant("a", "1", setOf("text"), setOf("text")),
            participant("a", "1", setOf("text", "receipts")),
            participant("a", "1", setOf("text", "receipts"), setOf("text"), version = 2),
        )
        for (replacement in changed) {
            assertChanged(a, b, replacement, b)
            assertChanged(b, a, b, replacement)
        }
        assertChanged(a, b, a, participant("b", "3", setOf("text")))
    }

    @Test
    fun semanticOfferOrderAndJsonWhitespaceDoNotChangeTranscript() {
        val reordered = ProtocolCapabilitiesCodec.decode(
            """ { "requiredFeatures": ["text"], "version": 1, "supportedFeatures": ["text", "receipts"] } """.encodeToByteArray(),
        )
        val equivalent = ProtocolHandshakeParticipant(a.identity, a.nonce, reordered)
        assertContentEquals(ProtocolHandshakeTranscript.bytes(a, b), ProtocolHandshakeTranscript.bytes(equivalent, b))
        assertContentEquals(ProtocolHandshakeTranscript.approvalBytes(a, b), ProtocolHandshakeTranscript.approvalBytes(equivalent, b))
    }

    @Test
    fun rejectsMalformedAndRepeatedIdentityButDoesNotInventNonceFreshness() {
        for (invalid in listOf("", "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64), "é".repeat(64))) {
            assertFailsWith<IllegalArgumentException> { ProtocolHandshakeParticipant(invalid, a.nonce, a.capabilities) }
            assertFailsWith<IllegalArgumentException> { ProtocolHandshakeParticipant(a.identity, invalid, a.capabilities) }
        }
        val sameIdentity = ProtocolHandshakeParticipant(a.identity, b.nonce, b.capabilities)
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeTranscript.bytes(a, sameIdentity) }
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeTranscript.approvalBytes(a, sameIdentity) }
        // Randomness and freshness must be enforced by the connection owner, not inferred from syntax.
        ProtocolHandshakeTranscript.bytes(a, ProtocolHandshakeParticipant(b.identity, a.nonce, b.capabilities))
    }

    @Test
    fun participantCopiesCapabilitiesAndReturnedBytesHaveNoSharedOwnership() {
        val supported = mutableSetOf("text")
        val required = mutableSetOf("text")
        val snapshot = ProtocolHandshakeParticipant(a.identity, a.nonce, ProtocolCapabilities(1, supported, required))
        supported.clear()
        required.clear()
        assertEquals(setOf("text"), snapshot.capabilities.supportedFeatures)
        assertEquals(setOf("text"), snapshot.capabilities.requiredFeatures)
        val expected = ProtocolHandshakeTranscript.bytes(snapshot, b)
        val mutated = ProtocolHandshakeTranscript.bytes(snapshot, b)
        mutated.fill(0)
        assertContentEquals(expected, ProtocolHandshakeTranscript.bytes(snapshot, b))
    }

    private fun assertChanged(
        originalA: ProtocolHandshakeParticipant,
        originalB: ProtocolHandshakeParticipant,
        changedA: ProtocolHandshakeParticipant,
        changedB: ProtocolHandshakeParticipant,
    ) {
        assertFalse(ProtocolHandshakeTranscript.bytes(originalA, originalB).contentEquals(ProtocolHandshakeTranscript.bytes(changedA, changedB)))
        assertFalse(ProtocolHandshakeTranscript.approvalBytes(originalA, originalB).contentEquals(ProtocolHandshakeTranscript.approvalBytes(changedA, changedB)))
    }

    private fun participant(
        identity: String,
        nonce: String,
        supported: Set<String>,
        required: Set<String> = emptySet(),
        version: Int = 1,
    ) = ProtocolHandshakeParticipant(identity.repeat(64), nonce.repeat(64), ProtocolCapabilities(version, supported, required))
}
