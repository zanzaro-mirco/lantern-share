package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class GroupMembershipEvidenceFrameDecoderTest {
    private val founder = "a".repeat(64)
    private val member = "b".repeat(64)
    private val anchor = GroupTrustAnchor("c".repeat(64), founder)
    private val evidence = GroupMembershipEvidence(anchor, member, GroupAdmissionEvidence(
        GroupAdmissionProof(anchor, listOf(SignedGroupAdmission(GroupAdmissionClaim(anchor.groupId, founder, member), "AAAA"))),
        listOf(GroupAdmissionCertificate(founder, "AA=="))))
    private val payload = GroupMembershipEvidenceCodec.encode(evidence)
    private val frame = GroupMembershipEvidenceCodec.header(payload.size) + payload

    @Test
    fun arbitrarySplitsUseExactBudgetsAndCompletionIsTerminal() {
        for (split in 0..frame.size) {
            val decoder = GroupMembershipEvidenceFrameDecoder()
            val first = decoder.accept(frame.copyOfRange(0, split))
            assertEquals(split, first.consumedBytes)
            val result = if (first.evidence == null) decoder.accept(frame.copyOfRange(split, frame.size)) else first
            assertContentEquals(payload, GroupMembershipEvidenceCodec.encode(assertNotNull(result.evidence)))
            assertClosed(decoder)
        }
        val decoder = GroupMembershipEvidenceFrameDecoder()
        assertEquals(4, decoder.nextReadBytes)
        decoder.accept(frame.copyOfRange(0, 1))
        assertEquals(3, decoder.nextReadBytes)
        decoder.accept(frame.copyOfRange(1, 4))
        assertEquals(payload.size, decoder.nextReadBytes)
        decoder.close()
        assertClosed(decoder)
    }

    @Test
    fun coalescedTailIsNotConsumedAndNativeOwnerCanRejectIt() {
        val decoder = GroupMembershipEvidenceFrameDecoder()
        val result = decoder.accept(frame + byteArrayOf(7, 8))
        assertEquals(frame.size, result.consumedBytes)
        assertContentEquals(payload, GroupMembershipEvidenceCodec.encode(assertNotNull(result.evidence)))
        assertClosed(decoder)
    }

    @Test
    fun maximumPayloadReadsInBoundedChunksWithoutEarlyCompletion() {
        val padded = payload + ByteArray(GroupMembershipEvidenceCodec.MAX_BYTES - payload.size) { ' '.code.toByte() }
        val large = GroupMembershipEvidenceCodec.header(padded.size) + padded
        val decoder = GroupMembershipEvidenceFrameDecoder()
        var offset = 0
        while (offset < large.size) {
            val end = minOf(large.size, offset + decoder.nextReadBytes)
            val result = decoder.accept(large.copyOfRange(offset, end))
            assertEquals(end - offset, result.consumedBytes)
            if (end < large.size) assertNull(result.evidence) else assertNotNull(result.evidence)
            offset = end
        }
        assertClosed(decoder)
    }

    @Test
    fun eofAtEveryTruncationCancelAndInvalidLengthAreTerminal() {
        for (end in 0 until frame.size) {
            val decoder = GroupMembershipEvidenceFrameDecoder()
            assertNull(decoder.accept(frame.copyOf(end)).evidence)
            assertFailsWith<IllegalArgumentException> { decoder.finish() }
            assertClosed(decoder)
        }
        for (header in listOf(byteArrayOf(-1, -1, -1, -1), byteArrayOf(0, 0, 0, 1), byteArrayOf(0, 4, 0, -58))) {
            val decoder = GroupMembershipEvidenceFrameDecoder()
            assertFailsWith<IllegalArgumentException> { decoder.accept(header) }
            assertClosed(decoder)
        }
        val cancelled = GroupMembershipEvidenceFrameDecoder()
        cancelled.accept(frame.copyOf(6))
        cancelled.close()
        assertClosed(cancelled)
    }

    @Test
    fun oversizedChunksAndBadSyntaxHaveFixedDiagnosticsAndCannotBeRetried() {
        val oversized = GroupMembershipEvidenceFrameDecoder()
        assertFailsWith<IllegalArgumentException> { oversized.accept(ByteArray(GroupMembershipEvidenceFrameDecoder.MAX_CHUNK_BYTES + 1)) }
        assertClosed(oversized)
        val decoder = GroupMembershipEvidenceFrameDecoder()
        val bad = frame.copyOf().also { it[4] = 0 }
        val failure = assertFailsWith<IllegalArgumentException> { decoder.accept(bad) }
        assertEquals("Invalid membership frame", failure.message)
        assertNull(failure.cause)
        assertClosed(decoder)
    }

    private fun assertClosed(decoder: GroupMembershipEvidenceFrameDecoder) {
        assertFailsWith<IllegalStateException> { decoder.nextReadBytes }
        assertFailsWith<IllegalStateException> { decoder.accept(byteArrayOf()) }
        assertFailsWith<IllegalStateException> { decoder.finish() }
    }
}
