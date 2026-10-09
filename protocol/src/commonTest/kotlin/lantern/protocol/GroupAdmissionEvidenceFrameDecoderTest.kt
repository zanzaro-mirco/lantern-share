package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GroupAdmissionEvidenceFrameDecoderTest {
    private val founder = "b".repeat(64)
    private val member = "c".repeat(64)
    private val group = "a".repeat(64)
    private val proof = GroupAdmissionProof(GroupTrustAnchor(group, founder), listOf(
        SignedGroupAdmission(GroupAdmissionClaim(group, founder, member), "cHJvb2Y="),
    ))
    private val evidence = GroupAdmissionEvidence(proof, listOf(GroupAdmissionCertificate(founder, "AA==")))
    private val frame = GroupAdmissionEvidenceFraming.encode(evidence)

    @Test
    fun everySplitAndSingleByteFragmentsReturnExactlyOneCompleteEvidence() {
        for (split in 0 until frame.size) {
            val decoder = GroupAdmissionEvidenceFrameDecoder()
            val first = decoder.accept(frame.copyOfRange(0, split))
            assertEquals(split, first.consumedBytes)
            assertNull(first.evidence)
            val second = decoder.accept(frame.copyOfRange(split, frame.size))
            assertEquals(frame.size - split, second.consumedBytes)
            assertEvidence(assertNotNull(second.evidence))
            assertClosed(decoder)
        }
        val decoder = GroupAdmissionEvidenceFrameDecoder()
        for (index in frame.indices) {
            val result = decoder.accept(byteArrayOf(frame[index]))
            assertEquals(1, result.consumedBytes)
            if (index == frame.lastIndex) assertEvidence(assertNotNull(result.evidence)) else assertNull(result.evidence)
        }
        assertClosed(decoder)
    }

    @Test
    fun queuedConfirmationAndSecondEvidenceRemainUnconsumedForTheOwner() {
        val confirmation = GroupAdmissionConfirmationFrameDecoder.encode(GroupAdmissionConfirmation(founder, member, "cHJvb2Y="))
        for (tail in listOf(confirmation, frame)) {
            val decoder = GroupAdmissionEvidenceFrameDecoder()
            val chunk = frame + tail
            val result = decoder.accept(chunk)
            assertEquals(frame.size, result.consumedBytes)
            assertEvidence(assertNotNull(result.evidence))
            assertContentEquals(tail, chunk.copyOfRange(result.consumedBytes, chunk.size))
            assertClosed(decoder)
        }
    }

    @Test
    fun exactReadBudgetPreventsReadAheadAndIsBoundedForLargePayloads() {
        val decoder = GroupAdmissionEvidenceFrameDecoder()
        assertEquals(4, decoder.nextReadBytes)
        assertNull(decoder.accept(frame.copyOfRange(0, 2)).evidence)
        assertEquals(2, decoder.nextReadBytes)
        assertNull(decoder.accept(frame.copyOfRange(2, 4)).evidence)
        assertEquals(frame.size - 4, decoder.nextReadBytes)
        assertNull(decoder.accept(frame.copyOfRange(4, 7)).evidence)
        assertEquals(frame.size - 7, decoder.nextReadBytes)
        assertEvidence(assertNotNull(decoder.accept(frame.copyOfRange(7, frame.size)).evidence))
        assertClosed(decoder)
        val large = GroupAdmissionEvidenceFrameDecoder()
        large.accept(GroupAdmissionEvidenceFraming.header(GroupAdmissionEvidenceCodec.MAX_BYTES))
        assertEquals(GroupAdmissionEvidenceFrameDecoder.MAX_CHUNK_BYTES, large.nextReadBytes)
        large.close()
    }

    @Test
    fun maximumPayloadUsesOnlyBoundedChunksAndReturnsOnlyAfterFinalByte() {
        val json = GroupAdmissionEvidenceCodec.encode(evidence)
        val payload = json + ByteArray(GroupAdmissionEvidenceCodec.MAX_BYTES - json.size) { ' '.code.toByte() }
        val large = GroupAdmissionEvidenceFraming.header(payload.size) + payload
        val decoder = GroupAdmissionEvidenceFrameDecoder()
        var offset = 0
        while (offset < large.size) {
            val end = minOf(large.size, offset + decoder.nextReadBytes)
            val result = decoder.accept(large.copyOfRange(offset, end))
            assertEquals(end - offset, result.consumedBytes)
            if (end == large.size) assertEvidence(assertNotNull(result.evidence)) else assertNull(result.evidence)
            offset = end
        }
        assertClosed(decoder)
    }

    @Test
    fun invalidUnsignedHeaderIsRejectedAsSoonAsTheFourthByteArrives() {
        for (header in listOf(byteArrayOf(0, 0, 0, 0), byteArrayOf(0, 4, 0, 1),
            byteArrayOf(0x80.toByte(), 0, 0, 0), ByteArray(4) { 0xff.toByte() })) {
            val decoder = GroupAdmissionEvidenceFrameDecoder()
            assertNull(decoder.accept(header.copyOfRange(0, 3)).evidence)
            assertFailsWith<IllegalArgumentException> { decoder.accept(header.copyOfRange(3, 4)) }
            assertClosed(decoder)
        }
    }

    @Test
    fun truncatedOrMissingMandatoryFrameCannotResumeAfterEof() {
        for (end in 0 until frame.size) {
            val decoder = GroupAdmissionEvidenceFrameDecoder()
            assertNull(decoder.accept(frame.copyOfRange(0, end)).evidence)
            assertEquals("Truncated group evidence stream", assertFailsWith<IllegalArgumentException> { decoder.finish() }.message)
            assertClosed(decoder)
        }
    }

    @Test
    fun parserDiagnosticsAndUnsupportedMessagesAreNotForwardedToTheOwner() {
        val confirmation = GroupAdmissionConfirmationCodec.encode(GroupAdmissionConfirmation(founder, member, "cHJvb2Y="))
        val invalid = listOf("{\"private-peer-content\":true}".encodeToByteArray(), byteArrayOf(0xc0.toByte(), 0xaf.toByte()),
            confirmation, GroupAdmissionProofCodec.encode(proof), ("[".repeat(6) + "0" + "]".repeat(6)).encodeToByteArray())
        for (payload in invalid) {
            val decoder = GroupAdmissionEvidenceFrameDecoder()
            val failure = assertFailsWith<IllegalArgumentException> {
                decoder.accept(GroupAdmissionEvidenceFraming.header(payload.size) + payload)
            }
            assertEquals("Invalid group evidence frame", failure.message)
            assertNull(failure.cause)
            assertClosed(decoder)
        }
    }

    @Test
    fun inputMutationEmptyChunksOversizeAndCancellationDoNotReviveDecoder() {
        val decoder = GroupAdmissionEvidenceFrameDecoder()
        val prefix = frame.copyOfRange(0, 10)
        assertNull(decoder.accept(prefix).evidence)
        prefix.fill(0)
        assertEquals(0, decoder.accept(byteArrayOf()).consumedBytes)
        assertEvidence(assertNotNull(decoder.accept(frame.copyOfRange(10, frame.size)).evidence))
        assertClosed(decoder)
        val cancelled = GroupAdmissionEvidenceFrameDecoder()
        cancelled.accept(frame.copyOfRange(0, 10))
        cancelled.close()
        cancelled.close()
        assertClosed(cancelled)
        val oversized = GroupAdmissionEvidenceFrameDecoder()
        assertFailsWith<IllegalArgumentException> {
            oversized.accept(ByteArray(GroupAdmissionEvidenceFrameDecoder.MAX_CHUNK_BYTES + 1))
        }
        assertClosed(oversized)
    }

    private fun assertEvidence(actual: GroupAdmissionEvidence) {
        assertContentEquals(GroupAdmissionEvidenceCodec.encode(evidence), GroupAdmissionEvidenceCodec.encode(actual))
    }

    private fun assertClosed(decoder: GroupAdmissionEvidenceFrameDecoder) {
        assertFailsWith<IllegalStateException> { decoder.accept(frame) }
        assertFailsWith<IllegalStateException> { decoder.finish() }
        assertFailsWith<IllegalStateException> { decoder.nextReadBytes }
    }
}
