package lantern.protocol

import lantern.domain.SessionCandidate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class GroupSessionOfferFrameDecoderTest {
    private val offer = GroupSessionOffer(SessionCandidate("a".repeat(64), "b".repeat(64), false), false)
    private val frame = GroupSessionOfferCodec.header() + GroupSessionOfferCodec.encode(offer)

    @Test
    fun allSplitsAndExactSingleByteBudgetsCompleteOnce() {
        for (split in 0..frame.size) {
            val decoder = GroupSessionOfferFrameDecoder()
            val first = decoder.accept(frame.copyOfRange(0, split))
            assertEquals(split, first.consumedBytes)
            val result = first.offer ?: decoder.accept(frame.copyOfRange(split, frame.size)).offer
            assertEquals(offer, result)
            assertClosed(decoder)
        }
        val decoder = GroupSessionOfferFrameDecoder()
        for (index in frame.indices) {
            assertEquals(if (index < 4) 4 - index else frame.size - index, decoder.nextReadBytes)
            val result = decoder.accept(byteArrayOf(frame[index]))
            assertEquals(1, result.consumedBytes)
            if (index == frame.lastIndex) assertEquals(offer, result.offer) else assertNull(result.offer)
        }
    }

    @Test
    fun everyTruncationEofAndCancellationAreTerminal() {
        for (end in frame.indices) {
            val decoder = GroupSessionOfferFrameDecoder()
            assertNull(decoder.accept(frame.copyOf(end)).offer)
            assertFailsWith<IllegalArgumentException> { decoder.finish() }
            assertClosed(decoder)
        }
        val decoder = GroupSessionOfferFrameDecoder()
        decoder.accept(frame.copyOf(7))
        decoder.close()
        assertClosed(decoder)
    }

    @Test
    fun rejectsHeaderBeforePayloadAndInvalidSyntaxWithoutRetry() {
        for (bad in listOf(byteArrayOf(-1, -1, -1, -1), byteArrayOf(0, 0, 0, 0), byteArrayOf(0, 0, 0, -122))) {
            val decoder = GroupSessionOfferFrameDecoder()
            assertFailsWith<IllegalArgumentException> { decoder.accept(bad) }
            assertClosed(decoder)
        }
        for (index in listOf(4, 8, frame.lastIndex)) {
            val decoder = GroupSessionOfferFrameDecoder()
            val bad = frame.copyOf().also { it[index] = -1 }
            assertFailsWith<IllegalArgumentException> { decoder.accept(bad) }
            assertClosed(decoder)
        }
    }

    @Test
    fun boundedTailIsNotConsumedAndOversizedInputCloses() {
        val decoder = GroupSessionOfferFrameDecoder()
        decoder.accept(frame.copyOf(4))
        val result = decoder.accept(frame.copyOfRange(4, frame.size) + byteArrayOf(9))
        assertEquals(133, result.consumedBytes)
        assertNotNull(result.offer)
        assertClosed(decoder)
        val oversized = GroupSessionOfferFrameDecoder()
        assertFailsWith<IllegalArgumentException> { oversized.accept(ByteArray(138)) }
        assertClosed(oversized)
    }

    private fun assertClosed(decoder: GroupSessionOfferFrameDecoder) {
        assertFailsWith<IllegalStateException> { decoder.nextReadBytes }
        assertFailsWith<IllegalStateException> { decoder.accept(byteArrayOf()) }
        assertFailsWith<IllegalStateException> { decoder.finish() }
    }
}
