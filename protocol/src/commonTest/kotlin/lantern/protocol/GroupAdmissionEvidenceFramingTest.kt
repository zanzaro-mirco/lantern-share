package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class GroupAdmissionEvidenceFramingTest {
    @Test
    fun evidenceHasItsOwnUnsignedBigEndianLengthLimit() {
        val vectors = listOf(
            1 to byteArrayOf(0, 0, 0, 1),
            255 to byteArrayOf(0, 0, 0, 0xff.toByte()),
            256 to byteArrayOf(0, 0, 1, 0),
            65536 to byteArrayOf(0, 1, 0, 0),
            262144 to byteArrayOf(0, 4, 0, 0),
        )
        for ((length, bytes) in vectors) {
            assertContentEquals(bytes, GroupAdmissionEvidenceFraming.header(length))
            assertEquals(length, GroupAdmissionEvidenceFraming.payloadBytes(bytes))
        }
        assertFailsWith<IllegalArgumentException> { GroupAdmissionConfirmationFraming.payloadBytes(byteArrayOf(0, 4, 0, 0)) }
        assertFailsWith<IllegalArgumentException> { ProtocolHandshakeFraming.payloadBytes(byteArrayOf(0, 4, 0, 0)) }
    }

    @Test
    fun zeroNegativeOversizeAndUnsignedOverflowLengthsAreRejectedBeforeAllocation() {
        for (length in listOf(0, -1, 262145, Int.MAX_VALUE, Int.MIN_VALUE)) {
            assertFailsWith<IllegalArgumentException> { GroupAdmissionEvidenceFraming.header(length) }
        }
        for (bytes in listOf(byteArrayOf(0, 0, 0, 0), byteArrayOf(0, 4, 0, 1),
            byteArrayOf(0x80.toByte(), 0, 0, 0), ByteArray(4) { 0xff.toByte() })) {
            assertFailsWith<IllegalArgumentException> { GroupAdmissionEvidenceFraming.payloadBytes(bytes) }
        }
        for (size in listOf(0, 1, 2, 3, 5)) {
            assertFailsWith<IllegalArgumentException> { GroupAdmissionEvidenceFraming.payloadBytes(ByteArray(size)) }
        }
    }

    @Test
    fun frameContainsExactlyTheSharedPayloadAndFreshBuffers() {
        val founder = "b".repeat(64)
        val member = "c".repeat(64)
        val group = "a".repeat(64)
        val proof = GroupAdmissionProof(GroupTrustAnchor(group, founder), listOf(
            SignedGroupAdmission(GroupAdmissionClaim(group, founder, member), "cHJvb2Y="),
        ))
        val evidence = GroupAdmissionEvidence(proof, listOf(GroupAdmissionCertificate(founder, "AA==")))
        val frame = GroupAdmissionEvidenceFraming.encode(evidence)
        val payload = GroupAdmissionEvidenceCodec.encode(evidence)
        assertEquals(payload.size, GroupAdmissionEvidenceFraming.payloadBytes(frame.copyOfRange(0, 4)))
        assertContentEquals(payload, frame.copyOfRange(4, frame.size))
        val copy = frame.copyOf()
        frame.fill(0)
        assertContentEquals(copy, GroupAdmissionEvidenceFraming.encode(evidence))
        assertEquals(proof.anchor, GroupAdmissionEvidenceCodec.decode(copy.copyOfRange(4, copy.size)).proof.anchor)
    }
}
