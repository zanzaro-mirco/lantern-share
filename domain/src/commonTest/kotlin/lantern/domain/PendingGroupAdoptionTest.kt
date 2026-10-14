package lantern.domain

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PendingGroupAdoptionTest {
    private val local = "a".repeat(64)
    private val peer = "b".repeat(64)
    private val anchor = GroupTrustAnchor("c".repeat(64), peer)

    @Test
    fun payloadIsBoundedAndDefensivelyCopied() {
        val input = byteArrayOf(1, 2, 3)
        val record = record(payload = input)
        input.fill(0)
        record.payload().fill(0)
        assertContentEquals(byteArrayOf(1, 2, 3), record.payload())
        record(payload = ByteArray(PendingGroupAdoption.MAX_PAYLOAD_BYTES))
        for (bytes in listOf(byteArrayOf(), ByteArray(PendingGroupAdoption.MAX_PAYLOAD_BYTES + 1))) {
            assertFailsWith<IllegalArgumentException> { record(payload = bytes) }
        }
    }

    @Test
    fun exactIdempotencyIncludesEveryMetadataFieldAndPayload() {
        val original = record()
        assertTrue(original.sameRecord(record()))
        for (other in listOf(
            record(id = "e".repeat(64)), record(local = "e".repeat(64)), record(peer = "e".repeat(64)),
            record(anchor = GroupTrustAnchor("e".repeat(64), peer)),
            record(anchor = GroupTrustAnchor(anchor.groupId, "e".repeat(64))), record(payload = byteArrayOf(2)),
        )) assertFalse(original.sameRecord(other))
    }

    @Test
    fun invalidIdentifiersCannotBecomeStagedMetadata() {
        for (value in listOf("", "alias", "a".repeat(63), "A".repeat(64), "z".repeat(64))) {
            assertFailsWith<IllegalArgumentException> { record(id = value) }
            assertFailsWith<IllegalArgumentException> { record(local = value) }
            assertFailsWith<IllegalArgumentException> { record(peer = value) }
            if (value.isNotBlank()) assertFailsWith<IllegalArgumentException> {
                record(anchor = GroupTrustAnchor(value, peer))
            }
        }
        assertFailsWith<IllegalArgumentException> { record(peer = local) }
    }

    private fun record(id: String = "d".repeat(64), local: String = this.local, peer: String = this.peer,
                       anchor: GroupTrustAnchor = this.anchor, payload: ByteArray = byteArrayOf(1)) =
        PendingGroupAdoption(id, local, peer, anchor, payload)
}
