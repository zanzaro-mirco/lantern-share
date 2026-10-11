package lantern.protocol

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertSame

class GroupFoundationDraftTest {
    private val localId = "a".repeat(64)
    private val groupId = "b".repeat(64)

    @Test
    fun originUsesExactlyTheLocalIdentityAndOneRandomValue() {
        var calls = 0
        val draft = GroupFoundationDraft.prepare(localId, null) {
            calls++
            groupId
        }
        assertEquals(GroupTrustAnchor(groupId, localId), draft.anchor)
        assertEquals(1, calls)
    }

    @Test
    fun anyExistingGroupRejectsBeforeRandomGeneration() {
        for (anchor in listOf(GroupTrustAnchor(groupId, localId), GroupTrustAnchor("other", "founder"))) {
            var calls = 0
            assertFailsWith<IllegalArgumentException> {
                GroupFoundationDraft.prepare(localId, anchor) {
                    calls++
                    groupId
                }
            }
            assertEquals(0, calls)
        }
    }

    @Test
    fun invalidIdentityRejectsBeforeRandomGeneration() {
        for (id in listOf("", " ", localId.uppercase(), "a".repeat(63), "g".repeat(64), " $localId")) {
            var calls = 0
            assertFailsWith<IllegalArgumentException> {
                GroupFoundationDraft.prepare(id, null) {
                    calls++
                    groupId
                }
            }
            assertEquals(0, calls)
        }
    }

    @Test
    fun malformedRandomOutputIsNotNormalizedOrRetried() {
        for (id in listOf("", groupId.uppercase(), "b".repeat(65), "z".repeat(64), "$groupId\n")) {
            var calls = 0
            assertFailsWith<IllegalArgumentException> {
                GroupFoundationDraft.prepare(localId, null) {
                    calls++
                    id
                }
            }
            assertEquals(1, calls)
        }
    }

    @Test
    fun randomFailurePropagatesWithoutFallback() {
        val failure = IllegalStateException("random source unavailable")
        var calls = 0
        val thrown = assertFailsWith<IllegalStateException> {
            GroupFoundationDraft.prepare(localId, null) {
                calls++
                throw failure
            }
        }
        assertSame(failure, thrown)
        assertEquals(1, calls)
    }

    @Test
    fun separateRequestsDoNotCacheAnOriginOrDependOnSessionOrNetwork() {
        var calls = 0
        val generate = {
            calls++
            calls.toString().repeat(64)
        }
        val first = GroupFoundationDraft.prepare(localId, null, generate)
        val second = GroupFoundationDraft.prepare(localId, null, generate)
        assertNotEquals(first.anchor.groupId, second.anchor.groupId)
        assertEquals(localId, second.anchor.founderId)
        assertEquals(2, calls)
    }

    @Test
    fun preparationDoesNotRelaxTheBanOnSelfAdmission() {
        val draft = GroupFoundationDraft.prepare(localId, null) { groupId }
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionClaim(draft.anchor.groupId, draft.anchor.founderId, localId)
        }
    }
}
