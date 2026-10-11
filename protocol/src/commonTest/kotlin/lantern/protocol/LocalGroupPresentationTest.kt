package lantern.protocol

import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupFailure
import lantern.domain.LocalGroupState
import kotlin.test.Test
import kotlin.test.assertEquals

class LocalGroupPresentationTest {
    private val identity = "a".repeat(64)
    private val anchor = GroupTrustAnchor("b".repeat(64), identity)

    @Test fun emptyStorageIsNotAnAutomaticFoundation() {
        assertEquals(LocalGroupState.Empty, localGroupPresentation(null, identity))
    }
    @Test fun validLocalRootIsPreservedExactly() {
        assertEquals(LocalGroupState.Founded(anchor), localGroupPresentation(anchor, identity))
    }
    @Test fun foreignFounderIsNotDisplayedAsLocalMembership() {
        assertEquals(LocalGroupState.Failed(LocalGroupFailure.IDENTITY_MISMATCH), localGroupPresentation(anchor, "c".repeat(64)))
    }
    @Test fun malformedStoredRootIsNeverNormalized() {
        for (invalid in listOf(GroupTrustAnchor("B".repeat(64), identity), GroupTrustAnchor("group", identity), GroupTrustAnchor(anchor.groupId, "A".repeat(64)))) {
            assertEquals(LocalGroupState.Failed(LocalGroupFailure.INVALID_ROOT), localGroupPresentation(invalid, identity))
        }
    }
    @Test fun invalidOSIdentityFailsEvenIfDatabaseIsEmpty() {
        for (invalid in listOf("", "identity", "A".repeat(64))) {
            assertEquals(LocalGroupState.Failed(LocalGroupFailure.IDENTITY_MISMATCH), localGroupPresentation(null, invalid))
        }
    }
}
