package lantern.domain

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class GroupTrustAnchorTest {
    @Test
    fun groupAndFounderAreBothPartOfTheAnchor() {
        val anchor = GroupTrustAnchor("group", "founder")
        assertEquals(anchor, GroupTrustAnchor("group", "founder"))
        assertNotEquals(anchor, GroupTrustAnchor("other-group", "founder"))
        assertNotEquals(anchor, GroupTrustAnchor("group", "other-founder"))
    }

    @Test
    fun blankIdentifiersAreRejected() {
        for (blank in listOf("", " ", "\t\n")) {
            assertFailsWith<IllegalArgumentException> { GroupTrustAnchor(blank, "founder") }
            assertFailsWith<IllegalArgumentException> { GroupTrustAnchor("group", blank) }
        }
    }

    @Test
    fun opaqueIdentifiersAreNotNormalizedOrTreatedAsSelfAdmission() {
        val anchor = GroupTrustAnchor(" group ", " founder ")
        assertEquals(" group ", anchor.groupId)
        assertEquals(" founder ", anchor.founderId)
        assertEquals("same", GroupTrustAnchor("same", "same").founderId)
    }
}
