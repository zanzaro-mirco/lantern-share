package lantern.connectivity

import lantern.domain.GroupTrustAnchor
import lantern.protocol.Wire
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class LocalGroupFoundationTest {
    @Test
    fun osRandomOriginsReuseTheExistingIdentityWithoutRotatingItsKey() {
        val identity = createDesktopIdentity().identity()
        val id = identity.id
        val first = prepareLocalGroupFoundation(identity, null)
        val second = prepareLocalGroupFoundation(identity, null)
        assertTrue(Wire.isFingerprint(first.anchor.groupId))
        assertTrue(Wire.isFingerprint(second.anchor.groupId))
        assertNotEquals(first.anchor.groupId, second.anchor.groupId)
        assertEquals(id, first.anchor.founderId)
        assertEquals(id, second.anchor.founderId)
        val challenge = first.anchor.groupId.encodeToByteArray()
        assertTrue(Identity.verify(identity.certificate, challenge, identity.sign(challenge)))
        assertEquals(id, identity.id)
    }

    @Test
    fun existingMembershipCannotBeSilentlyReplaced() {
        val identity = createDesktopIdentity().identity()
        val existing = GroupTrustAnchor(randomNonce(), identity.id)
        assertFailsWith<IllegalArgumentException> { prepareLocalGroupFoundation(identity, existing) }
        assertEquals(identity.id, existing.founderId)
    }
}
