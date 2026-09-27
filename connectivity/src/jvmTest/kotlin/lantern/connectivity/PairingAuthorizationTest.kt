package lantern.connectivity

import lantern.domain.TrustRepository
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PairingAuthorizationTest {
    private val peer = "a".repeat(64)
    private val other = "b".repeat(64)
    private var now = 0L
    private val repository = InMemoryTrust()
    private val authorization = PairingAuthorization(repository, { now }, timeoutMillis = 100)

    @Test fun selectionPermitsHandshakeButDoesNotGrantTrust() {
        assertFalse(authorization.allowsHandshake(peer))
        authorization.select(peer)
        assertTrue(authorization.allowsHandshake(peer))
        assertFalse(authorization.isTrusted(peer))
        assertFalse(authorization.allowsHandshake(other))
    }

    @Test fun expirationAndRejectionFailClosed() {
        authorization.select(peer)
        val attempt = checkNotNull(authorization.attemptFor(peer))
        now = 100
        assertFalse(authorization.allowsHandshake(peer))
        assertFailsWith<IllegalStateException> { authorization.admit(peer, "signed", attempt) }
        assertEquals(peer, authorization.takeExpired())
        assertNull(authorization.takeExpired())
        authorization.select(peer)
        authorization.cancel()
        assertFalse(authorization.allowsHandshake(peer))
    }

    @Test fun oldApprovalCannotAuthorizeANewAttemptForSamePeer() {
        authorization.select(peer)
        val previous = checkNotNull(authorization.attemptFor(peer))
        authorization.select(peer)
        assertFailsWith<IllegalStateException> { authorization.admit(peer, "old", previous) }
        assertFalse(authorization.isTrusted(peer))
        authorization.admit(peer, "new", checkNotNull(authorization.attemptFor(peer)))
        assertTrue(authorization.isTrusted(peer))
        authorization.revoke(peer)
        assertFalse(authorization.allowsHandshake(peer))
    }

    private class InMemoryTrust : TrustRepository {
        private val peers = mutableSetOf<String>()
        override fun trusted(): Set<String> = peers.toSet()
        override fun trust(id: String, admission: String) { peers.add(id) }
        override fun block(id: String) { peers.remove(id) }
    }
}
