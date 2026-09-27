package lantern.connectivity

import lantern.domain.TrustRepository
import lantern.protocol.Wire

/** Serializes candidate selection, expiration, admission and local revocation. */
internal class PairingAuthorization(
    private val repository: TrustRepository,
    private val nowMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val timeoutMillis: Long = 120_000,
) {
    private data class Candidate(val peerId: String, val selectedAt: Long, val token: Long)
    private var candidate: Candidate? = null
    private var nextToken = 0L

    init { require(timeoutMillis > 0) }

    @Synchronized
    fun select(peerId: String) {
        require(Wire.isFingerprint(peerId))
        candidate = Candidate(peerId, nowMillis(), ++nextToken)
    }

    @Synchronized
    fun selectedPeer(): String? = candidate?.peerId

    @Synchronized
    fun attemptFor(peerId: String): Long? = candidate?.takeIf { isCandidate(peerId) }?.token

    @Synchronized
    fun isTrusted(peerId: String): Boolean = peerId in repository.trusted()

    @Synchronized
    fun allowsHandshake(peerId: String): Boolean = isTrusted(peerId) || isCandidate(peerId)

    @Synchronized
    fun isCandidate(peerId: String): Boolean {
        val selected = candidate ?: return false
        return selected.peerId == peerId && nowMillis() - selected.selectedAt < timeoutMillis
    }

    @Synchronized
    fun cancel(): String? = candidate?.peerId.also { candidate = null }

    @Synchronized
    fun takeExpired(): String? {
        val selected = candidate ?: return null
        return if (nowMillis() - selected.selectedAt >= timeoutMillis) cancel() else null
    }

    /** Caller has verified both approvals and the remote signature on this TLS channel. */
    @Synchronized
    fun admit(peerId: String, signedAdmission: String, attempt: Long) {
        check(isCandidate(peerId) && candidate?.token == attempt) { "Associazione scaduta o annullata" }
        repository.trust(peerId, signedAdmission)
        candidate = null
    }

    @Synchronized
    fun revoke(peerId: String) {
        if (candidate?.peerId == peerId) candidate = null
        repository.block(peerId)
    }
}
