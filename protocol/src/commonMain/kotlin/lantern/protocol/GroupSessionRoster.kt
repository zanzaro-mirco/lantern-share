package lantern.protocol

import lantern.domain.GroupTrustAnchor

/** Signed by the participant itself, bound to one random LAN session, not a reusable TLS pin. */
class GroupSessionJoin(val sessionId: String, val membership: GroupMembershipEvidence,
                       val certificate: GroupAdmissionCertificate, val signature: String) {
    val memberId: String get() = membership.memberIdentity
    init {
        require(Wire.isFingerprint(sessionId) && certificate.identity == memberId)
        require(ProtocolSignatureEncoding.isValid(signature))
        // Admission carries issuer certificates, not the final member's key. Its own
        // certificate is independently pinned/validated by the OS when checking this join.
    }

    /** The caller supplies its independent root/session and an OS DER/pin/time/signature verifier. */
    fun verify(anchor: GroupTrustAnchor, expectedSession: String,
               verifySignature: (GroupAdmissionCertificate, ByteArray, String) -> Boolean): Boolean =
        sessionId == expectedSession && membership.verify(anchor, memberId, verifySignature) &&
            verifySignature(certificate, GroupSessionRosterCodec.signingBytes(sessionId, membership, certificate), signature)
}

/** Immutable grow-only knowledge for one current run. No history-based restoration or removals. */
class GroupSessionRoster(val anchor: GroupTrustAnchor, val sessionId: String, entries: Collection<GroupSessionJoin>,
                         val retainedSnapshot: Boolean = false) {
    private val snapshot = entries.sortedBy { it.memberId }
    val entries: List<GroupSessionJoin> get() = snapshot.toList()
    val participants: Set<String> get() = snapshot.map { it.memberId }.toSet()
    init {
        require(Wire.isFingerprint(anchor.groupId) && Wire.isFingerprint(anchor.founderId) && Wire.isFingerprint(sessionId))
        require(snapshot.isNotEmpty() && snapshot.map { it.memberId }.distinct().size == snapshot.size)
        require(snapshot.all { it.sessionId == sessionId && it.membership.anchor == anchor })
    }

    fun verify(verifySignature: (GroupAdmissionCertificate, ByteArray, String) -> Boolean): Boolean =
        snapshot.all { it.verify(anchor, sessionId, verifySignature) }

    /** Both inputs must be independently verified before merge. No entry silently disappears. */
    fun merge(other: GroupSessionRoster): GroupSessionRoster {
        require(anchor == other.anchor && sessionId == other.sessionId)
        val byMember = snapshot.associateBy { it.memberId }.toMutableMap()
        for (entry in other.snapshot) {
            val previous = byMember[entry.memberId]
            if (previous == null || compareBytes(GroupSessionRosterCodec.encodeJoin(entry), GroupSessionRosterCodec.encodeJoin(previous)) < 0) {
                byMember[entry.memberId] = entry
            }
        }
        return GroupSessionRoster(anchor, sessionId, byMember.values, retainedSnapshot || other.retainedSnapshot)
    }

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        for (index in 0 until minOf(a.size, b.size)) {
            val difference = (a[index].toInt() and 255) - (b[index].toInt() and 255)
            if (difference != 0) return difference
        }
        return a.size.compareTo(b.size)
    }
}
