package lantern.ui

import lantern.protocol.FounderGroupAdmissionDraft
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupAdmissionEvidence

/** Preparation only; no connection, lifecycle, remote root adoption or durable admission. */
object IosFounderGroupAdmission {
    /** Swift binds both callbacks and DER to its existing OS identity, on the owning I/O queue. */
    @Throws(Exception::class)
    fun prepare(
        persistence: IosPersistence,
        identityId: String,
        memberId: String,
        certificateDer: String,
        sign: (ByteArray) -> String?,
        verifySignature: (ByteArray, String) -> Boolean,
    ): IosGroupAdmissionEvidence {
        val certificate = GroupAdmissionCertificate(identityId, certificateDer)
        val proof = FounderGroupAdmissionDraft.prepareSigned(
            persistence.localGroups, identityId, memberId,
            { bytes -> checkNotNull(sign(bytes)) { "OS admission signing failed" } },
            verifySignature,
        )
        return IosGroupAdmissionEvidence(GroupAdmissionEvidence(proof, listOf(certificate)))
    }
}
