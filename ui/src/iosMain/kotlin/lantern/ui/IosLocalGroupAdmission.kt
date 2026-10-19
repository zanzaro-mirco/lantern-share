package lantern.ui

import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.LocalGroupAdmission

/** Existing OS identity and committed membership only; no Swift protocol or arbitrary writes. */
object IosLocalGroupAdmission {
    val maximumDerBytes: Int get() = GroupAdmissionCertificate.MAX_DER_BYTES

    @Throws(Exception::class)
    fun prepare(
        persistence: IosPersistence,
        identityId: String,
        memberId: String,
        certificateDer: String,
        sign: (ByteArray) -> String?,
        verifyCertificateSignature: (IosGroupAdmissionCertificate, ByteArray, String) -> Boolean?,
    ): IosGroupAdmissionEvidence = IosGroupAdmissionEvidence(LocalGroupAdmission.prepareSigned(
        persistence.groupAdoptions, identityId, memberId, GroupAdmissionCertificate(identityId, certificateDer),
        { bytes -> checkNotNull(sign(bytes)) { "OS admission signing failed" } },
        { certificate, bytes, signature ->
            checkNotNull(verifyCertificateSignature(IosGroupAdmissionCertificate(certificate), bytes, signature)) {
                "OS admission verification failed"
            }
        },
    ))
}
