package lantern.ui

import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupAdmissionChainResult
import lantern.protocol.GroupAdmissionChainVerification
import lantern.protocol.GroupAdmissionEvidence
import lantern.protocol.GroupAdmissionEvidenceCodec

/** Validated syntax only: Swift must still parse exact DER and check every certificate pin. */
class IosGroupAdmissionCertificate internal constructor(private val supplied: GroupAdmissionCertificate) {
    val identity: String get() = supplied.identity
    val der: String get() = supplied.der
}

/**
 * Swift-facing view of untrusted evidence. No root adoption, confirmation or authorization.
 * The shared codec owns all JSON, coverage, count, pin syntax and canonical Base64 rules.
 */
class IosGroupAdmissionEvidence private constructor(internal val evidence: GroupAdmissionEvidence) {
    val certificates: List<IosGroupAdmissionCertificate>
        get() = evidence.certificates.map(::IosGroupAdmissionCertificate)
    val maximumDerBytes: Int get() = GroupAdmissionCertificate.MAX_DER_BYTES

    /**
     * Pure whole-chain verification, never an authorization ticket. The anchor and member must
     * come from independent local context, not fields copied from this received evidence.
     * Swift binds the callback to each exact-pinned certificate and checks its OS validity.
     * Unexpected verifier errors propagate; no partially verified membership is exposed.
     */
    @Throws(Exception::class)
    fun verifyChain(
        expectedGroup: String,
        expectedFounder: String,
        expectedMember: String,
        verifyCertificateSignature: (String, ByteArray, String) -> Boolean,
    ): Boolean = GroupAdmissionChainVerification.verify(
        evidence.proof,
        GroupTrustAnchor(expectedGroup, expectedFounder),
        expectedMember,
        verifyCertificateSignature,
    ) == GroupAdmissionChainResult.VerifiedChain

    companion object {
        val maximumPayloadBytes: Int get() = GroupAdmissionEvidenceCodec.MAX_BYTES

        @Throws(Exception::class)
        fun decode(payload: ByteArray): IosGroupAdmissionEvidence = try {
            IosGroupAdmissionEvidence(GroupAdmissionEvidenceCodec.decode(payload))
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid group evidence")
        } catch (_: CharacterCodingException) {
            throw IllegalArgumentException("Invalid group evidence")
        }
    }
}
