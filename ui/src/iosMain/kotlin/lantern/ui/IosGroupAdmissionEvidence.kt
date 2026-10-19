package lantern.ui

import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupAdmissionChainResult
import lantern.protocol.GroupAdmissionChainVerification
import lantern.protocol.GroupAdmissionEvidence
import lantern.protocol.GroupAdmissionEvidenceCodec
import lantern.protocol.GroupAdmissionEvidenceFraming

/** Validated syntax only: Swift must still parse exact DER and check every certificate pin. */
class IosGroupAdmissionCertificate internal constructor(private val supplied: GroupAdmissionCertificate) {
    val identity: String get() = supplied.identity
    val der: String get() = supplied.der
}

/**
 * Swift-facing view of untrusted evidence. No root adoption, confirmation or authorization.
 * The shared codec owns all JSON, coverage, count, pin syntax and canonical Base64 rules.
 */
class IosGroupAdmissionEvidence internal constructor(internal val evidence: GroupAdmissionEvidence) {
    /** Untrusted display value: only the live full comparison can bind consent to this root. */
    val candidateGroupId: String get() = evidence.proof.anchor.groupId
    val certificates: List<IosGroupAdmissionCertificate>
        get() = evidence.certificates.map(::IosGroupAdmissionCertificate)
    val maximumDerBytes: Int get() = GroupAdmissionCertificate.MAX_DER_BYTES

    /**
     * Replaces only an existing issuer's public certificate with DER bound by the OS to TLS.
     * Syntax/coverage remain shared; this does NOT authenticate DER or change the proof.
     */
    @Throws(Exception::class)
    fun withIssuerCertificate(identity: String, der: String): IosGroupAdmissionEvidence {
        val certificates = evidence.certificates
        require(certificates.any { it.identity == identity }) { "Unknown evidence issuer" }
        val replacement = GroupAdmissionCertificate(identity, der)
        return IosGroupAdmissionEvidence(
            GroupAdmissionEvidence(
                proof = evidence.proof,
                certificates = certificates.map { if (it.identity == identity) replacement else it },
            ),
        )
    }

    /** Encoding only, not a completed OS write, signature check or ownership transfer. */
    @Throws(Exception::class)
    fun framedBytes(): ByteArray = GroupAdmissionEvidenceFraming.encode(evidence)

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
