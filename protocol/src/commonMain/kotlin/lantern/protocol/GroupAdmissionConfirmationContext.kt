package lantern.protocol

import lantern.domain.GroupTrustAnchor

/**
 * Frozen comparison context, NOT verified membership or a user confirmation.
 * Participants must be the TLS-bound compatible bootstrap offers with fresh OS-generated nonces.
 * The expected anchor comes from independent local context, never merely from `proof.anchor`.
 */
class GroupAdmissionConfirmationContext(
    issuer: ProtocolHandshakeParticipant,
    member: ProtocolHandshakeParticipant,
    expectedAnchor: GroupTrustAnchor,
    proof: GroupAdmissionProof,
) {
    val issuerIdentity: String = issuer.identity
    val memberIdentity: String = member.identity
    internal val admissionProof = proof
    internal val anchor = expectedAnchor
    private val comparisonContent: ByteArray

    init {
        require(issuerIdentity != memberIdentity) { "Confirmation needs distinct participants" }
        require(proof.anchor == expectedAnchor) { "Confirmation anchor mismatch" }
        require(ProtocolNegotiation.negotiate(issuer.capabilities, member.capabilities) is ProtocolNegotiationResult.Compatible) {
            "Confirmation needs compatible bootstrap offers"
        }
        val path = proof.admissions
        require(path.last().claim.issuerId == issuerIdentity && path.last().claim.memberId == memberIdentity) {
            "Confirmation participants must match the final admission"
        }
        // Encoding normalizes accepted JSON spellings, preserving every supplied signature and path order.
        comparisonContent = fields(listOf(
            "lantern-group-admission-confirm-1",
            issuerIdentity,
            memberIdentity,
            ProtocolHandshakeTranscript.bytes(issuer, member).decodeToString(),
            GroupAdmissionProofCodec.encode(proof).decodeToString(),
        ))
    }

    /** Hash these exact bytes with OS SHA-256 for the full comparison code shown on both devices. */
    fun comparisonBytes(): ByteArray = comparisonContent.copyOf()

    /** Directional OS signature after explicit confirmation of this full comparison, not old APPROVE. */
    fun approvalBytes(senderIdentity: String): ByteArray {
        require(senderIdentity == issuerIdentity || senderIdentity == memberIdentity) { "Unknown confirmation sender" }
        val recipient = if (senderIdentity == issuerIdentity) memberIdentity else issuerIdentity
        return fields(listOf(
            "lantern-group-admission-confirm-approve-1", senderIdentity, recipient,
            comparisonContent.decodeToString(),
        ))
    }

    private fun fields(values: List<String>) = values.joinToString("") {
        "${it.encodeToByteArray().size}:$it"
    }.encodeToByteArray()
}
