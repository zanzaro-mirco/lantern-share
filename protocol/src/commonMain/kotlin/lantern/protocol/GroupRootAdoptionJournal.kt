package lantern.protocol

/**
 * Untrusted recovery material, NOT membership, verified signatures or permission to commit.
 * The local participant is the candidate member; the remote one issued the final admission.
 * Certificate encodings are only syntactically checked. An OS adapter must verify DER/pins,
 * the complete chain and BOTH directional signatures before a future recovery policy runs.
 * No monotonic deadline, socket ownership or live consent can be restored from this record.
 */
class GroupRootAdoptionJournal(
    val evidence: GroupAdmissionEvidence,
    localOffer: ProtocolHandshakeParticipant,
    remoteOffer: ProtocolHandshakeParticipant,
    val memberCertificate: GroupAdmissionCertificate,
    val localConfirmation: GroupAdmissionConfirmation,
    val remoteConfirmation: GroupAdmissionConfirmation,
) {
    private val localContent = copyOffer(localOffer)
    private val remoteContent = copyOffer(remoteOffer)
    val localOffer: ProtocolHandshakeParticipant get() = copyOffer(localContent)
    val remoteOffer: ProtocolHandshakeParticipant get() = copyOffer(remoteContent)

    init {
        val finalClaim = evidence.proof.admissions.last().claim
        require(localContent.identity == finalClaim.memberId && remoteContent.identity == finalClaim.issuerId) {
            "Journal offers do not match admission roles"
        }
        require(memberCertificate.identity == localContent.identity) { "Journal member certificate mismatch" }
        require(localConfirmation.sender == localContent.identity && localConfirmation.recipient == remoteContent.identity &&
            remoteConfirmation.sender == remoteContent.identity && remoteConfirmation.recipient == localContent.identity
        ) { "Journal confirmations do not match offer directions" }
        // Also rejects incompatible offers; this is context construction, not signature verification.
        comparisonContext()
    }

    /** Reconstructed signed context, not an attempt-owned UI ticket or an independently trusted root. */
    fun comparisonContext(): GroupAdmissionConfirmationContext = GroupAdmissionConfirmationContext(
        remoteContent, localContent, evidence.proof.anchor, evidence.proof,
    )

    companion object {
        /**
         * Captures the exact released draft, never acknowledges persistence. The caller supplies
         * certificates from the authenticated connection (endpoint DER overrides received data),
         * retires its old owner, and preserves lifecycle separately. This method checks binding,
         * not liveness, certificate validity, signatures or durable/distributed commit.
         */
        fun fromDraft(
            draft: GroupRootAdoptionDraft,
            evidence: GroupAdmissionEvidence,
            offers: ProtocolHandshakeOffers,
            memberCertificate: GroupAdmissionCertificate,
        ): GroupRootAdoptionJournal {
            require(GroupAdmissionProofCodec.encode(draft.proof).contentEquals(GroupAdmissionProofCodec.encode(evidence.proof))) {
                "Journal evidence does not match released proof"
            }
            require(draft.memberIdentity == offers.local.identity) { "Journal local member mismatch" }
            val journal = GroupRootAdoptionJournal(evidence, offers.local, offers.remote, memberCertificate,
                draft.confirmations.local, draft.confirmations.remote)
            require(journal.comparisonContext().comparisonBytes().contentEquals(draft.comparisonBytes())) {
                "Journal offers do not match released comparison"
            }
            return journal
        }

        private fun copyOffer(value: ProtocolHandshakeParticipant) =
            ProtocolHandshakeParticipant(value.identity, value.nonce, value.capabilities)
    }
}
