package lantern.protocol

import lantern.domain.PendingGroupAdoption

/** Fixed diagnostic without peer-controlled parser contents or a nested parser cause. */
class InvalidGroupRootAdoptionJournalException : IllegalArgumentException("Invalid stored group adoption payload")

/** Historical material only. None of these results grants membership or permission to resume/commit. */
sealed interface GroupRootAdoptionJournalInspectionResult {
    data object HistoricalSignaturesValid : GroupRootAdoptionJournalInspectionResult
    data object LocalIdentityMismatch : GroupRootAdoptionJournalInspectionResult
    data object MetadataMismatch : GroupRootAdoptionJournalInspectionResult
    data class InvalidChain(val reason: GroupAdmissionChainResult) : GroupRootAdoptionJournalInspectionResult
    data object InvalidLocalConfirmation : GroupRootAdoptionJournalInspectionResult
    data object InvalidRemoteConfirmation : GroupRootAdoptionJournalInspectionResult
}

/** Read-only inspection of a snapshot, deliberately independent of repositories and live owners. */
object GroupRootAdoptionJournalInspection {
    /**
     * currentIdentityId comes from the OS, never from the record. The callback must check exact
     * DER/pin, current certificate validity, P-256 and self-signature before verifying each signature.
     * Decode errors (including unknown versions), OS errors and cancellation propagate: never absence.
     * The candidate anchor is used for internal consistency ONLY, not as independently trusted root.
     * No deadline/consent is restored. The attempt ID is opaque metadata, not authenticated by signatures.
     * The caller owns lifecycle/identity serialization and any later durable-group/recovery policy.
     */
    fun inspect(
        record: PendingGroupAdoption,
        currentIdentityId: String,
        verifySignature: (GroupAdmissionCertificate, ByteArray, String) -> Boolean,
    ): GroupRootAdoptionJournalInspectionResult {
        require(Wire.isFingerprint(currentIdentityId)) { "Invalid current identity" }
        val journal = decode(record)
        if (record.localIdentity != currentIdentityId) {
            return GroupRootAdoptionJournalInspectionResult.LocalIdentityMismatch
        }
        if (record.localIdentity != journal.localOffer.identity || record.peerIdentity != journal.remoteOffer.identity ||
            record.anchor != journal.evidence.proof.anchor
        ) return GroupRootAdoptionJournalInspectionResult.MetadataMismatch

        val certificates = journal.evidence.certificates.associateBy { it.identity }
        val chain = GroupAdmissionChainVerification.verify(
            journal.evidence.proof, record.anchor, record.localIdentity,
        ) { issuer, bytes, signature ->
            verifySignature(certificates.getValue(issuer), bytes, signature)
        }
        if (chain != GroupAdmissionChainResult.VerifiedChain) {
            return GroupRootAdoptionJournalInspectionResult.InvalidChain(chain)
        }
        val context = journal.comparisonContext()
        // Both directions are historical signatures, not TLS identity or current user confirmation.
        if (!verifySignature(journal.memberCertificate, context.approvalBytes(record.localIdentity),
                journal.localConfirmation.signature)) {
            return GroupRootAdoptionJournalInspectionResult.InvalidLocalConfirmation
        }
        if (!verifySignature(certificates.getValue(record.peerIdentity), context.approvalBytes(record.peerIdentity),
                journal.remoteConfirmation.signature)) {
            return GroupRootAdoptionJournalInspectionResult.InvalidRemoteConfirmation
        }
        return GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid
    }

    private fun decode(record: PendingGroupAdoption): GroupRootAdoptionJournal = try {
        GroupRootAdoptionJournalCodec.decode(record.payload())
    } catch (_: IllegalArgumentException) {
        throw InvalidGroupRootAdoptionJournalException()
    } catch (_: CharacterCodingException) {
        throw InvalidGroupRootAdoptionJournalException()
    }
}
