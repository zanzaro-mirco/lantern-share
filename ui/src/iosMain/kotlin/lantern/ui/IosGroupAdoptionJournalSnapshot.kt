package lantern.ui

import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupRootAdoptionJournalInspection
import lantern.protocol.GroupRootAdoptionJournalInspectionResult

enum class IosGroupAdoptionJournalStatus {
    HISTORICAL_SIGNATURES_VALID, LOCAL_IDENTITY_MISMATCH, METADATA_MISMATCH,
    INVALID_CHAIN, INVALID_LOCAL_CONFIRMATION, INVALID_REMOTE_CONFIRMATION,
}

/** Opaque immutable stored snapshot, never a live confirmation or recoverable commit ticket. */
class IosGroupAdoptionJournalSnapshot internal constructor(internal val record: PendingGroupAdoption) {
    val localIdentity: String get() = record.localIdentity
    val maximumDerBytes: Int get() = GroupAdmissionCertificate.MAX_DER_BYTES

    /**
     * Caller supplies the current OS identity and exact-DER OS verifier on its non-UI serial queue.
     * Exceptions propagate through the Swift boundary; no writes, cleanup or authorization occur.
     */
    @Throws(Exception::class)
    fun inspect(
        currentIdentityId: String,
        verifyCertificateSignature: (IosGroupAdmissionCertificate, ByteArray, String) -> Boolean,
    ): IosGroupAdoptionJournalStatus {
        val result = GroupRootAdoptionJournalInspection.inspect(record, currentIdentityId) { cert, bytes, signature ->
            verifyCertificateSignature(IosGroupAdmissionCertificate(cert), bytes, signature)
        }
        return when (result) {
            GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid -> IosGroupAdoptionJournalStatus.HISTORICAL_SIGNATURES_VALID
            GroupRootAdoptionJournalInspectionResult.LocalIdentityMismatch -> IosGroupAdoptionJournalStatus.LOCAL_IDENTITY_MISMATCH
            GroupRootAdoptionJournalInspectionResult.MetadataMismatch -> IosGroupAdoptionJournalStatus.METADATA_MISMATCH
            is GroupRootAdoptionJournalInspectionResult.InvalidChain -> IosGroupAdoptionJournalStatus.INVALID_CHAIN
            GroupRootAdoptionJournalInspectionResult.InvalidLocalConfirmation -> IosGroupAdoptionJournalStatus.INVALID_LOCAL_CONFIRMATION
            GroupRootAdoptionJournalInspectionResult.InvalidRemoteConfirmation -> IosGroupAdoptionJournalStatus.INVALID_REMOTE_CONFIRMATION
        }
    }

    companion object {
        /** Imports untrusted metadata/opaque bytes only, without parsing or saving them. */
        @Throws(Exception::class)
        fun fromStoredRecord(
            attemptId: String, localIdentity: String, peerIdentity: String,
            groupId: String, founderId: String, payload: ByteArray,
        ): IosGroupAdoptionJournalSnapshot = IosGroupAdoptionJournalSnapshot(PendingGroupAdoption(
            attemptId, localIdentity, peerIdentity, GroupTrustAnchor(groupId, founderId), payload,
        ))
    }
}
