import Foundation
import Security
import LanternIdentity
import LanternUI

/// OS boundary only: shared Kotlin owns membership, canonical encoding and complete proof checks.
enum GroupMembership {
    static func prepare(identity: AppleIdentity, persistence: IosPersistence) throws -> IosGroupMembershipEvidence {
        try withVerifier { verify in
            try IosLocalGroupMembership.shared.prepare(persistence: persistence, identityId: identity.id,
                certificateDer: (SecCertificateCopyData(identity.certificate) as Data).base64EncodedString(),
                verifyCertificateSignature: verify)
        }
    }

    static func verify(_ evidence: IosGroupMembershipEvidence, anchor: IosLocalGroupAnchor, peerID: String) throws -> Bool {
        try withVerifier { verify in
            try evidence.verify(expectedGroup: anchor.groupId, expectedFounder: anchor.founderId,
                authenticatedPeerIdentity: peerID, verifyCertificateSignature: verify)
        }
    }

    private static func withVerifier<T>(
        _ operation: (@escaping (IosGroupAdmissionCertificate, KotlinByteArray, String) -> KotlinBoolean?) throws -> T
    ) throws -> T {
        let verifier = GroupAdoptionJournalInspector.CertificateVerifier(
            maximumDerBytes: Int(IosLocalGroupMembership.shared.maximumDerBytes), now: Date())
        let verify: (IosGroupAdmissionCertificate, KotlinByteArray, String) -> KotlinBoolean? = { cert, bytes, signature in
            let result = verifier.verify(cert, bytes, signature)
            return verifier.failure == nil ? result : nil
        }
        do { return try operation(verify) } catch { throw verifier.failure ?? error }
    }
}
