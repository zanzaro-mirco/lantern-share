import Foundation
import Security
import LanternIdentity
import LanternUI

/// OS boundary only. Shared Kotlin checks authoritative membership, historical proof and
/// canonical new delegation. Caller rechecks the live owner and exact membership before use.
enum LocalGroupAdmission {
    static func prepare(identity: AppleIdentity, persistence: IosPersistence, memberID: String) throws -> IosGroupAdmissionEvidence {
        var signingFailure: Error?
        let verifier = GroupAdoptionJournalInspector.CertificateVerifier(
            maximumDerBytes: Int(IosLocalGroupAdmission.shared.maximumDerBytes), now: Date())
        do {
            return try IosLocalGroupAdmission.shared.prepare(
                persistence: persistence, identityId: identity.id, memberId: memberID,
                certificateDer: (SecCertificateCopyData(identity.certificate) as Data).base64EncodedString(),
                sign: { bytes in
                    do {
                        return try identity.sign(Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) }))
                    } catch { signingFailure = error; return nil }
                },
                verifyCertificateSignature: { certificate, bytes, signature in
                    let result = verifier.verify(certificate, bytes, signature)
                    // Abort Kotlin before signing/publication on an OS parsing/provider error.
                    return verifier.failure == nil ? result : nil
                })
        } catch { throw signingFailure ?? verifier.failure ?? error }
    }
}
