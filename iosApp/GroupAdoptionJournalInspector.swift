import Foundation
import Security
import LanternIdentity
import LanternUI

/// Historical inspection only: never restores consent, adopts a root or writes storage/Keychain.
/// Caller reads the snapshot and CURRENT identity from the OS on its non-UI serial lifecycle queue.
enum GroupAdoptionJournalInspector {
    static func inspect(
        _ snapshot: IosGroupAdoptionJournalSnapshot, currentIdentityID: String, now: Date = Date()
    ) throws -> IosGroupAdoptionJournalStatus {
        var certificates: [String: SecCertificate] = [:]
        var certificateFailure: Error?
        let result = try snapshot.inspect(currentIdentityId: currentIdentityID, verifyCertificateSignature: { supplied, bytes, signature in
            do {
                let certificate: SecCertificate
                if let cached = certificates[supplied.identity] {
                    certificate = cached
                } else {
                    guard let der = Data(base64Encoded: supplied.der),
                          !der.isEmpty, der.count <= Int(snapshot.maximumDerBytes) else {
                        throw PublicCertificateError.invalid
                    }
                    certificate = try ApplePublicCertificate.decode(der: der, expectedID: supplied.identity)
                    certificates[supplied.identity] = certificate
                }
                return KotlinBoolean(bool: ApplePublicCertificate.verifySignature(
                    certificate: certificate, expectedID: supplied.identity,
                    message: Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) }),
                    signature: signature, now: now
                ))
            } catch {
                // Kotlin callbacks cannot throw Swift errors. Preserve the original failure rather
                // than publishing the temporary false result as an ordinary invalid signature.
                certificateFailure = error
                return KotlinBoolean(bool: false)
            }
        })
        if let failure = certificateFailure { throw failure }
        return result
    }
}
