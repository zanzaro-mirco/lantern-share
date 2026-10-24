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
        let verifier = CertificateVerifier(maximumDerBytes: Int(snapshot.maximumDerBytes), now: now)
        do {
            let result = try snapshot.inspect(currentIdentityId: currentIdentityID,
                verifyCertificateSignature: verifier.verify)
            if let failure = verifier.failure { throw failure }
            return result
        } catch { throw verifier.failure ?? error }
    }

    /// Same verifier for startup/reload and creation readback. No journal promotion or write.
    /// Called by BonjourProbe on its serial non-UI store/identity queue.
    static func loadLocalGroup(
        _ controller: IosLocalGroupController, identityID: String, persistence: IosPersistence,
        afterCreation: Bool = false, now: Date = Date()
    ) throws {
        let verifier = CertificateVerifier(maximumDerBytes: Int(controller.maximumDerBytes), now: now)
        let verify: (IosGroupAdmissionCertificate, KotlinByteArray, String) -> KotlinBoolean? = { supplied, bytes, signature in
            let result = verifier.verify(supplied, bytes, signature)
            // Stop Kotlin before publishing a state; preserve the original Swift error below.
            return verifier.failure == nil ? result : nil
        }
        do {
            if afterCreation {
                try controller.createdVerified(identityId: identityID, persistence: persistence,
                    verifyCertificateSignature: verify)
            } else {
                try controller.loadedVerified(identityId: identityID, persistence: persistence,
                    verifyCertificateSignature: verify)
            }
        } catch { throw verifier.failure ?? error }
    }

    final class CertificateVerifier {
        private var certificates: [String: SecCertificate] = [:]
        private let maximumDerBytes: Int
        private let now: Date
        private(set) var failure: Error?

        init(maximumDerBytes: Int, now: Date) {
            self.maximumDerBytes = maximumDerBytes
            self.now = now
        }

        func verify(_ supplied: IosGroupAdmissionCertificate, _ bytes: KotlinByteArray, _ signature: String) -> KotlinBoolean {
            do {
                let certificate: SecCertificate
                if let cached = certificates[supplied.identity] {
                    guard (SecCertificateCopyData(cached) as Data).base64EncodedString() == supplied.der else {
                        throw PublicCertificateError.invalid
                    }
                    certificate = cached
                } else {
                    guard let der = Data(base64Encoded: supplied.der),
                          !der.isEmpty, der.count <= maximumDerBytes else {
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
                if failure == nil { failure = error }
                return KotlinBoolean(bool: false)
            }
        }
    }
}
