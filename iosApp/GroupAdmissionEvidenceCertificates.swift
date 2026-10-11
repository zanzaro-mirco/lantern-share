import Foundation
import Security
import LanternIdentity
import LanternUI

/// Untrusted public evidence only. Never writes Keychain/trust or adopts its received root.
/// The future TLS owner must prefer its actual endpoint certificates over received entries,
/// verify the whole chain against an independent anchor, and require both confirmations.
enum GroupAdmissionEvidenceCertificates {
    static func decode(_ evidence: IosGroupAdmissionEvidence) throws -> [String: SecCertificate] {
        var certificates: [String: SecCertificate] = [:]
        for supplied in evidence.certificates {
            // The Kotlin facade already checked canonical Base64, bounded count and coverage.
            guard let der = Data(base64Encoded: supplied.der),
                  !der.isEmpty, der.count <= Int(evidence.maximumDerBytes) else {
                throw PublicCertificateError.invalid
            }
            certificates[supplied.identity] = try ApplePublicCertificate.decode(der: der, expectedID: supplied.identity)
        }
        // No partially decoded map escapes if any certificate fails.
        return certificates
    }

    /// Offline verification only. Not a replacement for TLS endpoint binding, both user
    /// confirmations, current-attempt checks or a recoverable trust commit.
    static func verifyChain(
        _ evidence: IosGroupAdmissionEvidence,
        expectedGroup: String, expectedFounder: String, expectedMember: String,
        now: Date = Date()
    ) throws -> Bool {
        let certificates = try decode(evidence)
        return try evidence.verifyChain(
            expectedGroup: expectedGroup, expectedFounder: expectedFounder, expectedMember: expectedMember,
            verifyCertificateSignature: { issuer, bytes, signature in
                guard let certificate = certificates[issuer] else { return KotlinBoolean(bool: false) }
                return KotlinBoolean(bool: ApplePublicCertificate.verifySignature(
                    certificate: certificate, expectedID: issuer,
                    message: Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) }),
                    signature: signature, now: now
                ))
            }
        )
    }
}
