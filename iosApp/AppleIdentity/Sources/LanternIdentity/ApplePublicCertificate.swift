import Foundation
import Security
import SwiftASN1

public enum PublicCertificateError: Error, LocalizedError {
    case invalid

    public var errorDescription: String? { "Invalid group admission certificate" }
}

/// OS parsing only, not trust. Callers must bound untrusted DER before calling this adapter.
/// Validity dates, curve, self-signature and chain signatures require a separate verifier.
public enum ApplePublicCertificate {
    public static func decode(der: Data, expectedID: String) throws -> SecCertificate {
        // Parse the original bytes, not Security's possibly normalized/truncated representation.
        // The pinned ASN1 parser consumes exactly one complete DER object (no PEM/tail).
        // Security then parses X.509; this path does not validate the public key or signatures.
        do {
            _ = try DER.parse(Array(der))
        } catch is ASN1Error {
            throw PublicCertificateError.invalid
        }
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData),
              (SecCertificateCopyData(certificate) as Data) == der,
              AppleIdentity.fingerprint(certificate) == expectedID else {
            throw PublicCertificateError.invalid
        }
        return certificate
    }

    /// The shared core supplies canonical bytes/Base64 and an independently expected issuer pin.
    /// Reuse the existing Apple certificate policy: time validity, P-256 and SHA-256 self-signature.
    /// A successful signature is not membership, a confirmation or durable trust.
    public static func verifySignature(
        certificate: SecCertificate, expectedID: String, message: Data, signature: String, now: Date = Date()
    ) -> Bool {
        guard AppleTLSTransport.accepts(certificate: certificate, allowedPeerIDs: [expectedID], now: now) else { return false }
        return AppleIdentity.verify(certificate: certificate, message: message, signature: signature)
    }
}
