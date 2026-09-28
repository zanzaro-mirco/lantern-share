import CryptoKit
import Foundation
import Security
import X509

public enum IdentityError: Error, LocalizedError {
    case keychain(OSStatus)
    case inconsistent
    case cryptography

    public var errorDescription: String? {
        switch self {
        case .keychain(let status): return "Accesso Keychain non riuscito (\(status))."
        case .inconsistent: return "Identità incompleta o incoerente. Nessuna nuova identità è stata creata."
        case .cryptography: return "Verifica crittografica dell'identità non riuscita."
        }
    }
}

public final class AppleIdentity {
    public let id: String
    public let certificate: SecCertificate
    public let tlsIdentity: SecIdentity
    private let privateKey: SecKey

    internal init(key: SecKey, certificate: SecCertificate, identity: SecIdentity, expectedID: String) throws {
        let parsed = try Certificate(certificate)
        let now = Date()
        guard parsed.notValidBefore <= now, now <= parsed.notValidAfter,
              parsed.signatureAlgorithm == .ecdsaWithSHA256,
              parsed.subject == parsed.issuer,
              parsed.publicKey.isValidSignature(parsed.signature, for: parsed),
              Self.fingerprint(certificate) == expectedID else { throw IdentityError.inconsistent }
        self.id = expectedID
        self.certificate = certificate
        self.tlsIdentity = identity
        self.privateKey = key
        let challenge = Data(UUID().uuidString.utf8)
        guard Self.verify(certificate: certificate, message: challenge, signature: try sign(challenge)) else {
            throw IdentityError.cryptography
        }
    }

    /// SHA256withECDSA, DER signature in Base64, matching Lantern wire v0.
    public func sign(_ message: Data) throws -> String {
        var error: Unmanaged<CFError>?
        guard let result = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) else {
            throw error?.takeRetainedValue() as Error? ?? IdentityError.cryptography
        }
        return (result as Data).base64EncodedString()
    }

    public static func verify(certificate: SecCertificate, message: Data, signature: String) -> Bool {
        guard let signatureData = Data(base64Encoded: signature), let key = SecCertificateCopyKey(certificate) else { return false }
        return SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, signatureData as CFData, nil)
    }

    public static func fingerprint(_ certificate: SecCertificate) -> String {
        SHA256.hash(data: SecCertificateCopyData(certificate) as Data).map { String(format: "%02x", $0) }.joined()
    }
}
