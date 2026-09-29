import Foundation
import Network
import Security
import X509

public enum TransportError: Error, LocalizedError {
    case invalidPin
    case identityUnavailable

    public var errorDescription: String? {
        switch self {
        case .invalidPin: return "Pin del dispositivo remoto non valido."
        case .identityUnavailable: return "Identità TLS locale non disponibile."
        }
    }
}

/// Creates mutually authenticated TLS 1.3 connections. Pairing decides which pins are allowed;
/// the caller owns and must cancel every returned listener and connection.
public final class AppleTLSTransport {
    public typealias AllowedPeerIDs = () -> Set<String>

    private let identity: AppleIdentity
    private let verificationQueue: DispatchQueue
    private let certificateLock = NSLock()
    private var peerCertificates: [String: SecCertificate] = [:]

    public init(identity: AppleIdentity, verificationQueue: DispatchQueue? = nil) {
        self.identity = identity
        self.verificationQueue = verificationQueue ?? DispatchQueue(label: "dev.lantern.poc.tls-verification")
    }

    public func listen(
        port: NWEndpoint.Port = .any,
        allowedPeerIDs: @escaping AllowedPeerIDs
    ) throws -> NWListener {
        try NWListener(using: try parameters(allowedPeerIDs: allowedPeerIDs), on: port)
    }

    public func connect(
        host: NWEndpoint.Host,
        port: NWEndpoint.Port,
        expectedPeerID: String
    ) throws -> NWConnection {
        guard Self.isPin(expectedPeerID) else { throw TransportError.invalidPin }
        return NWConnection(
            host: host,
            port: port,
            using: try parameters(allowedPeerIDs: { [expectedPeerID] })
        )
    }

    public func connect(endpoint: NWEndpoint, expectedPeerID: String) throws -> NWConnection {
        guard Self.isPin(expectedPeerID) else { throw TransportError.invalidPin }
        return NWConnection(to: endpoint, using: try parameters(allowedPeerIDs: { [expectedPeerID] }))
    }

    public func certificate(forPeerID peerID: String) -> SecCertificate? {
        certificateLock.lock()
        defer { certificateLock.unlock() }
        return peerCertificates[peerID]
    }

    private func parameters(allowedPeerIDs: @escaping AllowedPeerIDs) throws -> NWParameters {
        let tls = NWProtocolTLS.Options()
        guard let localIdentity = sec_identity_create(identity.tlsIdentity) else {
            throw TransportError.identityUnavailable
        }
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_local_identity(options, localIdentity)
        sec_protocol_options_set_peer_authentication_required(options, true)
        sec_protocol_options_set_verify_block(options, { _, trust, complete in
            let pins = allowedPeerIDs()
            guard !pins.isEmpty, pins.allSatisfy(Self.isPin) else {
                complete(false)
                return
            }
            let nativeTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            guard let chain = SecTrustCopyCertificateChain(nativeTrust) as? [SecCertificate],
                  let certificate = chain.first else {
                complete(false)
                return
            }
            let accepted = Self.accepts(certificate: certificate, allowedPeerIDs: pins)
            if accepted {
                let pin = AppleIdentity.fingerprint(certificate)
                self.certificateLock.lock()
                self.peerCertificates[pin] = certificate
                self.certificateLock.unlock()
            }
            complete(accepted)
        }, verificationQueue)

        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.includePeerToPeer = false
        return parameters
    }

    static func accepts(certificate: SecCertificate, allowedPeerIDs: Set<String>, now: Date = Date()) -> Bool {
        let pin = AppleIdentity.fingerprint(certificate)
        guard let key = SecCertificateCopyKey(certificate) else { return false }
        guard let rawAttributes = SecKeyCopyAttributes(key) else { return false }
        let attributes = rawAttributes as NSDictionary
        guard (attributes[kSecAttrKeyType] as? String) == (kSecAttrKeyTypeECSECPrimeRandom as String),
              (attributes[kSecAttrKeySizeInBits] as? NSNumber)?.intValue == 256 else { return false }
        guard allowedPeerIDs.contains(pin),
              let parsed = try? Certificate(certificate),
              parsed.notValidBefore <= now, now <= parsed.notValidAfter,
              parsed.signatureAlgorithm == .ecdsaWithSHA256,
              parsed.subject == parsed.issuer,
              parsed.publicKey.isValidSignature(parsed.signature, for: parsed) else { return false }
        return true
    }

    private static func isPin(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { "0123456789abcdef".contains($0) }
    }
}
