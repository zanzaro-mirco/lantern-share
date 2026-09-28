import Foundation
import Security
import X509

/// App-owned Keychain records. Calls are serialized even across store objects.
public final class AppleIdentityStore {
    private static let lock = NSLock()
    private let namespace: String
    private var keyTag: Data { Data("\(namespace).key".utf8) }
    private var certificateLabel: String { "\(namespace).certificate" }

    public init(namespace: String = "dev.lantern.poc.identity.v1") { self.namespace = namespace }

    public func open() throws -> AppleIdentity {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        let key = try findKey()
        let certificate = try findCertificate()
        let pin = try findPin()
        if key == nil && certificate == nil && pin == nil {
            try create()
        } else if key == nil || certificate == nil || pin == nil {
            throw IdentityError.inconsistent
        }
        guard let loadedKey = try findKey(), let loadedCertificate = try findCertificate(), let loadedPin = try findPin() else {
            throw IdentityError.inconsistent
        }
        return try AppleIdentity(key: loadedKey, certificate: loadedCertificate,
                                 identity: findIdentity(certificate: loadedCertificate), expectedID: loadedPin)
    }

    private func create() throws {
        var error: Unmanaged<CFError>?
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecAttrSynchronizable as String: false,
            ],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error?.takeRetainedValue() as Error? ?? IdentityError.cryptography
        }
        // An interrupted creation leaves partial records, which fail closed on next open.
        let signingKey = try Certificate.PrivateKey(key)
        let name = try DistinguishedName { CommonName("Lantern") }
        var serial = [UInt8](repeating: 0, count: 16)
        try check(SecRandomCopyBytes(kSecRandomDefault, serial.count, &serial))
        let now = Date()
        let certificate = try Certificate(
            version: .v3, serialNumber: .init(bytes: serial), publicKey: signingKey.publicKey,
            notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(315_360_000),
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {}, issuerPrivateKey: signingKey
        )
        let native = try SecCertificate.makeWithCertificate(certificate)
        try check(SecItemAdd([
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certificateLabel,
            kSecValueRef as String: native,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
        ] as CFDictionary, nil))
        try check(SecItemAdd([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: namespace,
            kSecAttrAccount as String: "certificate-pin",
            kSecValueData as String: Data(AppleIdentity.fingerprint(native).utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
        ] as CFDictionary, nil))
    }

    private func findKey() throws -> SecKey? {
        let value = try copy([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: keyTag,
            kSecReturnRef as String: true,
        ])
        guard let value else { return nil }
        guard CFGetTypeID(value) == SecKeyGetTypeID() else { throw IdentityError.inconsistent }
        return (value as! SecKey)
    }

    private func findCertificate() throws -> SecCertificate? {
        let value = try copy([
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certificateLabel,
            kSecReturnRef as String: true,
        ])
        guard let value else { return nil }
        guard CFGetTypeID(value) == SecCertificateGetTypeID() else { throw IdentityError.inconsistent }
        return (value as! SecCertificate)
    }

    private func findPin() throws -> String? {
        guard let value = try copy([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: namespace,
            kSecAttrAccount as String: "certificate-pin",
            kSecReturnData as String: true,
        ]) else { return nil }
        guard let data = value as? Data, let pin = String(data: data, encoding: .utf8),
              pin.count == 64, pin.allSatisfy({ "0123456789abcdef".contains($0) }) else { throw IdentityError.inconsistent }
        return pin
    }

    private func findIdentity(certificate: SecCertificate) throws -> SecIdentity {
        guard let value = try copy([
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: certificateLabel,
            kSecReturnRef as String: true,
        ]), CFGetTypeID(value) == SecIdentityGetTypeID() else { throw IdentityError.inconsistent }
        let identity = value as! SecIdentity
        var identityCertificate: SecCertificate?
        try check(SecIdentityCopyCertificate(identity, &identityCertificate))
        guard let identityCertificate,
              SecCertificateCopyData(identityCertificate) as Data == SecCertificateCopyData(certificate) as Data else {
            throw IdentityError.inconsistent
        }
        return identity
    }

    private func copy(_ query: [String: Any]) throws -> CFTypeRef? {
        var query = query
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecAttrSynchronizable as String] = false
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        try check(status)
        return value
    }

    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw IdentityError.keychain(status) }
    }
}
