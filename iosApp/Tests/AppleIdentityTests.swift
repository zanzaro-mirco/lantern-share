import Foundation
import Security
import XCTest
import LanternIdentity

final class AppleIdentityTests: XCTestCase {
    private var namespace: String!

    override func setUp() {
        super.setUp()
        namespace = "dev.lantern.tests.\(UUID().uuidString)"
    }

    override func tearDown() {
        // Only this test's random namespace; never remove the app identity or unrelated keys.
        for query in [keyQuery, certificateQuery, pinQuery] {
            let status = SecItemDelete(query as CFDictionary)
            XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
        }
        super.tearDown()
    }

    private var keyQuery: [String: Any] {
        [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: Data("\(namespace!).key".utf8)]
    }
    private var certificateQuery: [String: Any] {
        [kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: "\(namespace!).certificate"]
    }
    private var pinQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: namespace!, kSecAttrAccount as String: "certificate-pin"]
    }

    func testReopenKeepsCertificateAndCanSignWithTLSIdentity() throws {
        let first = try AppleIdentityStore(namespace: namespace).open()
        let reopened = try AppleIdentityStore(namespace: namespace).open()
        XCTAssertEqual(first.id, reopened.id)
        XCTAssertEqual(SecCertificateCopyData(first.certificate) as Data, SecCertificateCopyData(reopened.certificate) as Data)
        let message = Data("Lantern Unicode: caffè ☕".utf8)
        let signature = try reopened.sign(message)
        XCTAssertTrue(AppleIdentity.verify(certificate: first.certificate, message: message, signature: signature))
        XCTAssertFalse(AppleIdentity.verify(certificate: first.certificate, message: Data("alterato".utf8), signature: signature))
        var tlsKey: SecKey?
        XCTAssertEqual(SecIdentityCopyPrivateKey(reopened.tlsIdentity, &tlsKey), errSecSuccess)
        let actualTLSKey = try XCTUnwrap(tlsKey)
        let tlsSignature = try XCTUnwrap(SecKeyCreateSignature(actualTLSKey, .ecdsaSignatureMessageX962SHA256, message as CFData, nil))
        XCTAssertTrue(AppleIdentity.verify(certificate: first.certificate, message: message, signature: (tlsSignature as Data).base64EncodedString()))
    }

    func testMissingPrivateKeyDoesNotRotateIdentity() throws {
        let original = try AppleIdentityStore(namespace: namespace).open()
        XCTAssertEqual(SecItemDelete(keyQuery as CFDictionary), errSecSuccess)
        XCTAssertThrowsError(try AppleIdentityStore(namespace: namespace).open())
        var query = certificateQuery
        query[kSecReturnRef as String] = true
        var value: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &value), errSecSuccess)
        XCTAssertEqual(AppleIdentity.fingerprint(value as! SecCertificate), original.id)
    }

    func testMissingCertificateDoesNotRotateIdentity() throws {
        _ = try AppleIdentityStore(namespace: namespace).open()
        XCTAssertEqual(SecItemDelete(certificateQuery as CFDictionary), errSecSuccess)
        XCTAssertThrowsError(try AppleIdentityStore(namespace: namespace).open())
    }

    func testChangedPinIsRejected() throws {
        _ = try AppleIdentityStore(namespace: namespace).open()
        XCTAssertEqual(SecItemUpdate(pinQuery as CFDictionary, [kSecValueData as String: Data(String(repeating: "0", count: 64).utf8)] as CFDictionary), errSecSuccess)
        XCTAssertThrowsError(try AppleIdentityStore(namespace: namespace).open())
    }

    func testProtectionIsDeviceOnlyAndRequiresUnlock() throws {
        _ = try AppleIdentityStore(namespace: namespace).open()
        for original in [keyQuery, pinQuery] {
            var query = original
            query[kSecReturnAttributes as String] = true
            var result: CFTypeRef?
            XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &result), errSecSuccess)
            let attributes = try XCTUnwrap(result as? [String: Any])
            XCTAssertEqual(attributes[kSecAttrAccessible as String] as? String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
            XCTAssertNotEqual(attributes[kSecAttrSynchronizable as String] as? Bool, true)
        }
    }
}
