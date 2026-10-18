import CryptoKit
import Foundation
import Security
import XCTest
import LanternIdentity
import LanternUI
@testable import Lantern

/// Parsing/signature/boundary tests, not group membership, TLS handover or durable trust tests.
final class GroupAdmissionEvidenceCertificatesTests: XCTestCase {
    private var namespaces: [String] = []
    private let group = String(repeating: "c", count: 64)
    private let member = String(repeating: "b", count: 64)

    override func tearDown() {
        for namespace in namespaces {
            let queries: [[String: Any]] = [
                [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: Data("\(namespace).key".utf8)],
                [kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: "\(namespace).certificate"],
                [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: namespace, kSecAttrAccount as String: "certificate-pin"],
            ]
            for query in queries {
                let status = SecItemDelete(query as CFDictionary)
                XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
            }
        }
        namespaces.removeAll()
        super.tearDown()
    }

    func testExactPublicCertificatesSurviveKotlinCodecAndAppleDecoder() throws {
        let founder = try identity()
        let issuer = try identity()
        let evidence = try decode(payload(
            founder: founder.id,
            path: [(founder.id, issuer.id), (issuer.id, member)],
            certificates: [(issuer.id, der(issuer)), (founder.id, der(founder))]
        ))
        XCTAssertEqual(evidence.maximumDerBytes, 4096)
        let decoded = try GroupAdmissionEvidenceCertificates.decode(evidence)
        XCTAssertEqual(Set(decoded.keys), Set([founder.id, issuer.id]))
        XCTAssertEqual(SecCertificateCopyData(try XCTUnwrap(decoded[founder.id])) as Data, der(founder))
        XCTAssertEqual(SecCertificateCopyData(try XCTUnwrap(decoded[issuer.id])) as Data, der(issuer))
        XCTAssertNil(decoded[member]) // Final member is not a proof issuer.
        let challenge = Data("certificato pubblico: caffè ☕".utf8)
        XCTAssertTrue(AppleIdentity.verify(certificate: try XCTUnwrap(decoded[issuer.id]), message: challenge,
                                           signature: try issuer.sign(challenge)))
        // A modified Swift collection cannot mutate the Kotlin snapshot.
        var view = evidence.certificates
        view.removeAll()
        XCTAssertEqual(evidence.certificates.count, 2)
        XCTAssertEqual(try GroupAdmissionEvidenceCertificates.decode(evidence).count, 2)
        // The shared binding helper is not a certificate verifier and never changes other issuers.
        let substituted = try evidence.withIssuerCertificate(identity: issuer.id, der: der(founder).base64EncodedString())
        XCTAssertThrowsError(try GroupAdmissionEvidenceCertificates.decode(substituted))
        let rebound = try substituted.withIssuerCertificate(identity: issuer.id, der: der(issuer).base64EncodedString())
        let reboundCertificates = try GroupAdmissionEvidenceCertificates.decode(rebound)
        XCTAssertEqual(SecCertificateCopyData(try XCTUnwrap(reboundCertificates[founder.id])) as Data, der(founder))
        XCTAssertEqual(SecCertificateCopyData(try XCTUnwrap(reboundCertificates[issuer.id])) as Data, der(issuer))
    }

    func testAdvertisedPinCannotSubstituteAnotherCertificate() throws {
        let founder = try identity()
        let replacement = try identity()
        try assertInvalidCertificate(founder: founder.id, der: der(replacement))
    }

    func testIdentityIsExactCertificateNotJustItsPublicKey() throws {
        let founder = try identity()
        var altered = der(founder)
        altered[altered.count - 1] ^= 1 // Keep ASN.1 structure/key, invalidate certificate signature.
        let alteredID = fingerprint(altered)
        XCTAssertNotEqual(alteredID, founder.id)
        let parsed = try ApplePublicCertificate.decode(der: altered, expectedID: alteredID)
        let originalKey = try XCTUnwrap(SecCertificateCopyKey(founder.certificate))
        let alteredKey = try XCTUnwrap(SecCertificateCopyKey(parsed))
        let originalBytes = try XCTUnwrap(SecKeyCopyExternalRepresentation(originalKey, nil)) as Data
        let alteredBytes = try XCTUnwrap(SecKeyCopyExternalRepresentation(alteredKey, nil)) as Data
        XCTAssertEqual(originalBytes, alteredBytes)
        try assertInvalidCertificate(founder: founder.id, der: altered)
        // Parsing with the matching DER pin intentionally does not attest the self-signature.
        XCTAssertEqual(try GroupAdmissionEvidenceCertificates.decode(decode(payload(
            founder: alteredID, path: [(alteredID, member)], certificates: [(alteredID, altered)]
        ))).count, 1)
    }

    func testTruncationTailAndConcatenationFailEvenWithMatchingByteHash() throws {
        let founder = try identity()
        let original = der(founder)
        let malformed = [Data([0]), Data(original.dropLast()), original + Data([0]), original + original]
        for value in malformed {
            // A matching hash must not make malformed DER acceptable.
            try assertInvalidCertificate(founder: fingerprint(value), der: value)
        }
    }

    func testPemIsNotAnAlternativeToExactDer() throws {
        let founder = try identity()
        let pem = Data(("-----BEGIN CERTIFICATE-----\n" + der(founder).base64EncodedString()
                        + "\n-----END CERTIFICATE-----").utf8)
        try assertInvalidCertificate(founder: fingerprint(pem), der: pem)
    }

    func testBerLengthAliasesAreNotAcceptedAsDerEvenWithMatchingHash() throws {
        let founder = try identity()
        let original = der(founder)
        XCTAssertEqual(original[0], 0x30)
        let lengthOctets = original[1] & 0x80 == 0 ? 0 : Int(original[1] & 0x7f)
        var nonminimal = original
        if lengthOctets == 0 {
            nonminimal.insert(0x81, at: 1)
        } else {
            nonminimal[1] += 1
            nonminimal.insert(0, at: 2)
        }
        let indefinite = Data([0x30, 0x80]) + Data(original.dropFirst(2 + lengthOctets)) + Data([0, 0])
        for value in [nonminimal, indefinite] {
            try assertInvalidCertificate(founder: fingerprint(value), der: value)
        }
    }

    func testInvalidSecondCertificateCannotReturnPartialMap() throws {
        let founder = try identity()
        let invalid = Data([0])
        let invalidID = fingerprint(invalid)
        let evidence = try decode(payload(
            founder: founder.id, path: [(founder.id, invalidID), (invalidID, member)],
            certificates: [(founder.id, der(founder)), (invalidID, invalid)]
        ))
        assertCertificateError { _ = try GroupAdmissionEvidenceCertificates.decode(evidence) }
    }

    func testKotlinFacadeRejectsMalformedJsonWithoutPeerDiagnostics() throws {
        let founder = String(repeating: "a", count: 64)
        let valid = try payload(founder: founder, path: [(founder, member)], certificates: [(founder, Data([0]))])
        let json = try XCTUnwrap(String(data: valid, encoding: .utf8))
        let unknown = Data(("{\"peer-secret\":\"do-not-log\"," + json.dropFirst()).utf8)
        let duplicate = Data(("{\"version\":1," + json.dropFirst()).utf8)
        for value in [Data(), Data([0xc0, 0xaf]), unknown, duplicate, Data(json.dropLast().utf8)] {
            assertEvidenceError(value)
        }
    }

    func testSharedCertificateCoverageAndBase64RulesApplyBeforeOsParsing() throws {
        let founder = String(repeating: "a", count: 64)
        let other = String(repeating: "d", count: 64)
        let valid = try payload(founder: founder, path: [(founder, member)], certificates: [(founder, Data([0]))])
        let json = try XCTUnwrap(String(data: valid, encoding: .utf8))
        for encoding in ["AB==", "AA=", "AA==\n", "", String(repeating: "A", count: 5468)] {
            let replacement = encoding.replacingOccurrences(of: "\n", with: "\\n")
            assertEvidenceError(Data(json.replacingOccurrences(of: "\"der\":\"AA==\"", with: "\"der\":\"\(replacement)\"").utf8))
        }
        let missing = try payload(founder: founder, path: [(founder, other), (other, member)], certificates: [(founder, Data([0]))])
        let duplicate = try payload(founder: founder, path: [(founder, member)], certificates: [(founder, Data([0])), (founder, Data([0]))])
        let extra = try payload(founder: founder, path: [(founder, member)], certificates: [(founder, Data([0])), (other, Data([0]))])
        let foreign = try payload(founder: founder, path: [(founder, member)], certificates: [(other, Data([0]))])
        for value in [missing, duplicate, extra, foreign] { assertEvidenceError(value) }
    }

    func testSharedPayloadAndDerLimitsArePreservedAtSwiftBoundary() throws {
        let founder = String(repeating: "a", count: 64)
        let maximumDer = Data(repeating: 0, count: 4096)
        let valid = try payload(founder: founder, path: [(founder, member)], certificates: [(founder, maximumDer)])
        let evidence = try decode(valid)
        XCTAssertEqual(evidence.certificates.count, 1) // Syntax only; not X.509.
        assertCertificateError { _ = try GroupAdmissionEvidenceCertificates.decode(evidence) }
        assertEvidenceError(try payload(founder: founder, path: [(founder, member)], certificates: [(founder, maximumDer + Data([0]))]))
        let maximum = Int(IosGroupAdmissionEvidence.companion.maximumPayloadBytes)
        XCTAssertEqual(maximum, 262144)
        let padded = valid + Data(repeating: 32, count: maximum - valid.count)
        XCTAssertEqual(try decode(padded).certificates.count, 1)
        assertEvidenceError(padded + Data([32]))
    }

    func testThirtyTwoIssuerLimitIsSharedAndDoesNotAuthorizeCertificates() throws {
        let ids = (0...32).map { String(format: "%064x", $0) }
        let path = (0..<32).map { (ids[$0], ids[$0 + 1]) }
        let entries = ids.prefix(32).map { ($0, Data([0])) }
        let evidence = try decode(payload(founder: ids[0], path: path, certificates: entries))
        XCTAssertEqual(evidence.certificates.count, 32)
        assertCertificateError { _ = try GroupAdmissionEvidenceCertificates.decode(evidence) }
        assertEvidenceError(try payload(founder: ids[0], path: path, certificates: entries + [(ids[32], Data([0]))]))
    }

    func testActualAppleSignaturesVerifyWholeDelegatedChainAgainstIndependentContext() throws {
        let founder = try identity()
        let issuer = try identity()
        let path = [(founder.id, issuer.id), (issuer.id, member)]
        let evidence = try decode(payload(
            founder: founder.id, path: path,
            certificates: [(issuer.id, der(issuer)), (founder.id, der(founder))],
            signatures: [try founder.sign(admissionBytes(issuer: founder.id, member: issuer.id)),
                         try issuer.sign(admissionBytes(issuer: issuer.id, member: member))]
        ))
        XCTAssertTrue(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: group, expectedFounder: founder.id, expectedMember: member
        ))
        XCTAssertFalse(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: String(repeating: "d", count: 64), expectedFounder: founder.id, expectedMember: member
        ))
        XCTAssertFalse(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: group, expectedFounder: issuer.id, expectedMember: member
        ))
        XCTAssertFalse(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: group, expectedFounder: founder.id, expectedMember: issuer.id
        ))
        // No confirmation, TLS channel, app membership or trust write occurs in this test.
    }

    func testSignatureAndCertificateValidityAreCheckedAgainNotCachedFromParsing() throws {
        let founder = try identity()
        let evidence = try decode(payload(
            founder: founder.id, path: [(founder.id, member)], certificates: [(founder.id, der(founder))],
            signatures: [try founder.sign(admissionBytes(issuer: founder.id, member: member))]
        ))
        for date in [Date.distantPast, Date.distantFuture] {
            XCTAssertFalse(try GroupAdmissionEvidenceCertificates.verifyChain(
                evidence, expectedGroup: group, expectedFounder: founder.id, expectedMember: member, now: date
            ))
        }
        XCTAssertTrue(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: group, expectedFounder: founder.id, expectedMember: member
        ))
        let badSignature = try decode(payload(
            founder: founder.id, path: [(founder.id, member)], certificates: [(founder.id, der(founder))],
            signatures: [try founder.sign(Data("wrong signed bytes".utf8))]
        ))
        XCTAssertFalse(try GroupAdmissionEvidenceCertificates.verifyChain(
            badSignature, expectedGroup: group, expectedFounder: founder.id, expectedMember: member
        ))
    }

    func testMatchingDerPinAndValidClaimSignatureDoNotBypassCertificateSelfSignature() throws {
        let founder = try identity()
        var altered = der(founder)
        altered[altered.count - 1] ^= 1
        let alteredID = fingerprint(altered)
        let evidence = try decode(payload(
            founder: alteredID, path: [(alteredID, member)], certificates: [(alteredID, altered)],
            signatures: [try founder.sign(admissionBytes(issuer: alteredID, member: member))]
        ))
        let certificate = try XCTUnwrap(GroupAdmissionEvidenceCertificates.decode(evidence)[alteredID])
        // The claim really is signed by the key in the certificate; its self-signature is invalid.
        XCTAssertTrue(AppleIdentity.verify(
            certificate: certificate, message: admissionBytes(issuer: alteredID, member: member),
            signature: try founder.sign(admissionBytes(issuer: alteredID, member: member))
        ))
        XCTAssertFalse(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: group, expectedFounder: alteredID, expectedMember: member
        ))
    }

    func testInvalidSecondSignatureCannotVerifyAValidPrefix() throws {
        let founder = try identity()
        let issuer = try identity()
        let evidence = try decode(payload(
            founder: founder.id, path: [(founder.id, issuer.id), (issuer.id, member)],
            certificates: [(founder.id, der(founder)), (issuer.id, der(issuer))],
            signatures: [try founder.sign(admissionBytes(issuer: founder.id, member: issuer.id)), "AA=="]
        ))
        XCTAssertFalse(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: group, expectedFounder: founder.id, expectedMember: member
        ))
    }

    func testJvmP256VectorMatchesCanonicalBytesAndVerifiesOnApple() throws {
        let vector = JvmGroupAdmissionVectors.p256
        let evidence = try decode(vectorPayload(vector))
        let bytes = try XCTUnwrap(Data(base64Encoded: vector.canonicalBytes))
        XCTAssertEqual(bytes, admissionBytes(issuer: vector.founder, member: member))
        let certificate = try XCTUnwrap(GroupAdmissionEvidenceCertificates.decode(evidence)[vector.founder])
        XCTAssertTrue(AppleIdentity.verify(certificate: certificate, message: bytes, signature: vector.signature))
        XCTAssertTrue(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: group, expectedFounder: vector.founder, expectedMember: member,
            now: JvmGroupAdmissionVectors.verificationDate
        ))
        // These are fixed public JVM vectors, not freshly generated Apple identities.
    }

    func testValidJvmSignaturesDoNotBypassCurveOrCertificateAlgorithmPolicy() throws {
        for vector in [JvmGroupAdmissionVectors.p384, JvmGroupAdmissionVectors.sha384] {
            let evidence = try decode(vectorPayload(vector))
            let certificate = try XCTUnwrap(GroupAdmissionEvidenceCertificates.decode(evidence)[vector.founder])
            let bytes = try XCTUnwrap(Data(base64Encoded: vector.canonicalBytes))
            XCTAssertEqual(bytes, admissionBytes(issuer: vector.founder, member: member))
            XCTAssertTrue(AppleIdentity.verify(certificate: certificate, message: bytes, signature: vector.signature))
            // A valid SHA-256 claim with the exact pinned key is insufficient: the certificate
            // itself must be P-256 and self-signed with ECDSA/SHA-256, not P-384 or SHA-384.
            XCTAssertFalse(try GroupAdmissionEvidenceCertificates.verifyChain(
                evidence, expectedGroup: group, expectedFounder: vector.founder, expectedMember: member,
                now: JvmGroupAdmissionVectors.verificationDate
            ))
        }
    }

    func testFacadeRejectsContextAndBrokenTopologyBeforeSwiftSignatureCallback() throws {
        let founder = String(repeating: "a", count: 64)
        let other = String(repeating: "d", count: 64)
        let evidence = try decode(payload(
            founder: founder, path: [(founder, member)], certificates: [(founder, Data([0]))]
        ))
        var calls = 0
        let verifier: (String, KotlinByteArray, String) -> KotlinBoolean = { _, _, _ in
            calls += 1
            return KotlinBoolean(bool: true) // Callback-count fixture, not production verification.
        }
        for (expectedGroup, expectedFounder, expectedMember) in [
            (other, founder, member), (group, other, member), (group, founder, other),
        ] {
            XCTAssertFalse(try evidence.verifyChain(
                expectedGroup: expectedGroup, expectedFounder: expectedFounder, expectedMember: expectedMember,
                verifyCertificateSignature: verifier
            ))
        }
        XCTAssertThrowsError(try evidence.verifyChain(
            expectedGroup: "invalid", expectedFounder: founder, expectedMember: member,
            verifyCertificateSignature: verifier
        ))
        let broken = try decode(payload(
            founder: founder, path: [(founder, member), (other, member)],
            certificates: [(founder, Data([0])), (other, Data([0]))]
        ))
        XCTAssertFalse(try broken.verifyChain(
            expectedGroup: group, expectedFounder: founder, expectedMember: member,
            verifyCertificateSignature: verifier
        ))
        XCTAssertEqual(calls, 0)
    }

    func testSwiftCallbackReceivesFreshCanonicalBytesOnEveryVerification() throws {
        let vector = JvmGroupAdmissionVectors.p256
        let evidence = try decode(vectorPayload(vector))
        let certificate = try XCTUnwrap(GroupAdmissionEvidenceCertificates.decode(evidence)[vector.founder])
        let canonical = try XCTUnwrap(Data(base64Encoded: vector.canonicalBytes))
        var calls = 0
        var retained: KotlinByteArray?
        for _ in 0..<2 {
            XCTAssertTrue(try evidence.verifyChain(
                expectedGroup: group, expectedFounder: vector.founder, expectedMember: member,
                verifyCertificateSignature: { issuer, bytes, signature in
                    calls += 1
                    let value = Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
                    XCTAssertEqual(issuer, vector.founder)
                    XCTAssertEqual(value, canonical)
                    XCTAssertEqual(signature, vector.signature)
                    retained = bytes
                    let valid = ApplePublicCertificate.verifySignature(
                        certificate: certificate, expectedID: issuer, message: value, signature: signature,
                        now: JvmGroupAdmissionVectors.verificationDate
                    )
                    bytes.set(index: 0, value: 0) // Only the caller-owned byte copy, never the proof.
                    return KotlinBoolean(bool: valid)
                }
            ))
        }
        XCTAssertEqual(calls, 2)
        XCTAssertEqual(try XCTUnwrap(retained).get(index: 0), 0)
        XCTAssertTrue(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: group, expectedFounder: vector.founder, expectedMember: member,
            now: JvmGroupAdmissionVectors.verificationDate
        ))
    }

    private func vectorPayload(_ vector: JvmGroupAdmissionVectors.Vector) throws -> Data {
        try payload(
            founder: vector.founder, path: [(vector.founder, member)],
            certificates: [(vector.founder, try XCTUnwrap(Data(base64Encoded: vector.der)))],
            signatures: [vector.signature]
        )
    }

    private func identity() throws -> AppleIdentity {
        let namespace = "dev.lantern.tests.evidence.\(UUID().uuidString)"
        namespaces.append(namespace) // Register cleanup even if creation fails partway through.
        return try AppleIdentityStore(namespace: namespace).open()
    }

    private func der(_ identity: AppleIdentity) -> Data { SecCertificateCopyData(identity.certificate) as Data }

    private func fingerprint(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    private func payload(
        founder: String, path: [(String, String)], certificates: [(String, Data)], signatures: [String]? = nil
    ) throws -> Data {
        // Test construction only. Production encoding/validation remains in Kotlin.
        if let signatures { XCTAssertEqual(signatures.count, path.count) }
        let admissions: [[String: Any]] = path.enumerated().map { index, entry in
            ["claim": ["version": 1, "group": group, "issuer": entry.0, "member": entry.1],
             "signature": signatures?[index] ?? "cHJvb2Y="]
        }
        let entries: [[String: Any]] = certificates.map { id, der in ["identity": id, "der": der.base64EncodedString()] }
        return try JSONSerialization.data(withJSONObject: [
            "version": 1, "type": "GROUP_EVIDENCE",
            "proof": ["version": 1, "anchor": ["group": group, "founder": founder], "admissions": admissions],
            "certificates": entries,
        ], options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private func admissionBytes(issuer: String, member: String) -> Data {
        // Independent test vector construction; production uses Kotlin's canonical byte contract.
        var bytes = Data()
        for value in ["lantern-group-admission-1", "1", group, issuer, member] {
            let field = Data(value.utf8)
            bytes.append(Data("\(field.count):".utf8))
            bytes.append(field)
        }
        return bytes
    }

    private func decode(_ payload: Data) throws -> IosGroupAdmissionEvidence {
        let bytes = KotlinByteArray(size: Int32(payload.count))
        for (index, byte) in payload.enumerated() { bytes.set(index: Int32(index), value: Int8(bitPattern: byte)) }
        return try IosGroupAdmissionEvidence.companion.decode(payload: bytes)
    }

    private func assertInvalidCertificate(founder: String, der: Data, file: StaticString = #filePath, line: UInt = #line) throws {
        let evidence = try decode(payload(founder: founder, path: [(founder, member)], certificates: [(founder, der)]))
        assertCertificateError(file: file, line: line) { _ = try GroupAdmissionEvidenceCertificates.decode(evidence) }
    }

    private func assertCertificateError(file: StaticString = #filePath, line: UInt = #line, _ operation: () throws -> Void) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            guard let failure = error as? PublicCertificateError, case .invalid = failure else {
                XCTFail("Unexpected error type", file: file, line: line)
                return
            }
            XCTAssertEqual(error.localizedDescription, "Invalid group admission certificate", file: file, line: line)
            XCTAssertNil((error as NSError).userInfo[NSUnderlyingErrorKey], file: file, line: line)
        }
    }

    private func assertEvidenceError(_ payload: Data, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try decode(payload), file: file, line: line) { error in
            XCTAssertFalse(error.localizedDescription.contains("peer-secret"), file: file, line: line)
            XCTAssertFalse(error.localizedDescription.contains("do-not-log"), file: file, line: line)
            XCTAssertTrue(error.localizedDescription.contains("Invalid group evidence"), file: file, line: line)
        }
    }
}
