import Foundation
import XCTest
import LanternUI
@testable import Lantern

/// Fixed public JVM vectors; no current consent, connection or membership is reconstructed.
final class GroupAdoptionJournalInspectorTests: XCTestCase {
    private typealias V = JvmGroupConfirmationVectors

    func testWholeJournalWithJvmSignaturesUsesTheSharedContextAndAppleVerifier() throws {
        let snapshot = try snapshot()
        XCTAssertEqual(try inspect(snapshot).name, "HISTORICAL_SIGNATURES_VALID")
        XCTAssertEqual(try inspect(snapshot).name, "HISTORICAL_SIGNATURES_VALID")
    }

    func testCurrentIdentityAndMetadataAreNotTakenFromThePayload() throws {
        XCTAssertEqual(try GroupAdoptionJournalInspector.inspect(
            snapshot(), currentIdentityID: V.issuer, now: V.verificationDate
        ).name, "LOCAL_IDENTITY_MISMATCH")
        let mismatch = try snapshot(group: String(repeating: "d", count: 64), memberDer: "AA==")
        // Metadata failure must precede OS parsing of deliberately invalid DER.
        XCTAssertEqual(try inspect(mismatch).name, "METADATA_MISMATCH")
    }

    func testBothDirectionalSignaturesAndOriginalOffersAreRequired() throws {
        XCTAssertEqual(try inspect(snapshot(localSignature: V.issuerSignature)).name, "INVALID_LOCAL_CONFIRMATION")
        XCTAssertEqual(try inspect(snapshot(remoteSignature: V.memberSignature)).name, "INVALID_REMOTE_CONFIRMATION")
        XCTAssertEqual(try inspect(snapshot(memberNonce: "3")).name, "INVALID_LOCAL_CONFIRMATION")
        XCTAssertEqual(try inspect(snapshot(evidence: V.alternativeEvidence)).name, "INVALID_LOCAL_CONFIRMATION")
    }

    func testMalformedMemberDerRemainsAnErrorNotAnInvalidSignatureOrSuccess() throws {
        let memberDer = try XCTUnwrap(Data(base64Encoded: V.memberDer))
        for encoded in ["AA==", V.issuerDer, (memberDer + Data([0])).base64EncodedString(),
                        (memberDer + memberDer).base64EncodedString()] {
            let snapshot = try snapshot(memberDer: encoded)
            XCTAssertThrowsError(try inspect(snapshot))
            XCTAssertThrowsError(try inspect(snapshot)) // Snapshot is not consumed or silently discarded.
        }
    }

    func testCertificatePolicyIsRecheckedForEachInspection() throws {
        let snapshot = try snapshot()
        for date in [Date.distantPast, Date.distantFuture] {
            XCTAssertEqual(try GroupAdoptionJournalInspector.inspect(
                snapshot, currentIdentityID: V.member, now: date
            ).name, "INVALID_CHAIN")
        }
        XCTAssertEqual(try inspect(snapshot).name, "HISTORICAL_SIGNATURES_VALID")
    }

    func testUnknownVersionAndTruncationAreErrorsAndNeverAbsence() throws {
        let payload = try payload()
        for data in [Data([76, 71, 82, 74, 2]), Data(payload.dropLast()), payload + Data([0])] {
            let snapshot = try stored(data)
            XCTAssertThrowsError(try inspect(snapshot))
            XCTAssertThrowsError(try inspect(snapshot))
        }
        let source = bytes(payload)
        let snapshot = try IosGroupAdoptionJournalSnapshot.companion.fromStoredRecord(
            attemptId: String(repeating: "e", count: 64), localIdentity: V.member, peerIdentity: V.issuer,
            groupId: V.group, founderId: V.issuer, payload: source
        )
        source.set(index: 0, value: 0)
        XCTAssertEqual(try inspect(snapshot).name, "HISTORICAL_SIGNATURES_VALID")
    }

    func testReadingAnAbsentStoredCandidateDoesNotCreateOneOrChangeMembership() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        do {
            let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
            defer { store.close() }
            XCTAssertNil(try store.pendingGroupAdoption())
            XCTAssertNil(try store.localGroup())
            XCTAssertEqual(try store.trusted(), [])
        }
        let reopened = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { reopened.close() }
        XCTAssertNil(try reopened.pendingGroupAdoption())
        XCTAssertNil(try reopened.localGroup())
    }

    private func inspect(_ snapshot: IosGroupAdoptionJournalSnapshot) throws -> IosGroupAdoptionJournalStatus {
        try GroupAdoptionJournalInspector.inspect(snapshot, currentIdentityID: V.member, now: V.verificationDate)
    }

    private func snapshot(
        group: String = V.group, memberDer: String = V.memberDer, memberNonce: String = "2",
        localSignature: String = V.memberSignature, remoteSignature: String = V.issuerSignature,
        evidence: String = V.evidence
    ) throws -> IosGroupAdoptionJournalSnapshot {
        try stored(payload(memberDer: memberDer, memberNonce: memberNonce,
                           localSignature: localSignature, remoteSignature: remoteSignature, evidence: evidence), group: group)
    }

    private func stored(_ payload: Data, group: String = V.group) throws -> IosGroupAdoptionJournalSnapshot {
        try IosGroupAdoptionJournalSnapshot.companion.fromStoredRecord(
            attemptId: String(repeating: "e", count: 64), localIdentity: V.member, peerIdentity: V.issuer,
            groupId: group, founderId: V.issuer, payload: bytes(payload)
        )
    }

    private func payload(
        memberDer: String = V.memberDer, memberNonce: String = "2", localSignature: String = V.memberSignature,
        remoteSignature: String = V.issuerSignature, evidence: String = V.evidence
    ) throws -> Data {
        // Local-format fixture only; production binary/JSON encoding stays exclusively Kotlin.
        func hello(_ identity: String, _ nonce: String) throws -> Data {
            try JSONSerialization.data(withJSONObject: [
                "identity": identity, "nonce": String(repeating: nonce, count: 64),
                "capabilities": ["version": 1, "supportedFeatures": ["text", "receipts"], "requiredFeatures": ["text"]],
            ], options: [.sortedKeys])
        }
        func confirmation(_ sender: String, _ recipient: String, _ signature: String) throws -> Data {
            try JSONSerialization.data(withJSONObject: ["version": 1, "type": "GROUP_CONFIRM", "sender": sender,
                                                        "recipient": recipient, "signature": signature], options: [.sortedKeys])
        }
        let fields = try [XCTUnwrap(Data(base64Encoded: evidence)), hello(V.member, memberNonce), hello(V.issuer, "1"),
                          Data(memberDer.utf8), confirmation(V.member, V.issuer, localSignature),
                          confirmation(V.issuer, V.member, remoteSignature)]
        var result = Data([76, 71, 82, 74, 1])
        for field in fields {
            let size = UInt32(field.count)
            result += Data([UInt8(size >> 24), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)])
            result += field
        }
        return result
    }

    private func bytes(_ data: Data) -> KotlinByteArray {
        let result = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() { result.set(index: Int32(index), value: Int8(bitPattern: byte)) }
        return result
    }
}
