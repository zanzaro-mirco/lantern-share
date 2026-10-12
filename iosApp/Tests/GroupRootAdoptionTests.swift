import Foundation
import XCTest
import LanternUI

/// Swift/Kotlin ticket boundary with real SQLite, NOT an NWConnection or OS crypto test.
/// Signature/clock doubles are confined here; the native transport owner is still separate.
final class GroupRootAdoptionTests: XCTestCase {
    private let issuer = String(repeating: "a", count: 64)
    private let member = String(repeating: "b", count: 64)
    private let group = String(repeating: "c", count: 64)
    private var directories: [URL] = []

    override func tearDown() {
        directories.forEach { try? FileManager.default.removeItem(at: $0) }
        super.tearDown()
    }

    func testBothConfirmationsAndSuccessfulWriteStillLeaveReopenedDatabaseEmpty() throws {
        let directory = try directory()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        var closed = false
        defer { if !closed { store.close() } }
        let local = try owner()
        let remote = try issuerOwner()
        defer { try? local.cancel(); remote.cancel() }
        XCTAssertNil(try local.comparison())
        XCTAssertTrue(try local.prepare(currentIdentityId: member, persistence: store))
        XCTAssertFalse(try local.prepare(currentIdentityId: member, persistence: store))
        XCTAssertTrue(try remote.prepare())
        let ticket = try XCTUnwrap(local.comparison())
        XCTAssertEqual(data(ticket.bytes), data(try XCTUnwrap(remote.comparison()).bytes))
        let sign = try XCTUnwrap(local.confirm(ticket: ticket))
        let write = try XCTUnwrap(local.signed(ticket: sign, signature: "cHJvb2Y="))
        let remoteSign = try XCTUnwrap(remote.confirm(ticket: try XCTUnwrap(remote.comparison())))
        let remoteWrite = try XCTUnwrap(remote.signed(ticket: remoteSign, signature: "cHJvb2Y="))
        XCTAssertTrue(try local.accept(chunk: remoteWrite.bytes))
        XCTAssertEqual(try local.snapshot().phase.name, "SENDING")
        XCTAssertTrue(try local.snapshot().remoteConfirmed)
        XCTAssertTrue(try local.sent(ticket: write))
        XCTAssertEqual(try local.snapshot().phase.name, "CONFIRMED")
        XCTAssertFalse(try local.sent(ticket: write))
        try local.finish()
        XCTAssertEqual(try local.snapshot().failure.name, "TRANSPORT")
        XCTAssertNil(try store.localGroup())
        XCTAssertEqual(try store.trusted(), [])
        store.close()
        closed = true
        let reopened = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { reopened.close() }
        XCTAssertNil(try reopened.localGroup())
        XCTAssertEqual(try reopened.trusted(), [])
        XCTAssertEqual(try reopened.history().count, 0)
    }

    func testWrongIdentityAndExistingLocalFoundationRefuseBeforeProofVerification() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        var verified = 0
        let changed = try owner(proof: { verified += 1; return true })
        XCTAssertFalse(try changed.prepare(currentIdentityId: issuer, persistence: store))
        XCTAssertEqual(try changed.snapshot().failure.name, "IDENTITY_CHANGED")
        let foundation = try IosLocalGroupFoundation.companion.create(identityId: member)
        let draft = try XCTUnwrap(foundation.prepare(persistence: store, generateGroupId: { self.group }))
        XCTAssertEqual(try foundation.commit(ticket: draft, currentIdentityId: member, persistence: store).name, "COMMITTED")
        let existing = try owner(proof: { verified += 1; return true })
        XCTAssertFalse(try existing.prepare(currentIdentityId: member, persistence: store))
        XCTAssertEqual(try existing.snapshot().failure.name, "ALREADY_IN_GROUP")
        XCTAssertNil(try existing.comparison())
        XCTAssertEqual(verified, 0)
        XCTAssertEqual(try store.localGroup()?.groupId, group)
    }

    func testForeignTicketsAndMutatedCopiesCannotAdvanceAnotherAttempt() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let first = try owner()
        let second = try owner()
        defer { try? first.cancel(); try? second.cancel() }
        XCTAssertTrue(try first.prepare(currentIdentityId: member, persistence: store))
        XCTAssertTrue(try second.prepare(currentIdentityId: member, persistence: store))
        let ticket = try XCTUnwrap(first.comparison())
        let original = data(ticket.bytes)
        ticket.bytes.set(index: 0, value: 0)
        XCTAssertEqual(data(ticket.bytes), original)
        XCTAssertNil(try second.confirm(ticket: ticket))
        let sign = try XCTUnwrap(first.confirm(ticket: ticket))
        XCTAssertNil(try second.signed(ticket: sign, signature: "cHJvb2Y="))
        let write = try XCTUnwrap(first.signed(ticket: sign, signature: "cHJvb2Y="))
        let encoded = data(write.bytes)
        write.bytes.set(index: 0, value: 127)
        XCTAssertEqual(data(write.bytes), encoded)
        XCTAssertFalse(try second.sent(ticket: write))
        try first.block()
        XCTAssertFalse(try first.sent(ticket: write))
        try first.cancel()
        XCTAssertEqual(try first.snapshot().failure.name, "BLOCKED")
    }

    func testExpiryKeepsOriginalDeadlineAndBootstrapWatermark() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        var now: Int64 = 119_999
        let local = try owner(clock: { now })
        XCTAssertEqual(try local.remainingMillis()?.int64Value, 1)
        XCTAssertTrue(try local.prepare(currentIdentityId: member, persistence: store))
        let sign = try XCTUnwrap(local.confirm(ticket: try XCTUnwrap(local.comparison())))
        now += 1
        XCTAssertNil(try local.signed(ticket: sign, signature: "cHJvb2Y="))
        XCTAssertEqual(try local.snapshot().failure.name, "EXPIRED")
        let backwards = try owner(clock: { 16 })
        XCTAssertFalse(try backwards.prepare(currentIdentityId: member, persistence: store))
        XCTAssertEqual(try backwards.snapshot().failure.name, "CLOCK_MOVED_BACKWARDS")
    }

    func testEarlyMalformedAndTruncatedInputCannotExposeComparison() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let early = try owner()
        XCTAssertThrowsError(try early.accept(chunk: KotlinByteArray(size: 0)))
        XCTAssertEqual(try early.snapshot().failure.name, "ADAPTER")
        for size in [Int32(2), Int32(4)] {
            let local = try owner()
            XCTAssertTrue(try local.prepare(currentIdentityId: member, persistence: store))
            if size == 2 {
                XCTAssertTrue(try local.accept(chunk: KotlinByteArray(size: size)))
                XCTAssertThrowsError(try local.finish())
            } else { XCTAssertThrowsError(try local.accept(chunk: KotlinByteArray(size: size))) }
            XCTAssertEqual(try local.snapshot().failure.name, "INVALID_FRAME")
            XCTAssertNil(try local.comparison())
        }
    }

    func testProofFailureAndSigningFailureRemainDistinct() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let invalid = try owner(proof: { false })
        XCTAssertFalse(try invalid.prepare(currentIdentityId: member, persistence: store))
        XCTAssertEqual(try invalid.snapshot().failure.name, "INVALID_PROOF")
        let local = try owner()
        XCTAssertTrue(try local.prepare(currentIdentityId: member, persistence: store))
        let sign = try XCTUnwrap(local.confirm(ticket: try XCTUnwrap(local.comparison())))
        XCTAssertTrue(try local.signingFailed(ticket: sign))
        XCTAssertEqual(try local.snapshot().failure.name, "LOCAL_OPERATION_FAILED")
        XCTAssertNil(try local.signed(ticket: sign, signature: "cHJvb2Y="))
    }

    func testWriteFailureAndLifecycleRejectLateCallbacksAndKeepFirstReason() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let actions: [(String, (IosGroupRootAdoption) throws -> Void)] = [
            ("CANCELLED", { try $0.cancel() }), ("BLOCKED", { try $0.block() }),
            ("LEFT_GROUP", { try $0.leaveGroup() }), ("TRANSPORT", { try $0.transportFailed() }),
        ]
        for (reason, action) in actions {
            let local = try owner()
            XCTAssertTrue(try local.prepare(currentIdentityId: member, persistence: store))
            let sign = try XCTUnwrap(local.confirm(ticket: try XCTUnwrap(local.comparison())))
            let write = try XCTUnwrap(local.signed(ticket: sign, signature: "cHJvb2Y="))
            try action(local)
            XCTAssertFalse(try local.sent(ticket: write))
            XCTAssertFalse(try local.writeFailed(ticket: write))
            try local.cancel()
            XCTAssertEqual(try local.snapshot().failure.name, reason)
        }
        let failed = try owner()
        XCTAssertTrue(try failed.prepare(currentIdentityId: member, persistence: store))
        let sign = try XCTUnwrap(failed.confirm(ticket: try XCTUnwrap(failed.comparison())))
        let write = try XCTUnwrap(failed.signed(ticket: sign, signature: "cHJvb2Y="))
        XCTAssertTrue(try failed.writeFailed(ticket: write))
        XCTAssertFalse(try failed.sent(ticket: write))
        XCTAssertEqual(try failed.snapshot().failure.name, "TRANSPORT")
    }

    func testDuplicateRemoteConfirmationRevokesConfirmedWithoutMembership() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let local = try owner()
        let remote = try issuerOwner()
        defer { try? local.cancel(); remote.cancel() }
        XCTAssertTrue(try local.prepare(currentIdentityId: member, persistence: store))
        XCTAssertTrue(try remote.prepare())
        let sign = try XCTUnwrap(local.confirm(ticket: try XCTUnwrap(local.comparison())))
        XCTAssertTrue(try local.sent(ticket: try XCTUnwrap(local.signed(ticket: sign, signature: "cHJvb2Y="))))
        let remoteSign = try XCTUnwrap(remote.confirm(ticket: try XCTUnwrap(remote.comparison())))
        let write = try XCTUnwrap(remote.signed(ticket: remoteSign, signature: "cHJvb2Y="))
        XCTAssertTrue(try local.accept(chunk: write.bytes))
        XCTAssertEqual(try local.snapshot().phase.name, "CONFIRMED")
        XCTAssertFalse(try local.accept(chunk: write.bytes))
        XCTAssertEqual(try local.snapshot().failure.name, "UNEXPECTED_CONFIRMATION")
        XCTAssertNil(try store.localGroup())
        XCTAssertEqual(try store.trusted(), [])
    }

    private func owner(clock: @escaping () -> Int64 = { 17 }, proof: @escaping () -> Bool = { true }) throws -> IosGroupRootAdoption {
        try IosGroupRootAdoption.companion.create(
            offers: offers(local: member, peer: issuer, nonce: "2", peerNonce: "1"), evidence: evidence(),
            authenticatedLocalIdentity: member, selectedPeerIdentity: issuer, authenticatedPeerIdentity: issuer,
            selectedAtMillis: 0, nowMillis: { KotlinLong(longLong: clock()) },
            verifyAdmissionSignature: { _, _, _ in KotlinBoolean(bool: proof()) },
            verifyRemoteSignature: { _, _ in KotlinBoolean(bool: true) }
        )
    }

    private func issuerOwner() throws -> IosGroupAdmissionConfirmation {
        let context = try IosGroupAdmissionContext.companion.create(
            offers: offers(local: issuer, peer: member, nonce: "1", peerNonce: "2"),
            expectedGroup: group, expectedFounder: issuer, evidence: evidence(), role: .issuer
        )
        return try IosGroupAdmissionConfirmation.companion.create(
            context: context, selectedAtMillis: 0, nowMillis: { KotlinLong(longLong: 17) },
            verifyAdmissionSignature: { _, _, _ in KotlinBoolean(bool: true) },
            verifyRemoteSignature: { _, _ in KotlinBoolean(bool: true) }
        )
    }

    private func offers(local: String, peer: String, nonce: String, peerNonce: String) throws -> IosHandshakeV1Offers {
        func bootstrap(_ id: String, _ remote: String, _ nonce: String) throws -> IosHandshakeV1 {
            try IosHandshakeV1.companion.create(
                localIdentity: id, localNonce: String(repeating: nonce, count: 64),
                capabilitiesJson: "{\"version\":1,\"supportedFeatures\":[\"text\"],\"requiredFeatures\":[]}",
                authenticatedLocalIdentity: id, selectedPeerIdentity: remote, authenticatedPeerIdentity: remote,
                selectedAtMillis: 0, nowMillis: { KotlinLong(longLong: 17) },
                verifyRemoteSignature: { _, _ in KotlinBoolean(bool: false) }
            )
        }
        let owner = try bootstrap(local, peer, nonce)
        let remote = try bootstrap(peer, local, peerNonce)
        defer { remote.cancel() }
        XCTAssertTrue(try owner.sent(ticket: try XCTUnwrap(owner.start())))
        XCTAssertTrue(try owner.accept(chunk: try XCTUnwrap(remote.start()).bytes))
        return try XCTUnwrap(owner.releaseForGroupAdmission())
    }

    private func evidence() throws -> IosGroupAdmissionEvidence {
        let json = """
        {"version":1,"type":"GROUP_EVIDENCE","proof":{"version":1,"anchor":{"group":"\(group)","founder":"\(issuer)"},"admissions":[{"claim":{"version":1,"group":"\(group)","issuer":"\(issuer)","member":"\(member)"},"signature":"cHJvb2Y="}]},"certificates":[{"identity":"\(issuer)","der":"AA=="}]}
        """
        let data = Data(json.utf8)
        let bytes = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() { bytes.set(index: Int32(index), value: Int8(bitPattern: byte)) }
        return try IosGroupAdmissionEvidence.companion.decode(payload: bytes)
    }

    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        directories.append(url)
        return url
    }

    private func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }
}
