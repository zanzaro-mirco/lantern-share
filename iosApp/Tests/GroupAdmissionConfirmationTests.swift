import Foundation
import XCTest
import LanternUI

/// Kotlin/Swift callback-state boundary. Crypto doubles are confined to this test;
/// real TLS/certificate/signature coverage belongs to the channel integration tests.
final class GroupAdmissionConfirmationTests: XCTestCase {
    private let issuer = String(repeating: "a", count: 64)
    private let member = String(repeating: "b", count: 64)
    private let group = String(repeating: "c", count: 64)

    func testComparisonAndQueuedSignatureCannotBypassProofOrSuccessfulLocalWrite() throws {
        var verificationCalls = 0
        let local = try confirmation(role: .issuer, proof: { id, bytes, signature in
            verificationCalls += 1
            XCTAssertEqual(id, self.issuer)
            XCTAssertEqual(signature, "cHJvb2Y=")
            XCTAssertGreaterThan(bytes.size, 0)
            return true
        })
        let peer = try confirmation(role: .member)
        XCTAssertNil(try local.comparison())
        XCTAssertTrue(try local.prepare())
        XCTAssertTrue(try peer.prepare())
        XCTAssertEqual(verificationCalls, 1)
        let ticket = try XCTUnwrap(local.comparison())
        let peerTicket = try XCTUnwrap(peer.comparison())
        XCTAssertEqual(data(ticket.bytes), data(peerTicket.bytes))
        let original = data(ticket.bytes)
        ticket.bytes.set(index: 0, value: 0)
        XCTAssertEqual(data(ticket.bytes), original)
        let sign = try XCTUnwrap(local.confirm(ticket: ticket))
        let write = try XCTUnwrap(local.signed(ticket: sign, signature: "cHJvb2Y="))
        let remoteSign = try XCTUnwrap(peer.confirm(ticket: peerTicket))
        let remoteWrite = try XCTUnwrap(peer.signed(ticket: remoteSign, signature: "cHJvb2Y="))
        XCTAssertTrue(try local.accept(chunk: remoteWrite.bytes))
        XCTAssertEqual(try local.snapshot().phase.name, "SENDING")
        XCTAssertTrue(try local.snapshot().remoteConfirmed)
        XCTAssertTrue(try local.sent(ticket: write))
        XCTAssertEqual(try local.snapshot().phase.name, "CONFIRMED")
        XCTAssertFalse(try local.sent(ticket: write))
        try local.finish()
        XCTAssertEqual(try local.snapshot().failure.name, "TRANSPORT")
        local.cancel()
        peer.cancel()
    }

    func testContextRejectsReceivedRootSubstitutionAndWrongDirection() throws {
        let frozen = try offers(role: .issuer)
        let supplied = try evidence()
        XCTAssertThrowsError(try IosGroupAdmissionContext.companion.create(
            offers: frozen, expectedGroup: String(repeating: "d", count: 64), expectedFounder: issuer,
            evidence: supplied, role: .issuer
        ))
        XCTAssertThrowsError(try IosGroupAdmissionContext.companion.create(
            offers: frozen, expectedGroup: group, expectedFounder: member, evidence: supplied, role: .issuer
        ))
        XCTAssertThrowsError(try IosGroupAdmissionContext.companion.create(
            offers: frozen, expectedGroup: group, expectedFounder: issuer, evidence: supplied, role: .member
        ))
    }

    func testFreshNonceChangesComparisonAndForeignTicketCannotAdvanceReplacement() throws {
        let first = try confirmation(role: .issuer)
        let next = try confirmation(role: .issuer, nonce: "3")
        XCTAssertTrue(try first.prepare())
        XCTAssertTrue(try next.prepare())
        let old = try XCTUnwrap(first.comparison())
        let current = try XCTUnwrap(next.comparison())
        XCTAssertNotEqual(data(old.bytes), data(current.bytes))
        XCTAssertNil(try next.confirm(ticket: old))
        XCTAssertEqual(try next.snapshot().phase.name, "AWAITING_CONFIRMATION")
        first.cancel()
        next.cancel()
    }

    func testOriginalDeadlineAndBootstrapWatermarkAreNotReset() throws {
        var now: Int64 = 119_999
        let local = try confirmation(role: .issuer, clock: { now })
        XCTAssertEqual(try local.remainingMillis()?.int64Value, 1)
        XCTAssertTrue(try local.prepare())
        let sign = try XCTUnwrap(local.confirm(ticket: try XCTUnwrap(local.comparison())))
        now += 1
        XCTAssertNil(try local.signed(ticket: sign, signature: "cHJvb2Y="))
        XCTAssertEqual(try local.snapshot().failure.name, "EXPIRED")
        let backwards = try confirmation(role: .issuer, clock: { 16 })
        XCTAssertThrowsError(try backwards.prepare())
        XCTAssertEqual(try backwards.snapshot().failure.name, "ADAPTER")
        XCTAssertNil(try backwards.comparison())
    }

    func testInvalidProofNeverExposesComparisonOrAcceptsNetworkInput() throws {
        let local = try confirmation(role: .issuer, proof: { _, _, _ in false })
        XCTAssertFalse(try local.prepare())
        XCTAssertNil(try local.comparison())
        XCTAssertFalse(try local.accept(chunk: KotlinByteArray(size: 0)))
        XCTAssertEqual(try local.snapshot().failure.name, "INVALID_PROOF")
        let early = try confirmation(role: .issuer)
        XCTAssertThrowsError(try early.accept(chunk: KotlinByteArray(size: 0)))
        XCTAssertEqual(try early.snapshot().failure.name, "ADAPTER")
    }

    func testLifecycleRevokesPendingSignaturesAndPreservesFirstReason() throws {
        let actions: [(String, (IosGroupAdmissionConfirmation) -> Void)] = [
            ("CANCELLED", { $0.cancel() }), ("BLOCKED", { $0.block() }), ("LEFT_GROUP", { $0.leaveGroup() }),
        ]
        for (reason, event) in actions {
            let local = try confirmation(role: .issuer)
            XCTAssertTrue(try local.prepare())
            let sign = try XCTUnwrap(local.confirm(ticket: try XCTUnwrap(local.comparison())))
            event(local)
            XCTAssertNil(try local.signed(ticket: sign, signature: "cHJvb2Y="))
            XCTAssertFalse(try local.signingFailed(ticket: sign))
            local.cancel()
            local.block()
            local.leaveGroup()
            XCTAssertEqual(try local.snapshot().failure.name, reason)
        }
    }

    func testTransportSigningAndMalformedFrameFailuresRemainDistinct() throws {
        let local = try confirmation(role: .issuer)
        XCTAssertTrue(try local.prepare())
        let sign = try XCTUnwrap(local.confirm(ticket: try XCTUnwrap(local.comparison())))
        XCTAssertTrue(try local.signingFailed(ticket: sign))
        XCTAssertEqual(try local.snapshot().failure.name, "LOCAL_OPERATION_FAILED")
        let writing = try confirmation(role: .issuer)
        XCTAssertTrue(try writing.prepare())
        let writingSign = try XCTUnwrap(writing.confirm(ticket: try XCTUnwrap(writing.comparison())))
        let write = try XCTUnwrap(writing.signed(ticket: writingSign, signature: "cHJvb2Y="))
        XCTAssertTrue(try writing.writeFailed(ticket: write))
        XCTAssertFalse(try writing.sent(ticket: write))
        XCTAssertEqual(try writing.snapshot().failure.name, "TRANSPORT")
        let malformed = try confirmation(role: .issuer)
        XCTAssertTrue(try malformed.prepare())
        XCTAssertThrowsError(try malformed.accept(chunk: KotlinByteArray(size: 4)))
        XCTAssertEqual(try malformed.snapshot().failure.name, "INVALID_FRAME")
    }

    private func confirmation(
        role: IosGroupAdmissionRole, nonce: String? = nil, clock: @escaping () -> Int64 = { 17 },
        proof: @escaping (String, KotlinByteArray, String) -> Bool = { _, _, _ in true }
    ) throws -> IosGroupAdmissionConfirmation {
        let context = try IosGroupAdmissionContext.companion.create(
            offers: offers(role: role, nonce: nonce), expectedGroup: group, expectedFounder: issuer,
            evidence: evidence(), role: role
        )
        return try IosGroupAdmissionConfirmation.companion.create(
            context: context, selectedAtMillis: 0, nowMillis: { KotlinLong(longLong: clock()) },
            verifyAdmissionSignature: { id, bytes, signature in KotlinBoolean(bool: proof(id, bytes, signature)) },
            verifyRemoteSignature: { _, _ in KotlinBoolean(bool: true) }
        )
    }

    private func offers(role: IosGroupAdmissionRole, nonce: String? = nil) throws -> IosHandshakeV1Offers {
        let local = role == .issuer ? issuer : member
        let peer = role == .issuer ? member : issuer
        func bootstrap(id: String, remote: String, nonce: String) throws -> IosHandshakeV1 {
            try IosHandshakeV1.companion.create(
                localIdentity: id, localNonce: String(repeating: nonce, count: 64),
                capabilitiesJson: "{\"version\":1,\"supportedFeatures\":[\"text\"],\"requiredFeatures\":[]}",
                authenticatedLocalIdentity: id, selectedPeerIdentity: remote, authenticatedPeerIdentity: remote,
                selectedAtMillis: 0, nowMillis: { KotlinLong(longLong: 17) },
                verifyRemoteSignature: { _, _ in KotlinBoolean(bool: false) }
            )
        }
        let owner = try bootstrap(id: local, remote: peer, nonce: nonce ?? (role == .issuer ? "1" : "2"))
        let remote = try bootstrap(id: peer, remote: local, nonce: role == .issuer ? "2" : "1")
        XCTAssertTrue(try owner.sent(ticket: try XCTUnwrap(owner.start())))
        XCTAssertTrue(try owner.accept(chunk: try XCTUnwrap(remote.start()).bytes))
        remote.cancel()
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

    private func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }
}
