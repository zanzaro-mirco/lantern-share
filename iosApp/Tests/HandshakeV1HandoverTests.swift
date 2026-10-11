import Foundation
import XCTest
import LanternUI

/// Core boundary only: no TLS socket is ceded by these tests.
final class HandshakeV1HandoverTests: XCTestCase {
    func testFrozenOffersAndTerminalReleaseInvalidateOldTicketsWithoutClockReads() throws {
        var released = false
        let owner = try create(local: "a", remote: "b", clock: {
            XCTAssertFalse(released, "Released core must not consult old clock")
            return 17
        })
        XCTAssertNil(try owner.releaseForGroupAdmission())
        let hello = try XCTUnwrap(owner.start())
        XCTAssertTrue(try owner.sent(ticket: hello))
        let remote = try create(local: "b", remote: "a")
        XCTAssertTrue(try owner.accept(chunk: try XCTUnwrap(remote.start()).bytes))
        let comparison = try XCTUnwrap(owner.comparison())
        let offers = try XCTUnwrap(owner.releaseForGroupAdmission())
        released = true
        XCTAssertEqual(offers.localIdentity, String(repeating: "a", count: 64))
        XCTAssertEqual(offers.remoteIdentity, String(repeating: "b", count: 64))
        XCTAssertEqual(offers.observedAtMillis, 17)
        XCTAssertEqual(try owner.snapshot().phase.name, "RELEASED_TO_GROUP")
        XCTAssertNil(try owner.releaseForGroupAdmission())
        XCTAssertNil(try owner.offersForGroupAdmission())
        XCTAssertNil(try owner.nextReadBytes())
        XCTAssertNil(try owner.remainingMillis())
        XCTAssertNil(try owner.confirm(ticket: comparison))
        XCTAssertFalse(try owner.sent(ticket: hello))
        XCTAssertFalse(try owner.accept(chunk: hello.bytes))
        try owner.finish()
        owner.cancel()
        XCTAssertEqual(try owner.snapshot().phase.name, "RELEASED_TO_GROUP")
        remote.cancel()
    }

    func testPartialNextHeaderPreventsReleaseDespiteCompatibleHello() throws {
        let owner = try create(local: "a", remote: "b")
        let remote = try create(local: "b", remote: "a")
        XCTAssertTrue(try owner.sent(ticket: try XCTUnwrap(owner.start())))
        XCTAssertTrue(try owner.accept(chunk: try XCTUnwrap(remote.start()).bytes))
        XCTAssertNotNil(try owner.offersForGroupAdmission())
        let prefix = KotlinByteArray(size: 1)
        prefix.set(index: 0, value: 0)
        XCTAssertTrue(try owner.accept(chunk: prefix))
        XCTAssertNil(try owner.offersForGroupAdmission())
        XCTAssertNil(try owner.releaseForGroupAdmission())
        owner.cancel()
        remote.cancel()
    }

    private func create(local: String, remote: String, clock: @escaping () -> Int64 = { 0 }) throws -> IosHandshakeV1 {
        let localID = String(repeating: local, count: 64)
        let remoteID = String(repeating: remote, count: 64)
        return try IosHandshakeV1.companion.create(
            localIdentity: localID, localNonce: String(repeating: local == "a" ? "1" : "2", count: 64),
            capabilitiesJson: "{\"version\":1,\"supportedFeatures\":[\"text\"],\"requiredFeatures\":[]}",
            authenticatedLocalIdentity: localID, selectedPeerIdentity: remoteID, authenticatedPeerIdentity: remoteID,
            selectedAtMillis: 0, nowMillis: { KotlinLong(longLong: clock()) },
            verifyRemoteSignature: { _, _ in KotlinBoolean(bool: false) }
        )
    }
}
