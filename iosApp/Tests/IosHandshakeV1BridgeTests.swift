import Foundation
import XCTest
import LanternUI

/// Swift/Kotlin boundary tests only. Clock, nonce and signature verifier are test fixtures, not TLS.
final class IosHandshakeV1BridgeTests: XCTestCase {
    private let proof = "cHJvb2Y="

    func testBridgeRequiresExplicitConfirmationAndCompletedWrites() throws {
        let left = try bridge(left: true)
        let right = try bridge(left: false)
        let leftHello = try XCTUnwrap(left.start())
        let rightHello = try XCTUnwrap(right.start())
        XCTAssertEqual(try left.snapshot().phase.name, "SENDING_HELLO")
        XCTAssertNil(try left.start())
        XCTAssertTrue(try left.sent(ticket: leftHello))
        XCTAssertTrue(try right.sent(ticket: rightHello))
        XCTAssertTrue(try left.accept(chunk: rightHello.bytes))
        XCTAssertTrue(try right.accept(chunk: leftHello.bytes))
        let leftCode = try XCTUnwrap(left.comparison())
        let rightCode = try XCTUnwrap(right.comparison())
        XCTAssertEqual(data(leftCode.bytes), data(rightCode.bytes))
        let signing = try XCTUnwrap(left.confirm(ticket: leftCode))
        let sending = try XCTUnwrap(left.signed(ticket: signing, signature: proof))
        XCTAssertTrue(try right.accept(chunk: sending.bytes))
        XCTAssertEqual(try right.snapshot().phase.name, "AWAITING_CONFIRMATION")
        XCTAssertTrue(try right.snapshot().remoteApproved)
        let remoteSigning = try XCTUnwrap(right.confirm(ticket: rightCode))
        let remoteSending = try XCTUnwrap(right.signed(ticket: remoteSigning, signature: proof))
        XCTAssertTrue(try left.accept(chunk: remoteSending.bytes))
        XCTAssertEqual(try left.snapshot().phase.name, "SENDING_APPROVAL")
        XCTAssertTrue(try left.sent(ticket: sending))
        XCTAssertTrue(try right.sent(ticket: remoteSending))
        XCTAssertEqual(try left.snapshot().phase.name, "READY")
        XCTAssertEqual(try left.snapshot().negotiatedFeatures, ["receipts", "text"])
        left.cancel()
        XCTAssertEqual(try left.snapshot().failure.name, "CANCELLED")
        XCTAssertFalse(try left.sent(ticket: sending))
        XCTAssertEqual(try right.snapshot().phase.name, "READY")
        try right.finish()
        XCTAssertEqual(try right.snapshot().phase.name, "CLOSED")
        XCTAssertEqual(try right.snapshot().failure.name, "TRANSPORT")
        XCTAssertFalse(try right.snapshot().remoteApproved)
        XCTAssertTrue(try right.snapshot().negotiatedFeatures.isEmpty)
        XCTAssertFalse(try right.sent(ticket: remoteSending))
        XCTAssertNil(try right.confirm(ticket: rightCode))
    }

    func testForeignHelloCallbackAndExpiredCallbackCannotAdvance() throws {
        var now: Int64 = 0
        let first = try bridge(left: true, now: { now })
        let replacement = try bridge(left: true)
        let pending = try XCTUnwrap(first.start())
        XCTAssertFalse(try replacement.sent(ticket: pending))
        XCTAssertEqual(try replacement.snapshot().phase.name, "AWAITING_START")
        XCTAssertEqual(try first.remainingMillis()?.int64Value, 120_000)
        now = 120_000
        XCTAssertNil(try first.remainingMillis())
        XCTAssertEqual(try first.snapshot().failure.name, "EXPIRED")
        XCTAssertFalse(try first.sent(ticket: pending))
    }

    func testMalformedAndTruncatedInputBecomeSwiftErrorsAndTerminalStates() throws {
        let invalid = try bridge(left: true)
        XCTAssertTrue(try invalid.sent(ticket: XCTUnwrap(invalid.start())))
        XCTAssertThrowsError(try invalid.accept(chunk: bytes(Data([0, 0, 0, 0]))))
        XCTAssertEqual(try invalid.snapshot().failure.name, "INVALID_FRAME")
        XCTAssertNil(try invalid.start())
        for headerOnly in [true, false] {
            let truncated = try bridge(left: true)
            let remote = try bridge(left: false)
            let hello = data(try XCTUnwrap(remote.start()).bytes)
            let prefix = Data(hello.prefix(headerOnly ? 3 : hello.count - 1))
            XCTAssertTrue(try truncated.sent(ticket: XCTUnwrap(truncated.start())))
            XCTAssertTrue(try truncated.accept(chunk: bytes(prefix)))
            XCTAssertEqual(try truncated.snapshot().phase.name, "AWAITING_HELLO")
            XCTAssertNil(try truncated.comparison())
            XCTAssertThrowsError(try truncated.finish())
            XCTAssertEqual(try truncated.snapshot().phase.name, "CLOSED")
            XCTAssertEqual(try truncated.snapshot().failure.name, "TRANSPORT")
            XCTAssertNil(try truncated.start())
            XCTAssertFalse(try truncated.accept(chunk: bytes(hello)))
            try truncated.finish() // Idempotent, without replacing the first failure.
            truncated.cancel()
            XCTAssertEqual(try truncated.snapshot().failure.name, "TRANSPORT")
        }
    }

    private func bridge(left: Bool, now: @escaping () -> Int64 = { 0 }) throws -> IosHandshakeV1 {
        let local = String(repeating: left ? "a" : "b", count: 64)
        let peer = String(repeating: left ? "b" : "a", count: 64)
        return try IosHandshakeV1.companion.create(
            localIdentity: local,
            localNonce: String(repeating: left ? "1" : "2", count: 64),
            capabilitiesJson: "{\"version\":1,\"supportedFeatures\":[\"text\",\"receipts\"],\"requiredFeatures\":[\"text\"]}",
            authenticatedLocalIdentity: local,
            selectedPeerIdentity: peer,
            authenticatedPeerIdentity: peer,
            selectedAtMillis: 0,
            nowMillis: { KotlinLong(longLong: now()) },
            verifyRemoteSignature: { _, signature in KotlinBoolean(bool: signature == "cHJvb2Y=") }
        )
    }

    private func bytes(_ data: Data) -> KotlinByteArray {
        let result = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() {
            result.set(index: Int32(index), value: Int8(bitPattern: byte))
        }
        return result
    }

    private func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }
}
