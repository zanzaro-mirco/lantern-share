import Foundation
import XCTest
import LanternUI
@testable import Lantern

/// Swift boundary/framing only. No NWConnection ownership or group authorization.
final class GroupAdmissionEvidenceDecoderTests: XCTestCase {
    func testByteByByteFrameUsesSharedEncodingAndExactReadBudget() throws {
        let payload = try vectorPayload()
        let frame = try data(try decode(payload).framedBytes())
        // Kotlin owns canonical JSON ordering; Swift's input need not have identical byte order.
        XCTAssertEqual(Data(frame.prefix(4)), header(frame.count - 4))
        XCTAssertEqual(try data(try decode(Data(frame.dropFirst(4))).framedBytes()), frame)
        let decoder = IosGroupAdmissionEvidenceDecoder()
        XCTAssertEqual(decoder.maximumChunkBytes, 4096)
        XCTAssertEqual(try decoder.nextReadBytes(), 4)
        var completed: IosGroupAdmissionEvidence?
        for (index, byte) in frame.enumerated() {
            let expected = index < 4 ? 4 - index : min(4096, frame.count - index)
            XCTAssertEqual(Int(try decoder.nextReadBytes()), expected)
            let result = try decoder.accept(chunk: kotlin(Data([byte])))
            XCTAssertEqual(result.consumedBytes, 1)
            if index == frame.count - 1 {
                completed = try XCTUnwrap(result.evidence)
            } else {
                XCTAssertNil(result.evidence)
            }
        }
        let evidence = try XCTUnwrap(completed)
        XCTAssertEqual(try data(try evidence.framedBytes()), frame)
        XCTAssertTrue(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: String(repeating: "c", count: 64),
            expectedFounder: JvmGroupAdmissionVectors.p256.founder, expectedMember: String(repeating: "b", count: 64),
            now: JvmGroupAdmissionVectors.verificationDate
        ))
        assertClosed(decoder)
    }

    func testCoalescedTailIsNotConsumedAndSecondEvidenceIsNotDecoded() throws {
        let frame = try data(try decode(vectorPayload()).framedBytes())
        let tail = frame // A second evidence is still a tail, never another authorized admission.
        let chunk = frame + tail
        XCTAssertLessThanOrEqual(chunk.count, 4096)
        let decoder = IosGroupAdmissionEvidenceDecoder()
        let result = try decoder.accept(chunk: kotlin(chunk))
        XCTAssertEqual(Int(result.consumedBytes), frame.count)
        XCTAssertNotNil(result.evidence)
        XCTAssertEqual(Data(chunk.dropFirst(Int(result.consumedBytes))), tail)
        assertClosed(decoder)
    }

    func testIncompleteInputIsCopiedAndEmptyChunkDoesNotCompleteFrame() throws {
        let frame = try data(try decode(vectorPayload()).framedBytes())
        let decoder = IosGroupAdmissionEvidenceDecoder()
        let empty = try decoder.accept(chunk: kotlin(Data()))
        XCTAssertEqual(empty.consumedBytes, 0)
        XCTAssertNil(empty.evidence)
        XCTAssertEqual(try decoder.nextReadBytes(), 4)
        let prefix = kotlin(Data(frame.prefix(9)))
        let partial = try decoder.accept(chunk: prefix)
        XCTAssertEqual(partial.consumedBytes, 9)
        XCTAssertNil(partial.evidence)
        for index in 0..<Int(prefix.size) { prefix.set(index: Int32(index), value: 0) }
        let result = try decoder.accept(chunk: kotlin(Data(frame.dropFirst(9))))
        XCTAssertEqual(try data(try XCTUnwrap(result.evidence).framedBytes()), frame)
    }

    func testMaximumPayloadIsReadInBoundedChunksWithoutReadingNextFrame() throws {
        let original = try vectorPayload()
        let maximum = Int(IosGroupAdmissionEvidence.companion.maximumPayloadBytes)
        let payload = original + Data(repeating: 32, count: maximum - original.count)
        let frame = header(payload.count) + payload
        let tail = Data([0, 0, 0, 1, 0])
        let source = frame + tail
        let decoder = IosGroupAdmissionEvidenceDecoder()
        var offset = 0
        var complete: IosGroupAdmissionEvidence?
        var fullChunkObserved = false
        while complete == nil {
            let budget = Int(try decoder.nextReadBytes())
            XCTAssertGreaterThan(budget, 0)
            XCTAssertLessThanOrEqual(budget, 4096)
            fullChunkObserved = fullChunkObserved || budget == 4096
            let result = try decoder.accept(chunk: kotlin(Data(source[offset..<offset + budget])))
            XCTAssertEqual(Int(result.consumedBytes), budget)
            offset += budget
            complete = result.evidence
        }
        XCTAssertTrue(fullChunkObserved)
        XCTAssertEqual(offset, frame.count)
        XCTAssertEqual(Data(source.dropFirst(offset)), tail)
        XCTAssertEqual(try XCTUnwrap(complete).certificates.first?.identity, JvmGroupAdmissionVectors.p256.founder)
        assertClosed(decoder)
    }

    func testInvalidLengthOversizedChunkAndMalformedPayloadAreTerminal() throws {
        for length in [0, 262145, Int(UInt32.max)] {
            let decoder = IosGroupAdmissionEvidenceDecoder()
            XCTAssertThrowsError(try decoder.accept(chunk: kotlin(header(length))))
            assertClosed(decoder)
        }
        let oversized = IosGroupAdmissionEvidenceDecoder()
        XCTAssertThrowsError(try oversized.accept(chunk: kotlin(Data(repeating: 0, count: 4097))))
        assertClosed(oversized)
        for payload in [Data([0xc0, 0xaf]), Data("{\"peer-secret\":\"do-not-log\"}".utf8)] {
            let decoder = IosGroupAdmissionEvidenceDecoder()
            XCTAssertThrowsError(try decoder.accept(chunk: kotlin(header(payload.count) + payload))) { error in
                XCTAssertTrue(error.localizedDescription.contains("Invalid group evidence frame"))
                XCTAssertFalse(error.localizedDescription.contains("peer-secret"))
                XCTAssertFalse(error.localizedDescription.contains("do-not-log"))
            }
            assertClosed(decoder)
        }
    }

    func testEofAtEveryIncompleteBoundaryAndRepeatedCancelAreTerminal() throws {
        let frame = try data(try decode(vectorPayload()).framedBytes())
        for prefixLength in [0, 1, 3, 4, 9, frame.count - 1] {
            let decoder = IosGroupAdmissionEvidenceDecoder()
            if prefixLength > 0 {
                XCTAssertNil(try decoder.accept(chunk: kotlin(Data(frame.prefix(prefixLength)))).evidence)
            }
            XCTAssertThrowsError(try decoder.finish())
            assertClosed(decoder)
        }
        let cancelled = IosGroupAdmissionEvidenceDecoder()
        XCTAssertNil(try cancelled.accept(chunk: kotlin(Data(frame.prefix(9)))).evidence)
        cancelled.cancel()
        cancelled.cancel()
        assertClosed(cancelled)
    }

    private func assertClosed(_ decoder: IosGroupAdmissionEvidenceDecoder, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try decoder.nextReadBytes(), file: file, line: line)
        XCTAssertThrowsError(try decoder.accept(chunk: kotlin(Data())), file: file, line: line)
        XCTAssertThrowsError(try decoder.finish(), file: file, line: line)
        decoder.cancel() // Cleanup stays idempotent even after completion or failure.
    }

    private func vectorPayload() throws -> Data {
        let vector = JvmGroupAdmissionVectors.p256
        let group = String(repeating: "c", count: 64)
        // Fixture construction only. Production encoding remains in Kotlin.
        return try JSONSerialization.data(withJSONObject: [
            "version": 1, "type": "GROUP_EVIDENCE",
            "proof": ["version": 1, "anchor": ["group": group, "founder": vector.founder],
                      "admissions": [["claim": ["version": 1, "group": group, "issuer": vector.founder,
                                                 "member": String(repeating: "b", count: 64)],
                                      "signature": vector.signature]]],
            "certificates": [["identity": vector.founder, "der": vector.der]],
        ], options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private func header(_ length: Int) -> Data {
        let value = UInt32(length)
        return Data([UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
                     UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)])
    }

    private func decode(_ payload: Data) throws -> IosGroupAdmissionEvidence {
        try IosGroupAdmissionEvidence.companion.decode(payload: kotlin(payload))
    }

    private func kotlin(_ data: Data) -> KotlinByteArray {
        let bytes = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() { bytes.set(index: Int32(index), value: Int8(bitPattern: byte)) }
        return bytes
    }

    private func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }
}
