import CryptoKit
import Foundation
import Security
import XCTest
import LanternIdentity
import LanternUI
@testable import Lantern

/// JVM-produced public fixtures tested at the Kotlin/Swift/Apple crypto boundary.
/// Fixed nonces, calendar and precomputed local signatures are test-only, not a TLS exchange.
final class GroupAdmissionConfirmationVectorTests: XCTestCase {
    private typealias V = JvmGroupConfirmationVectors

    func testBothJvmDirectionsMatchCanonicalBytesAndRequireSuccessfulLocalWrite() throws {
        let issuer = try confirmation(role: .issuer)
        let member = try confirmation(role: .member)
        XCTAssertTrue(try issuer.prepare())
        XCTAssertTrue(try member.prepare())
        let issuerTicket = try XCTUnwrap(issuer.comparison())
        let memberTicket = try XCTUnwrap(member.comparison())
        XCTAssertEqual(hash(issuerTicket.bytes), V.comparisonHash)
        XCTAssertEqual(data(issuerTicket.bytes), data(memberTicket.bytes))
        let issuerSign = try XCTUnwrap(issuer.confirm(ticket: issuerTicket))
        let memberSign = try XCTUnwrap(member.confirm(ticket: memberTicket))
        XCTAssertEqual(hash(issuerSign.bytes), V.issuerApprovalHash)
        XCTAssertEqual(hash(memberSign.bytes), V.memberApprovalHash)
        let issuerWrite = try XCTUnwrap(issuer.signed(ticket: issuerSign, signature: V.issuerSignature))
        let memberWrite = try XCTUnwrap(member.signed(ticket: memberSign, signature: V.memberSignature))
        XCTAssertEqual(data(issuerWrite.bytes), try decoded(V.issuerFrame))
        XCTAssertEqual(data(memberWrite.bytes), try decoded(V.memberFrame))
        XCTAssertTrue(try member.accept(chunk: issuerWrite.bytes))
        XCTAssertTrue(try issuer.accept(chunk: memberWrite.bytes))
        XCTAssertEqual(try issuer.snapshot().phase.name, "SENDING")
        XCTAssertEqual(try member.snapshot().phase.name, "SENDING")
        XCTAssertTrue(try issuer.sent(ticket: issuerWrite))
        XCTAssertTrue(try member.sent(ticket: memberWrite))
        XCTAssertEqual(try issuer.snapshot().phase.name, "CONFIRMED")
        XCTAssertEqual(try member.snapshot().phase.name, "CONFIRMED")
        try member.finish() // A valid pair of signatures is still revocable, not persisted trust.
        XCTAssertEqual(try member.snapshot().failure.name, "TRANSPORT")
        issuer.cancel()
    }

    func testJvmConfirmationCannotReplayWithFreshBootstrapNonce() throws {
        let member = try confirmation(role: .member, memberNonce: "3")
        XCTAssertTrue(try member.prepare())
        XCTAssertNotEqual(hash(try XCTUnwrap(member.comparison()).bytes), V.comparisonHash)
        XCTAssertFalse(try member.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertEqual(try member.snapshot().failure.name, "INVALID_REMOTE_CONFIRMATION")
        XCTAssertNil(try member.comparison())
    }

    func testAnotherValidAdmissionSignatureChangesContextAndRejectsOldConfirmation() throws {
        let original = try suppliedEvidence(V.evidence)
        let alternative = try suppliedEvidence(V.alternativeEvidence)
        XCTAssertNotEqual(data(try original.framedBytes()), data(try alternative.framedBytes()))
        XCTAssertTrue(try GroupAdmissionEvidenceCertificates.verifyChain(
            alternative, expectedGroup: V.group, expectedFounder: V.issuer, expectedMember: V.member,
            now: V.verificationDate
        ))
        let member = try confirmation(role: .member, payload: V.alternativeEvidence)
        XCTAssertTrue(try member.prepare())
        XCTAssertNotEqual(hash(try XCTUnwrap(member.comparison()).bytes), V.comparisonHash)
        XCTAssertFalse(try member.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertEqual(try member.snapshot().failure.name, "INVALID_REMOTE_CONFIRMATION")
    }

    func testRealSignatureFromWrongKeyCannotConfirmPinnedIssuer() throws {
        let member = try confirmation(role: .member)
        XCTAssertTrue(try member.prepare())
        let frame = try confirmationFrame(sender: V.issuer, recipient: V.member, signature: V.wrongIssuerSignature)
        XCTAssertFalse(try member.accept(chunk: bytes(frame)))
        XCTAssertEqual(try member.snapshot().failure.name, "INVALID_REMOTE_CONFIRMATION")
        XCTAssertFalse(try member.snapshot().remoteConfirmed)
        XCTAssertNil(try member.comparison())
    }

    func testReflectedSenderAndRecipientAreRejectedBeforeRemoteCryptoCallback() throws {
        var remoteCalls = 0
        let member = try confirmation(role: .member, onRemoteVerification: { remoteCalls += 1 })
        XCTAssertTrue(try member.prepare())
        let frame = try confirmationFrame(sender: V.member, recipient: V.issuer, signature: V.issuerSignature)
        XCTAssertFalse(try member.accept(chunk: bytes(frame)))
        XCTAssertEqual(remoteCalls, 0)
        XCTAssertEqual(try member.snapshot().failure.name, "INVALID_REMOTE_CONFIRMATION")
    }

    func testValidBootstrapApprovalSignatureCannotReplaceGroupConfirmation() throws {
        let member = try confirmation(role: .member)
        XCTAssertTrue(try member.prepare())
        let frame = try confirmationFrame(sender: V.issuer, recipient: V.member, signature: V.bootstrapSignature)
        XCTAssertFalse(try member.accept(chunk: bytes(frame)))
        XCTAssertEqual(try member.snapshot().failure.name, "INVALID_REMOTE_CONFIRMATION")
        XCTAssertNil(try member.comparison())
    }

    func testEquivalentJsonAndFeatureOrderKeepCanonicalCodeAndJvmSignatureValid() throws {
        let json = String(decoding: try decoded(V.evidence), as: UTF8.self)
            .replacingOccurrences(of: "\"version\"", with: "\"ver\\u0073ion\"")
            .replacingOccurrences(of: ",", with: ",\n")
        let payload = Data((" \n" + json + " \n").utf8).base64EncodedString()
        let member = try confirmation(role: .member, payload: payload, reversedFeatureOrder: true)
        XCTAssertTrue(try member.prepare())
        XCTAssertEqual(hash(try XCTUnwrap(member.comparison()).bytes), V.comparisonHash)
        XCTAssertTrue(try member.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertTrue(try member.snapshot().remoteConfirmed)
        XCTAssertEqual(try member.snapshot().phase.name, "AWAITING_CONFIRMATION")
        member.cancel()
    }

    func testChangedCompatibleOfferCannotReuseOldConfirmation() throws {
        // Negotiated text/receipts are unchanged, but the complete offered capabilities differ.
        let member = try confirmation(role: .member, additionalMemberFeature: true)
        XCTAssertTrue(try member.prepare())
        XCTAssertNotEqual(hash(try XCTUnwrap(member.comparison()).bytes), V.comparisonHash)
        XCTAssertFalse(try member.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertEqual(try member.snapshot().failure.name, "INVALID_REMOTE_CONFIRMATION")
    }

    func testBytewiseRealConfirmationCallsAppleVerifierOnlyAfterCompleteFrame() throws {
        var remoteCalls = 0
        let member = try confirmation(role: .member, onRemoteVerification: { remoteCalls += 1 })
        XCTAssertTrue(try member.prepare())
        let frame = try decoded(V.issuerFrame)
        for (index, byte) in frame.enumerated() {
            XCTAssertTrue(try member.accept(chunk: bytes(Data([byte]))))
            XCTAssertEqual(remoteCalls, index == frame.count - 1 ? 1 : 0)
            XCTAssertEqual(try member.snapshot().remoteConfirmed, index == frame.count - 1)
            XCTAssertEqual(try member.snapshot().phase.name, "AWAITING_CONFIRMATION")
        }
        XCTAssertEqual(hash(try XCTUnwrap(member.comparison()).bytes), V.comparisonHash)
        member.cancel()
    }

    func testDuplicateValidJvmConfirmationRevokesConfirmedAndInvalidatesTickets() throws {
        let member = try confirmation(role: .member)
        XCTAssertTrue(try member.prepare())
        let comparison = try XCTUnwrap(member.comparison())
        let signing = try XCTUnwrap(member.confirm(ticket: comparison))
        let sending = try XCTUnwrap(member.signed(ticket: signing, signature: V.memberSignature))
        let frame = try bytes(decoded(V.issuerFrame))
        XCTAssertTrue(try member.accept(chunk: frame))
        XCTAssertTrue(try member.sent(ticket: sending))
        XCTAssertEqual(try member.snapshot().phase.name, "CONFIRMED")
        XCTAssertFalse(try member.accept(chunk: frame))
        XCTAssertEqual(try member.snapshot().failure.name, "UNEXPECTED_CONFIRMATION")
        XCTAssertNil(try member.comparison())
        XCTAssertNil(try member.confirm(ticket: comparison))
        XCTAssertFalse(try member.sent(ticket: sending))
    }

    func testEveryTruncatedJvmFrameClosesWithoutAppleCryptoAndCannotResumeAfterEof() throws {
        let frame = try decoded(V.issuerFrame)
        for length in 1..<frame.count {
            var remoteCalls = 0
            let member = try confirmation(role: .member, onRemoteVerification: { remoteCalls += 1 })
            XCTAssertTrue(try member.prepare())
            let comparison = try XCTUnwrap(member.comparison())
            XCTAssertTrue(try member.accept(chunk: bytes(Data(frame.prefix(length)))))
            XCTAssertThrowsError(try member.finish(), "Prefix length \(length)")
            XCTAssertEqual(try member.snapshot().failure.name, "INVALID_FRAME")
            XCTAssertEqual(remoteCalls, 0)
            XCTAssertFalse(try member.accept(chunk: bytes(Data(frame.dropFirst(length)))))
            XCTAssertNil(try member.confirm(ticket: comparison))
            XCTAssertNil(try member.comparison())
        }
    }

    func testValidJvmFrameWithMalformedCoalescedTailDoesNotPublishPartialVerification() throws {
        let frame = try decoded(V.issuerFrame)
        let tails = [Data([0, 0, 0, 0]), Data([0, 0, 0, 1, 255]), Data([0, 0, 0, 1, 123])]
        for tail in tails {
            var remoteCalls = 0
            let member = try confirmation(role: .member, onRemoteVerification: { remoteCalls += 1 })
            XCTAssertTrue(try member.prepare())
            let sign = try XCTUnwrap(member.confirm(ticket: try XCTUnwrap(member.comparison())))
            let write = try XCTUnwrap(member.signed(ticket: sign, signature: V.memberSignature))
            XCTAssertThrowsError(try member.accept(chunk: bytes(frame + tail)))
            XCTAssertEqual(remoteCalls, 0)
            XCTAssertEqual(try member.snapshot().failure.name, "INVALID_FRAME")
            XCTAssertFalse(try member.snapshot().remoteConfirmed)
            XCTAssertFalse(try member.sent(ticket: write))
            XCTAssertFalse(try member.writeFailed(ticket: write))
            XCTAssertNil(try member.comparison())
        }
    }

    func testEofAfterValidJvmRemoteSignatureInvalidatesPendingLocalSignature() throws {
        let member = try confirmation(role: .member)
        XCTAssertTrue(try member.prepare())
        let comparison = try XCTUnwrap(member.comparison())
        let signing = try XCTUnwrap(member.confirm(ticket: comparison))
        XCTAssertTrue(try member.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertEqual(try member.snapshot().phase.name, "SIGNING")
        XCTAssertTrue(try member.snapshot().remoteConfirmed)
        try member.finish()
        XCTAssertEqual(try member.snapshot().failure.name, "TRANSPORT")
        XCTAssertNil(try member.signed(ticket: signing, signature: V.memberSignature))
        XCTAssertFalse(try member.signingFailed(ticket: signing))
        XCTAssertNil(try member.confirm(ticket: comparison))
        XCTAssertFalse(try member.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertEqual(try member.snapshot().failure.name, "TRANSPORT")
    }

    func testFailedLocalWriteAfterValidJvmSignatureCannotBeAcknowledgedLater() throws {
        let member = try confirmation(role: .member)
        XCTAssertTrue(try member.prepare())
        let signing = try XCTUnwrap(member.confirm(ticket: try XCTUnwrap(member.comparison())))
        let write = try XCTUnwrap(member.signed(ticket: signing, signature: V.memberSignature))
        XCTAssertTrue(try member.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertEqual(try member.snapshot().phase.name, "SENDING")
        XCTAssertTrue(try member.snapshot().remoteConfirmed)
        XCTAssertTrue(try member.writeFailed(ticket: write))
        XCTAssertEqual(try member.snapshot().failure.name, "TRANSPORT")
        XCTAssertFalse(try member.sent(ticket: write))
        XCTAssertFalse(try member.writeFailed(ticket: write))
        XCTAssertFalse(try member.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertNil(try member.comparison())
        XCTAssertEqual(try member.snapshot().failure.name, "TRANSPORT")
    }

    func testMalformedTailAfterConfirmedRevokesAndPreservesOriginalFailure() throws {
        let member = try confirmation(role: .member)
        XCTAssertTrue(try member.prepare())
        let sign = try XCTUnwrap(member.confirm(ticket: try XCTUnwrap(member.comparison())))
        let write = try XCTUnwrap(member.signed(ticket: sign, signature: V.memberSignature))
        XCTAssertTrue(try member.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertTrue(try member.sent(ticket: write))
        XCTAssertEqual(try member.snapshot().phase.name, "CONFIRMED")
        XCTAssertThrowsError(try member.accept(chunk: bytes(Data([0, 0, 0, 0]))))
        XCTAssertEqual(try member.snapshot().failure.name, "INVALID_FRAME")
        try member.finish()
        member.cancel()
        member.block()
        member.leaveGroup()
        member.transportFailed()
        XCTAssertFalse(try member.sent(ticket: write))
        XCTAssertFalse(try member.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertNil(try member.comparison())
        XCTAssertEqual(try member.snapshot().failure.name, "INVALID_FRAME")
        XCTAssertFalse(try member.snapshot().remoteConfirmed)
    }

    func testIdenticalPublicTranscriptCannotTransferAnotherInstancesCallbackTickets() throws {
        // Identical nonces are test-only; real reconnects must use fresh OS randomness.
        let first = try confirmation(role: .member)
        let replacement = try confirmation(role: .member)
        XCTAssertTrue(try first.prepare())
        XCTAssertTrue(try replacement.prepare())
        let oldComparison = try XCTUnwrap(first.comparison())
        let comparison = try XCTUnwrap(replacement.comparison())
        XCTAssertEqual(data(oldComparison.bytes), data(comparison.bytes))
        XCTAssertNil(try replacement.confirm(ticket: oldComparison))
        let oldSigning = try XCTUnwrap(first.confirm(ticket: oldComparison))
        let signing = try XCTUnwrap(replacement.confirm(ticket: comparison))
        XCTAssertNil(try replacement.signed(ticket: oldSigning, signature: V.memberSignature))
        XCTAssertFalse(try replacement.signingFailed(ticket: oldSigning))
        let oldWrite = try XCTUnwrap(first.signed(ticket: oldSigning, signature: V.memberSignature))
        let write = try XCTUnwrap(replacement.signed(ticket: signing, signature: V.memberSignature))
        XCTAssertEqual(data(oldWrite.bytes), data(write.bytes))
        XCTAssertFalse(try replacement.sent(ticket: oldWrite))
        XCTAssertFalse(try replacement.writeFailed(ticket: oldWrite))
        XCTAssertEqual(try replacement.snapshot().phase.name, "SENDING")
        XCTAssertFalse(try replacement.snapshot().remoteConfirmed)
        XCTAssertTrue(try replacement.accept(chunk: bytes(decoded(V.issuerFrame))))
        XCTAssertTrue(try replacement.sent(ticket: write))
        XCTAssertEqual(try replacement.snapshot().phase.name, "CONFIRMED")
        first.cancel()
        replacement.cancel()
    }

    private func confirmation(
        role: IosGroupAdmissionRole, memberNonce: String = "2", payload: String = V.evidence,
        reversedFeatureOrder: Bool = false, additionalMemberFeature: Bool = false,
        onRemoteVerification: @escaping () -> Void = {}
    ) throws -> IosGroupAdmissionConfirmation {
        let localID = role == .issuer ? V.issuer : V.member
        let remoteID = role == .issuer ? V.member : V.issuer
        func bootstrap(id: String, peer: String, nonce: String) throws -> IosHandshakeV1 {
            let featuresJson: String
            if additionalMemberFeature, id == V.member { featuresJson = "[\"text\",\"receipts\",\"files\"]" }
            else { featuresJson = reversedFeatureOrder ? "[\"receipts\",\"text\"]" : "[\"text\",\"receipts\"]" }
            return try IosHandshakeV1.companion.create(
                localIdentity: id, localNonce: String(repeating: nonce, count: 64),
                capabilitiesJson: "{\"version\":1,\"supportedFeatures\":\(featuresJson),\"requiredFeatures\":[\"text\"]}",
                authenticatedLocalIdentity: id, selectedPeerIdentity: peer, authenticatedPeerIdentity: peer,
                selectedAtMillis: 0, nowMillis: { KotlinLong(longLong: 17) },
                verifyRemoteSignature: { _, _ in KotlinBoolean(bool: false) }
            )
        }
        let owner = try bootstrap(id: localID, peer: remoteID, nonce: role == .issuer ? "1" : memberNonce)
        let peer = try bootstrap(id: remoteID, peer: localID, nonce: role == .issuer ? memberNonce : "1")
        XCTAssertTrue(try owner.sent(ticket: try XCTUnwrap(owner.start())))
        XCTAssertTrue(try owner.accept(chunk: try XCTUnwrap(peer.start()).bytes))
        let offers = try XCTUnwrap(owner.releaseForGroupAdmission())
        peer.cancel()
        let evidence = try suppliedEvidence(payload)
        let certificates = try GroupAdmissionEvidenceCertificates.decode(evidence)
        let remoteCertificate = try ApplePublicCertificate.decode(
            der: decoded(role == .issuer ? V.memberDer : V.issuerDer), expectedID: remoteID
        )
        let context = try IosGroupAdmissionContext.companion.create(
            offers: offers, expectedGroup: V.group, expectedFounder: V.issuer, evidence: evidence, role: role
        )
        return try IosGroupAdmissionConfirmation.companion.create(
            context: context, selectedAtMillis: 0, nowMillis: { KotlinLong(longLong: 17) },
            verifyAdmissionSignature: { id, canonical, signature in
                guard let certificate = certificates[id] else { return KotlinBoolean(bool: false) }
                return KotlinBoolean(bool: ApplePublicCertificate.verifySignature(
                    certificate: certificate, expectedID: id, message: self.data(canonical),
                    signature: signature, now: V.verificationDate
                ))
            },
            verifyRemoteSignature: { canonical, signature in
                onRemoteVerification()
                return KotlinBoolean(bool: ApplePublicCertificate.verifySignature(
                    certificate: remoteCertificate, expectedID: remoteID, message: self.data(canonical),
                    signature: signature, now: V.verificationDate
                ))
            }
        )
    }

    private func suppliedEvidence(_ payload: String) throws -> IosGroupAdmissionEvidence {
        try IosGroupAdmissionEvidence.companion.decode(payload: bytes(decoded(payload)))
    }

    private func confirmationFrame(sender: String, recipient: String, signature: String) throws -> Data {
        let payload = try JSONSerialization.data(withJSONObject: [
            "version": 1, "type": "GROUP_CONFIRM", "sender": sender, "recipient": recipient, "signature": signature,
        ], options: [.sortedKeys])
        let size = UInt32(payload.count)
        return Data([UInt8(size >> 24), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)]) + payload
    }

    private func decoded(_ base64: String) throws -> Data { try XCTUnwrap(Data(base64Encoded: base64)) }
    private func hash(_ bytes: KotlinByteArray) -> String {
        SHA256.hash(data: data(bytes)).map { String(format: "%02x", $0) }.joined()
    }
    private func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }
    private func bytes(_ data: Data) -> KotlinByteArray {
        let result = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() { result.set(index: Int32(index), value: Int8(bitPattern: byte)) }
        return result
    }
}
