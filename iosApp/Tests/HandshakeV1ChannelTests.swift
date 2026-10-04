import Foundation
import Network
import Security
import XCTest
import LanternIdentity
import LanternUI
@testable import Lantern

/// Real mutual pinned TLS, Keychain identities and OS signatures. Explicit UI actions are fixtures.
final class HandshakeV1ChannelTests: XCTestCase {
    private let queue = DispatchQueue(label: "dev.lantern.tests.bootstrap-v1")
    private var channels: [HandshakeV1Channel] = []
    private var scriptedPeers: [ScriptedPeer] = []
    private var connections: [NWConnection] = []
    private var listeners: [NWListener] = []
    private var namespaces: [String] = []

    override func tearDown() {
        queue.sync {
            channels.forEach { $0.cancel() }
            channels.removeAll()
            scriptedPeers.forEach { $0.stop() }
            scriptedPeers.removeAll()
            connections.forEach { $0.cancel() }
            connections.removeAll()
            listeners.forEach { $0.cancel() }
            listeners.removeAll()
        }
        for namespace in namespaces {
            let queries: [[String: Any]] = [
                [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: Data("\(namespace).key".utf8)],
                [kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: "\(namespace).certificate"],
                [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: namespace],
            ]
            queries.forEach { SecItemDelete($0 as CFDictionary) }
        }
        super.tearDown()
    }

    func testRealTLSAndSignaturesReachReadyOnlyAfterBothExplicitConfirmations() throws {
        let pair = try readyPair()
        let leftReady = expectation(description: "left bootstrap ready")
        let rightReady = expectation(description: "right bootstrap ready")
        try queue.sync {
            weak var left: HandshakeV1Channel?
            weak var right: HandshakeV1Channel?
            var leftCode: (IosHandshakeV1Comparison, String)?
            var rightCode: (IosHandshakeV1Comparison, String)?
            var confirmed = false
            var leftDone = false
            var rightDone = false
            func confirmBoth() {
                guard !confirmed, let leftCode, let rightCode else { return }
                XCTAssertEqual(leftCode.1, rightCode.1)
                XCTAssertEqual(leftCode.1.count, 64)
                confirmed = true // Simulated explicit comparison on both physical screens, test only.
                left?.confirm(leftCode.0)
                right?.confirm(rightCode.0)
            }
            left = try adopt(pair, client: true, onSnapshot: { snapshot in
                if snapshot.phase.name == "READY", !leftDone {
                    XCTAssertTrue(confirmed)
                    XCTAssertEqual(snapshot.negotiatedFeatures, ["receipts", "text"])
                    leftDone = true
                    leftReady.fulfill()
                }
            }, onComparison: { ticket, code in leftCode = (ticket, code); confirmBoth() })
            right = try adopt(pair, client: false, onSnapshot: { snapshot in
                if snapshot.phase.name == "READY", !rightDone {
                    XCTAssertTrue(confirmed)
                    rightDone = true
                    rightReady.fulfill()
                }
            }, onComparison: { ticket, code in rightCode = (ticket, code); confirmBoth() })
            left?.start()
            left?.start() // Duplicate start must not send a duplicate HELLO to the strict remote machine.
            right?.start()
        }
        wait(for: [leftReady, rightReady], timeout: 10)
    }

    func testIdleDeadlineClosesTransportWithoutStartOrIncomingBytes() throws {
        let pair = try readyPair()
        let expired = expectation(description: "idle selection expired")
        let eof = expectation(description: "remote observes physical transport closure")
        try queue.sync {
            pair.server.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, complete, error in
                XCTAssertTrue(data == nil || data!.isEmpty)
                XCTAssertTrue(complete || error != nil)
                eof.fulfill()
            }
            _ = try adopt(pair, client: true, selectedAt: HandshakeV1Channel.monotonicMillis() - 119_500, onClosed: { failure in
                if case .bootstrap(let reason) = failure { XCTAssertEqual(reason.name, "EXPIRED") }
                else { XCTFail("Expected bootstrap expiration") }
                expired.fulfill()
            })
            // No start(), reader or state inspection: only the independent deadline can close it.
        }
        wait(for: [expired, eof], timeout: 5)
    }

    func testSelectionMismatchRejectsAdoptionAndClosesTransferredConnection() throws {
        let pair = try readyPair()
        let eof = expectation(description: "rejected adoption closed transport")
        try queue.sync {
            pair.server.receive(minimumIncompleteLength: 1, maximumLength: 1024) { _, _, complete, error in
                XCTAssertTrue(complete || error != nil)
                eof.fulfill()
            }
            XCTAssertThrowsError(try HandshakeV1Channel(
                connection: pair.client, identity: pair.clientIdentity, transport: pair.clientTransport,
                selectedPeerID: String(repeating: "0", count: 64), selectedAtMillis: pair.selectedAt,
                queue: queue, onSnapshot: { _ in XCTFail("Invalid TLS adopted") },
                onComparison: { _, _ in XCTFail("Invalid TLS comparison") }, onClosed: { _ in }
            ))
        }
        wait(for: [eof], timeout: 5)
    }

    func testDifferentLocalSignerCannotAdoptTransportIdentity() throws {
        let pair = try readyPair()
        let eof = expectation(description: "local identity mismatch closes transport")
        try queue.sync {
            pair.server.receive(minimumIncompleteLength: 1, maximumLength: 1024) { _, _, complete, error in
                XCTAssertTrue(complete || error != nil)
                eof.fulfill()
            }
            XCTAssertThrowsError(try HandshakeV1Channel(
                connection: pair.client, identity: pair.serverIdentity, transport: pair.clientTransport,
                selectedPeerID: pair.serverIdentity.id, selectedAtMillis: pair.selectedAt,
                queue: queue, onSnapshot: { _ in XCTFail("Wrong local signer adopted") },
                onComparison: { _, _ in XCTFail("Wrong local signer comparison") }, onClosed: { _ in }
            ))
        }
        wait(for: [eof], timeout: 5)
    }

    func testPeerDisconnectInvalidatesBootstrapWithoutReady() throws {
        let pair = try readyPair()
        let closed = expectation(description: "peer disconnect closes owner")
        try queue.sync {
            pair.server.receive(minimumIncompleteLength: 1, maximumLength: 5124) { data, _, _, error in
                XCTAssertNil(error)
                XCTAssertFalse(data?.isEmpty ?? true)
                pair.server.cancel()
            }
            let owner = try adopt(pair, client: true, onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "READY")
            }, onClosed: { failure in
                switch failure {
                case .transport: break
                case .bootstrap(let reason): XCTAssertEqual(reason.name, "TRANSPORT")
                default: XCTFail("Unexpected disconnect classification")
                }
                closed.fulfill()
            })
            owner.start()
        }
        wait(for: [closed], timeout: 5)
    }

    func testCancelledChannelIgnoresRealSignatureCompletionFromPreviousAttempt() throws {
        let pair = try readyPair()
        let cancelled = expectation(description: "cancelled with signature pending")
        let drained = expectation(description: "late signature callback drained")
        let cryptoQueue = DispatchQueue(label: "dev.lantern.tests.delayed-real-signer")
        let gate = DispatchSemaphore(value: 0)
        cryptoQueue.async { gate.wait() }
        defer { gate.signal() }
        try queue.sync {
            weak var left: HandshakeV1Channel?
            left = try adopt(pair, client: true, signingQueue: cryptoQueue, onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "READY")
            }, onComparison: { ticket, _ in
                left?.confirm(ticket)
                left?.cancel()
                // Marker runs after the real signer, then after its old completion on the owner queue.
                cryptoQueue.async { self.queue.async { drained.fulfill() } }
            }, onClosed: { failure in
                if case .cancelled = failure {} else { XCTFail("Expected explicit cancellation") }
                cancelled.fulfill()
            })
            let right = try adopt(pair, client: false, onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "READY")
            }, onClosed: { _ in })
            left?.start()
            right.start()
        }
        wait(for: [cancelled], timeout: 5)
        gate.signal()
        wait(for: [drained], timeout: 5)
    }

    func testApprovalSignedByDifferentKeyIsRejectedAndClosesTransport() throws {
        let pair = try readyPair()
        let rejected = expectation(description: "wrong signing key rejected")
        let eof = expectation(description: "wrong proof closes actual TLS connection")
        try queue.sync {
            let remote = try scriptedPeer(pair, onComparison: { peer, comparison in
                // Valid DER/ECDSA proof, but not from the identity pinned by the client's TLS.
                let proof = try peer.approval(comparison, signer: pair.clientIdentity)
                peer.send(proof)
            }, onEOF: { snapshot in
                XCTAssertFalse(snapshot.remoteApproved)
                eof.fulfill()
            })
            let owner = try adopt(pair, client: true, onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "READY")
                XCTAssertFalse(snapshot.remoteApproved)
            }, onClosed: { failure in
                if case .bootstrap(let reason) = failure { XCTAssertEqual(reason.name, "INVALID_SIGNATURE") }
                else { XCTFail("Expected invalid signature") }
                rejected.fulfill()
            })
            try remote.start()
            owner.start()
        }
        wait(for: [rejected, eof], timeout: 10)
    }

    func testPreviouslyAcceptedApprovalCannotBeReplayedOnNewTLSAttempt() throws {
        let first = try readyPair()
        let accepted = expectation(description: "original OS proof accepted without local confirmation")
        var oldProof: Data?
        var oldComparison: Data?
        var originalOwner: HandshakeV1Channel?
        var originalRemote: ScriptedPeer?
        try queue.sync {
            originalRemote = try scriptedPeer(first, onComparison: { peer, comparison in
                oldComparison = Self.data(comparison.bytes)
                let proof = try peer.approval(comparison, signer: first.serverIdentity)
                oldProof = Self.data(proof.bytes)
                peer.send(proof)
            })
            var proofObserved = false
            originalOwner = try adopt(first, client: true, onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "READY")
                if snapshot.remoteApproved, !proofObserved {
                    XCTAssertEqual(snapshot.phase.name, "AWAITING_CONFIRMATION")
                    proofObserved = true
                    accepted.fulfill()
                }
            })
            try originalRemote?.start()
            originalOwner?.start()
        }
        wait(for: [accepted], timeout: 10)
        let captured = try queue.sync { () throws -> (Data, Data) in
            originalOwner?.cancel()
            originalRemote?.stop()
            return (try XCTUnwrap(oldProof), try XCTUnwrap(oldComparison))
        }

        // Same persistent identities/pins, new real TLS connection and fresh HELLO nonces.
        let replacement = try readyPair(clientIdentity: first.clientIdentity, serverIdentity: first.serverIdentity)
        let rejected = expectation(description: "previously valid proof rejected in replacement attempt")
        let eof = expectation(description: "replay closes replacement TLS connection")
        try queue.sync {
            let remote = try scriptedPeer(replacement, onComparison: { peer, comparison in
                XCTAssertNotEqual(Self.data(comparison.bytes), captured.1)
                peer.replay(captured.0) // Exact captured bytes, no re-encoding or replacement signature.
            }, onEOF: { snapshot in
                XCTAssertFalse(snapshot.remoteApproved)
                eof.fulfill()
            })
            let owner = try adopt(replacement, client: true, onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "READY")
                XCTAssertFalse(snapshot.remoteApproved)
            }, onClosed: { failure in
                if case .bootstrap(let reason) = failure { XCTAssertEqual(reason.name, "INVALID_SIGNATURE") }
                else { XCTFail("Expected replay rejection") }
                rejected.fulfill()
            })
            try remote.start()
            owner.start()
        }
        wait(for: [rejected, eof], timeout: 10)
    }

    func testPreviousUITicketCannotConfirmReplacementTLSWithSameIdentities() throws {
        let first = try readyPair()
        let oldComparisonShown = expectation(description: "original UI comparison retained")
        let oldProofAccepted = expectation(description: "original remote proof accepted")
        let oldEOF = expectation(description: "cancelled original attempt closes TLS")
        var originalOwner: HandshakeV1Channel?
        var oldComparison: (IosHandshakeV1Comparison, String)?
        var originalClosedCount = 0
        try queue.sync {
            var proofObserved = false
            let remote = try scriptedPeer(first, onComparison: { peer, ticket in
                peer.send(try peer.approval(ticket, signer: first.serverIdentity))
            }, onEOF: { snapshot in
                XCTAssertFalse(snapshot.remoteApproved)
                oldEOF.fulfill()
            })
            originalOwner = try adopt(first, client: true, onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "READY")
                if snapshot.remoteApproved, !proofObserved {
                    XCTAssertEqual(snapshot.phase.name, "AWAITING_CONFIRMATION")
                    proofObserved = true
                    oldProofAccepted.fulfill()
                }
            }, onComparison: { ticket, code in
                XCTAssertNil(oldComparison)
                oldComparison = (ticket, code)
                oldComparisonShown.fulfill()
            }, onClosed: { failure in
                originalClosedCount += 1
                XCTAssertEqual(originalClosedCount, 1)
                if case .cancelled = failure {} else { XCTFail("Expected original UI cancellation") }
            })
            try remote.start()
            originalOwner?.start()
        }
        wait(for: [oldComparisonShown, oldProofAccepted], timeout: 10)
        let captured = try queue.sync { () throws -> (IosHandshakeV1Comparison, String) in
            originalOwner?.cancel()
            return try XCTUnwrap(oldComparison)
        }
        wait(for: [oldEOF], timeout: 5)

        // Same Keychain identities and selected pins, fresh real TLS connection and OS nonces.
        let replacement = try readyPair(clientIdentity: first.clientIdentity, serverIdentity: first.serverIdentity)
        let remoteApproved = expectation(description: "replacement proof awaits current local UI confirmation")
        let staleWorkDrained = expectation(description: "old UI action and any signing work drained")
        let leftReady = expectation(description: "replacement client ready after current confirmation")
        let rightReady = expectation(description: "replacement server ready after current confirmation")
        let cryptoQueue = DispatchQueue(label: "dev.lantern.tests.replacement-ticket-signer")
        weak var left: HandshakeV1Channel?
        weak var right: HandshakeV1Channel?
        var leftCode: (IosHandshakeV1Comparison, String)?
        var rightCode: (IosHandshakeV1Comparison, String)?
        var peerConfirmed = false
        var currentConfirmed = false
        var proofObserved = false
        var leftPhase: String?
        var leftRemoteApproved = false
        var leftReadyCount = 0
        var rightReadyCount = 0
        try queue.sync {
            func confirmPeerAfterComparison() {
                guard !peerConfirmed, let leftCode, let rightCode else { return }
                XCTAssertEqual(leftCode.1, rightCode.1)
                XCTAssertEqual(leftCode.1.count, 64)
                XCTAssertNotEqual(leftCode.1, captured.1)
                peerConfirmed = true // Only the peer confirms; local UI is deliberately withheld.
                right?.confirm(rightCode.0)
            }
            left = try adopt(replacement, client: true, signingQueue: cryptoQueue, onSnapshot: { snapshot in
                leftPhase = snapshot.phase.name
                leftRemoteApproved = snapshot.remoteApproved
                if snapshot.phase.name == "READY" {
                    XCTAssertTrue(currentConfirmed)
                    leftReadyCount += 1
                    XCTAssertEqual(leftReadyCount, 1)
                    if leftReadyCount == 1 { leftReady.fulfill() }
                } else if snapshot.remoteApproved, snapshot.phase.name == "AWAITING_CONFIRMATION", !proofObserved {
                    proofObserved = true
                    remoteApproved.fulfill()
                }
            }, onComparison: { ticket, code in
                XCTAssertNil(leftCode)
                leftCode = (ticket, code)
                confirmPeerAfterComparison()
            })
            right = try adopt(replacement, client: false, onSnapshot: { snapshot in
                if snapshot.phase.name == "READY" {
                    XCTAssertTrue(currentConfirmed)
                    rightReadyCount += 1
                    XCTAssertEqual(rightReadyCount, 1)
                    if rightReadyCount == 1 { rightReady.fulfill() }
                }
            }, onComparison: { ticket, code in
                XCTAssertNil(rightCode)
                rightCode = (ticket, code)
                confirmPeerAfterComparison()
            })
            left?.start()
            right?.start()
        }
        wait(for: [remoteApproved], timeout: 10)
        queue.sync {
            XCTAssertEqual(leftPhase, "AWAITING_CONFIRMATION")
            XCTAssertTrue(leftRemoteApproved)
            originalOwner?.start()
            originalOwner?.confirm(captured.0)
            XCTAssertEqual(originalClosedCount, 1)
            left?.confirm(captured.0) // Old UI must not become a signature request for the replacement.
            XCTAssertEqual(leftPhase, "AWAITING_CONFIRMATION")
            XCTAssertTrue(leftRemoteApproved)
            // A serial marker drains any erroneous signer job and its owner callback without sleeps.
            cryptoQueue.async { self.queue.async { staleWorkDrained.fulfill() } }
        }
        wait(for: [staleWorkDrained], timeout: 5)
        try queue.sync {
            XCTAssertEqual(leftPhase, "AWAITING_CONFIRMATION")
            XCTAssertTrue(leftRemoteApproved)
            XCTAssertEqual(leftReadyCount, 0)
            XCTAssertEqual(rightReadyCount, 0)
            currentConfirmed = true // Explicit confirmation of the replacement's retained UI ticket.
            left?.confirm(try XCTUnwrap(leftCode).0)
        }
        wait(for: [leftReady, rightReady], timeout: 10)
    }

    func testDeadlineClosesTransportWhileRealSignerIsPendingAndIgnoresLateCompletion() throws {
        let pair = try readyPair()
        let expired = expectation(description: "deadline closes owner with signature still pending")
        let approved = expectation(description: "valid remote proof cannot bypass pending local signature")
        let eof = expectation(description: "expired owner sends no approval and closes TLS")
        let drained = expectation(description: "real signature and late callback drained after expiration")
        let cryptoQueue = DispatchQueue(label: "dev.lantern.tests.expiring-real-signer")
        let gate = DispatchSemaphore(value: 0)
        cryptoQueue.async { gate.wait() }
        defer { gate.signal() }
        try queue.sync {
            weak var owner: HandshakeV1Channel?
            var confirmationRequested = false
            var proofObserved = false
            var closedCount = 0
            let remote = try scriptedPeer(pair, onComparison: { peer, comparison in
                peer.send(try peer.approval(comparison, signer: pair.serverIdentity))
            }, onEOF: { snapshot in
                XCTAssertFalse(snapshot.remoteApproved) // No local APPROVE escaped before closure.
                eof.fulfill()
            })
            owner = try adopt(pair, client: true,
                              selectedAt: HandshakeV1Channel.monotonicMillis() - 117_000,
                              signingQueue: cryptoQueue, onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "READY")
                if snapshot.remoteApproved, snapshot.phase.name == "SIGNING_APPROVAL", !proofObserved {
                    proofObserved = true
                    approved.fulfill()
                }
            }, onComparison: { comparison, _ in
                confirmationRequested = true
                owner?.confirm(comparison)
                // The marker is behind the real OS signing job and its completion on the owner queue.
                cryptoQueue.async { self.queue.async { drained.fulfill() } }
            }, onClosed: { failure in
                closedCount += 1
                XCTAssertEqual(closedCount, 1)
                XCTAssertTrue(confirmationRequested)
                XCTAssertTrue(proofObserved)
                if case .bootstrap(let reason) = failure { XCTAssertEqual(reason.name, "EXPIRED") }
                else { XCTFail("Expected expiration while signing") }
                expired.fulfill()
            })
            try remote.start()
            owner?.start()
        }
        wait(for: [approved, expired, eof], timeout: 10)
        gate.signal()
        wait(for: [drained], timeout: 5)
    }

    func testMalformedFramesAreRejectedAndCloseActualTLSConnection() throws {
        let frames: [Data] = [
            Data([0, 0, 0, 0]),                 // Zero payload length.
            Data([0, 0, 0x14, 0x01]),          // 5121, just beyond the Kotlin limit.
            Data([0xff, 0xff, 0xff, 0xff]),    // Unsigned length must not become negative.
            Data([0, 0, 0, 1, 0xff]),          // Invalid UTF-8.
            Data([0, 0, 0, 2, 0x7b, 0x7d]),   // JSON object without a bootstrap envelope.
        ]
        for frame in frames {
            try assertRejectedInput(expectedFailure: "INVALID_FRAME") { peer in
                peer.replay(frame)
            }
        }
    }

    func testPeerDisconnectAfterTruncatedWriteInvalidatesBootstrapWithoutReady() throws {
        for headerOnly in [true, false] {
            let pair = try readyPair()
            let written = expectation(description: "truncated TLS write completed")
            let disconnected = expectation(description: "peer disconnect invalidates bootstrap")
            weak var owner: HandshakeV1Channel?
            var comparison: IosHandshakeV1Comparison?
            var closedCount = 0
            try queue.sync {
                let remote = try scriptedPeer(pair, onComparison: { peer, _ in
                    let hello = try peer.helloFrame()
                    let prefix = Data(hello.prefix(headerOnly ? 3 : hello.count - 1))
                    // Completion proves local processing, not that the decoder consumed the prefix.
                    // Exact truncation/EOF semantics are covered separately at the Native bridge.
                    peer.disconnectAfterSending(prefix) { written.fulfill() }
                })
                owner = try adopt(pair, client: true, onSnapshot: { snapshot in
                    XCTAssertNotEqual(snapshot.phase.name, "READY")
                    XCTAssertFalse(snapshot.remoteApproved)
                }, onComparison: { ticket, _ in comparison = ticket }, onClosed: { failure in
                    closedCount += 1
                    XCTAssertEqual(closedCount, 1)
                    Self.assertTransportClosure(failure)
                    disconnected.fulfill()
                })
                try remote.start()
                owner?.start()
            }
            wait(for: [written, disconnected], timeout: 10)
            queue.sync {
                owner?.start()
                if let comparison { owner?.confirm(comparison) }
                owner?.cancel()
                XCTAssertEqual(closedCount, 1)
            }
        }
    }

    func testReadyIsRevokedOnceByCancellationOrPeerDisconnect() throws {
        for cancelLocally in [true, false] {
            let pair = try readyPair()
            let leftReady = expectation(description: "left ready before revocation")
            let rightReady = expectation(description: "right ready before revocation")
            let leftClosed = expectation(description: "left ready revoked")
            let rightClosed = expectation(description: "right ready revoked")
            weak var left: HandshakeV1Channel?
            weak var right: HandshakeV1Channel?
            var leftCode: (IosHandshakeV1Comparison, String)?
            var rightCode: (IosHandshakeV1Comparison, String)?
            var confirmed = false
            var leftReadyCount = 0
            var rightReadyCount = 0
            var leftClosedCount = 0
            var rightClosedCount = 0
            try queue.sync {
                func confirmBoth() {
                    guard !confirmed, let leftCode, let rightCode else { return }
                    XCTAssertEqual(leftCode.1, rightCode.1)
                    XCTAssertEqual(leftCode.1.count, 64)
                    confirmed = true // Explicit comparison simulated only in this test.
                    left?.confirm(leftCode.0)
                    right?.confirm(rightCode.0)
                }
                left = try adopt(pair, client: true, onSnapshot: { snapshot in
                    XCTAssertEqual(leftClosedCount, 0)
                    if snapshot.phase.name == "READY" {
                        XCTAssertTrue(confirmed)
                        XCTAssertTrue(snapshot.remoteApproved)
                        leftReadyCount += 1
                        XCTAssertEqual(leftReadyCount, 1)
                        if leftReadyCount == 1 { leftReady.fulfill() }
                    }
                }, onComparison: { ticket, code in leftCode = (ticket, code); confirmBoth() }, onClosed: { failure in
                    leftClosedCount += 1
                    XCTAssertEqual(leftClosedCount, 1)
                    XCTAssertEqual(leftReadyCount, 1)
                    XCTAssertEqual(rightReadyCount, 1)
                    if cancelLocally {
                        if case .cancelled = failure {} else { XCTFail("Expected explicit cancellation") }
                    } else { Self.assertTransportClosure(failure) }
                    leftClosed.fulfill()
                })
                right = try adopt(pair, client: false, onSnapshot: { snapshot in
                    XCTAssertEqual(rightClosedCount, 0)
                    if snapshot.phase.name == "READY" {
                        XCTAssertTrue(confirmed)
                        XCTAssertTrue(snapshot.remoteApproved)
                        rightReadyCount += 1
                        XCTAssertEqual(rightReadyCount, 1)
                        if rightReadyCount == 1 { rightReady.fulfill() }
                    }
                }, onComparison: { ticket, code in rightCode = (ticket, code); confirmBoth() }, onClosed: { failure in
                    rightClosedCount += 1
                    XCTAssertEqual(rightClosedCount, 1)
                    XCTAssertEqual(leftReadyCount, 1)
                    XCTAssertEqual(rightReadyCount, 1)
                    Self.assertTransportClosure(failure)
                    rightClosed.fulfill()
                })
                left?.start()
                right?.start()
            }
            wait(for: [leftReady, rightReady], timeout: 10)
            queue.sync {
                if cancelLocally { left?.cancel() } else { pair.server.cancel() }
            }
            wait(for: [leftClosed, rightClosed], timeout: 5)
            queue.sync {
                left?.start()
                right?.start()
                if let leftCode { left?.confirm(leftCode.0) }
                if let rightCode { right?.confirm(rightCode.0) }
                left?.cancel()
                right?.cancel()
                XCTAssertEqual(leftClosedCount, 1)
                XCTAssertEqual(rightClosedCount, 1)
                XCTAssertEqual(leftReadyCount, 1)
                XCTAssertEqual(rightReadyCount, 1)
            }
        }
    }

    private static func assertTransportClosure(_ failure: HandshakeV1ChannelFailure) {
        // A Network error/state callback and a clean receive EOF can race; both revoke progress.
        switch failure {
        case .transport: break
        case .bootstrap(let reason): XCTAssertEqual(reason.name, "TRANSPORT")
        default: XCTFail("Expected transport closure")
        }
    }

    func testDuplicateHelloIsRejectedWithoutLocalConfirmation() throws {
        try assertRejectedInput(expectedFailure: "UNEXPECTED_MESSAGE") { peer in
            peer.replay(try peer.helloFrame())
        }
    }

    func testDuplicateAcceptedApprovalIsRejectedWithoutReachingReady() throws {
        let pair = try readyPair()
        let accepted = expectation(description: "first real OS approval accepted")
        let rejected = expectation(description: "duplicate approval rejected")
        let eof = expectation(description: "duplicate approval closes actual TLS connection")
        try queue.sync {
            weak var remote: ScriptedPeer?
            var proof: Data?
            var proofObserved = false
            var closedCount = 0
            remote = try scriptedPeer(pair, onComparison: { peer, comparison in
                let ticket = try peer.approval(comparison, signer: pair.serverIdentity)
                proof = Self.data(ticket.bytes)
                peer.send(ticket)
            }, onEOF: { snapshot in
                XCTAssertFalse(snapshot.remoteApproved)
                eof.fulfill()
            })
            let owner = try adopt(pair, client: true, onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "READY")
                if snapshot.remoteApproved, !proofObserved {
                    XCTAssertEqual(snapshot.phase.name, "AWAITING_CONFIRMATION")
                    proofObserved = true
                    accepted.fulfill()
                    // Only replay once the owner's Kotlin machine actually accepted the first proof.
                    guard let proof, let remote else { XCTFail("Missing original proof/peer"); return }
                    remote.replay(proof)
                }
            }, onClosed: { failure in
                closedCount += 1
                XCTAssertEqual(closedCount, 1)
                XCTAssertTrue(proofObserved)
                if case .bootstrap(let reason) = failure { XCTAssertEqual(reason.name, "UNEXPECTED_MESSAGE") }
                else { XCTFail("Expected duplicate approval rejection") }
                rejected.fulfill()
            })
            try remote?.start()
            owner.start()
        }
        wait(for: [accepted, rejected, eof], timeout: 10)
    }

    /// Each hostile input uses a fresh real TLS pair, never a reset of a failed bootstrap.
    private func assertRejectedInput(
        expectedFailure: String,
        inject: @escaping (ScriptedPeer) throws -> Void
    ) throws {
        let pair = try readyPair()
        let rejected = expectation(description: "input rejected as \(expectedFailure)")
        let eof = expectation(description: "rejected input closes actual TLS connection")
        var owner: HandshakeV1Channel?
        var comparison: IosHandshakeV1Comparison?
        var closedCount = 0
        try queue.sync {
            var comparisonCount = 0
            let remote = try scriptedPeer(pair, onComparison: { peer, _ in
                try inject(peer)
            }, onEOF: { snapshot in
                XCTAssertFalse(snapshot.remoteApproved)
                eof.fulfill()
            })
            owner = try adopt(pair, client: true, onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "READY")
                XCTAssertFalse(snapshot.remoteApproved)
            }, onComparison: { ticket, _ in
                comparisonCount += 1
                XCTAssertEqual(comparisonCount, 1)
                comparison = ticket // No local confirmation before rejection.
            }, onClosed: { failure in
                closedCount += 1
                XCTAssertEqual(closedCount, 1)
                if case .bootstrap(let reason) = failure { XCTAssertEqual(reason.name, expectedFailure) }
                else { XCTFail("Expected typed bootstrap failure \(expectedFailure)") }
                rejected.fulfill()
            })
            try remote.start()
            owner?.start()
        }
        wait(for: [rejected, eof], timeout: 10)
        queue.sync {
            // Old UI actions cannot reopen the failed attempt or publish a second closure.
            owner?.start()
            if let comparison { owner?.confirm(comparison) }
            owner?.cancel()
            XCTAssertEqual(closedCount, 1)
        }
    }

    private struct Pair {
        let client: NWConnection
        let server: NWConnection
        let clientIdentity: AppleIdentity
        let serverIdentity: AppleIdentity
        let clientTransport: AppleTLSTransport
        let serverTransport: AppleTLSTransport
        let selectedAt: Int64
    }

    private func adopt(
        _ pair: Pair, client: Bool, selectedAt: Int64? = nil,
        signingQueue: DispatchQueue = .global(qos: .userInitiated),
        onSnapshot: @escaping (IosHandshakeV1Snapshot) -> Void = { _ in },
        onComparison: @escaping (IosHandshakeV1Comparison, String) -> Void = { _, _ in },
        onClosed: @escaping (HandshakeV1ChannelFailure) -> Void = { failure in
            if case .cancelled = failure {} else { XCTFail("Unexpected bootstrap closure") }
        }
    ) throws -> HandshakeV1Channel {
        let channel = try HandshakeV1Channel(
            connection: client ? pair.client : pair.server,
            identity: client ? pair.clientIdentity : pair.serverIdentity,
            transport: client ? pair.clientTransport : pair.serverTransport,
            selectedPeerID: client ? pair.serverIdentity.id : pair.clientIdentity.id,
            selectedAtMillis: selectedAt ?? pair.selectedAt, queue: queue, signingQueue: signingQueue,
            onSnapshot: onSnapshot, onComparison: onComparison, onClosed: onClosed
        )
        channels.append(channel)
        return channel
    }

    private func readyPair(clientIdentity suppliedClient: AppleIdentity? = nil,
                           serverIdentity suppliedServer: AppleIdentity? = nil) throws -> Pair {
        let clientIdentity = try suppliedClient ?? identity()
        let serverIdentity = try suppliedServer ?? identity()
        let clientTransport = AppleTLSTransport(identity: clientIdentity)
        let serverTransport = AppleTLSTransport(identity: serverIdentity)
        let selectedAt = HandshakeV1Channel.monotonicMillis()
        let listenerReady = expectation(description: "v1 listener ready")
        let clientReady = expectation(description: "v1 client TLS ready")
        let serverReady = expectation(description: "v1 server TLS ready")
        let listener = try serverTransport.listen { [clientIdentity.id] }
        var accepted: NWConnection?
        queue.sync {
            listeners.append(listener)
            listener.stateUpdateHandler = { state in if case .ready = state { listenerReady.fulfill() } }
            listener.newConnectionHandler = { connection in
                accepted = connection
                self.connections.append(connection)
                connection.stateUpdateHandler = { state in if case .ready = state { serverReady.fulfill() } }
                connection.start(queue: self.queue)
            }
            listener.start(queue: queue)
        }
        wait(for: [listenerReady], timeout: 10)
        let client = try clientTransport.connect(host: "127.0.0.1", port: XCTUnwrap(listener.port), expectedPeerID: serverIdentity.id)
        queue.sync {
            connections.append(client)
            client.stateUpdateHandler = { state in if case .ready = state { clientReady.fulfill() } }
            client.start(queue: queue)
        }
        wait(for: [clientReady, serverReady], timeout: 10)
        let server = try queue.sync { try XCTUnwrap(accepted) }
        return Pair(client: client, server: server, clientIdentity: clientIdentity, serverIdentity: serverIdentity,
                    clientTransport: clientTransport, serverTransport: serverTransport, selectedAt: selectedAt)
    }

    private func identity() throws -> AppleIdentity {
        let namespace = "dev.lantern.tests.v1-channel.\(UUID().uuidString)"
        namespaces.append(namespace)
        return try AppleIdentityStore(namespace: namespace).open()
    }

    private func scriptedPeer(
        _ pair: Pair,
        onComparison: @escaping (ScriptedPeer, IosHandshakeV1Comparison) throws -> Void,
        onEOF: @escaping (IosHandshakeV1Snapshot) -> Void = { _ in XCTFail("Unexpected scripted peer EOF") }
    ) throws -> ScriptedPeer {
        let peer = try ScriptedPeer(pair: pair, queue: queue, onComparison: onComparison, onEOF: onEOF)
        scriptedPeers.append(peer)
        return peer
    }

    /// Test-only malicious peer: real pinned TLS/crypto, Kotlin codec, explicit proof substitution.
    /// All state and callbacks use the same serial queue as the channel under test.
    private final class ScriptedPeer {
        private let bridge: IosHandshakeV1
        private let connection: NWConnection
        private let queue: DispatchQueue
        private let onComparison: (ScriptedPeer, IosHandshakeV1Comparison) throws -> Void
        private let onEOF: (IosHandshakeV1Snapshot) -> Void
        private var stopped = false
        private var comparisonPublished = false
        private var hello: Data?

        init(pair: Pair, queue: DispatchQueue,
             onComparison: @escaping (ScriptedPeer, IosHandshakeV1Comparison) throws -> Void,
             onEOF: @escaping (IosHandshakeV1Snapshot) -> Void) throws {
            dispatchPrecondition(condition: .onQueue(queue))
            let certificate = try XCTUnwrap(pair.serverTransport.certificate(for: pair.server))
            XCTAssertEqual(AppleIdentity.fingerprint(certificate), pair.clientIdentity.id)
            var nonce = [UInt8](repeating: 0, count: 32)
            let status = SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce)
            guard status == errSecSuccess else { throw IdentityError.cryptography }
            bridge = try IosHandshakeV1.companion.create(
                localIdentity: pair.serverIdentity.id,
                localNonce: nonce.map { String(format: "%02x", $0) }.joined(),
                capabilitiesJson: "{\"version\":1,\"supportedFeatures\":[\"text\",\"receipts\"],\"requiredFeatures\":[\"text\"]}",
                authenticatedLocalIdentity: pair.serverTransport.localIdentityID,
                selectedPeerIdentity: pair.clientIdentity.id,
                authenticatedPeerIdentity: AppleIdentity.fingerprint(certificate),
                selectedAtMillis: pair.selectedAt,
                nowMillis: { KotlinLong(longLong: HandshakeV1Channel.monotonicMillis()) },
                verifyRemoteSignature: { bytes, signature in
                    KotlinBoolean(bool: AppleIdentity.verify(certificate: certificate, message: HandshakeV1ChannelTests.data(bytes), signature: signature))
                }
            )
            connection = pair.server
            self.queue = queue
            self.onComparison = onComparison
            self.onEOF = onEOF
        }

        func start() throws {
            dispatchPrecondition(condition: .onQueue(queue))
            let hello = try XCTUnwrap(bridge.start())
            self.hello = HandshakeV1ChannelTests.data(hello.bytes)
            send(hello) { [weak self] in self?.receiveNext() }
        }

        func helloFrame() throws -> Data {
            dispatchPrecondition(condition: .onQueue(queue))
            return try XCTUnwrap(hello)
        }

        func approval(_ comparison: IosHandshakeV1Comparison, signer: AppleIdentity) throws -> IosHandshakeV1Write {
            dispatchPrecondition(condition: .onQueue(queue))
            let signing = try XCTUnwrap(bridge.confirm(ticket: comparison))
            let message = HandshakeV1ChannelTests.data(signing.bytes)
            let signature = try signer.sign(message)
            XCTAssertTrue(AppleIdentity.verify(certificate: signer.certificate, message: message, signature: signature))
            return try XCTUnwrap(bridge.signed(ticket: signing, signature: signature))
        }

        func send(_ ticket: IosHandshakeV1Write, onSent: @escaping () -> Void = {}) {
            dispatchPrecondition(condition: .onQueue(queue))
            connection.send(content: HandshakeV1ChannelTests.data(ticket.bytes), completion: .contentProcessed { [weak self] error in
                guard let self, !self.stopped else { return }
                dispatchPrecondition(condition: .onQueue(self.queue))
                XCTAssertNil(error)
                guard error == nil else { self.stop(); return }
                do {
                    // Keep Kotlin errors inside this non-throwing Network callback, not an XCTest autoclosure.
                    let accepted = try self.bridge.sent(ticket: ticket)
                    XCTAssertTrue(accepted)
                    guard accepted else { self.stop(); return }
                    onSent()
                } catch { self.fail(error) }
            })
        }

        func replay(_ frame: Data) {
            dispatchPrecondition(condition: .onQueue(queue))
            connection.send(content: frame, completion: .contentProcessed { [weak self] error in
                guard let self, !self.stopped else { return }
                dispatchPrecondition(condition: .onQueue(self.queue))
                XCTAssertNil(error)
                if error != nil { self.stop() }
            })
        }

        func stop() {
            dispatchPrecondition(condition: .onQueue(queue))
            stopped = true
            bridge.cancel()
            connection.cancel()
        }

        func disconnectAfterSending(_ prefix: Data, onSent: @escaping () -> Void) {
            dispatchPrecondition(condition: .onQueue(queue))
            connection.send(content: prefix, completion: .contentProcessed { [weak self] error in
                guard let self, !self.stopped else { return }
                dispatchPrecondition(condition: .onQueue(self.queue))
                XCTAssertNil(error)
                if error == nil { onSent() }
                self.stop() // Close the whole TLS connection, not just its write side.
            })
        }

        private func receiveNext() {
            dispatchPrecondition(condition: .onQueue(queue))
            guard !stopped else { return }
            connection.receive(minimumIncompleteLength: 1, maximumLength: Int(bridge.maximumChunkBytes)) { [weak self] chunk, _, complete, error in
                guard let self, !self.stopped else { return }
                dispatchPrecondition(condition: .onQueue(self.queue))
                do {
                    if let chunk, !chunk.isEmpty {
                        XCTAssertTrue(try self.bridge.accept(chunk: HandshakeV1ChannelTests.bytes(chunk)))
                    }
                    let snapshot = try self.bridge.snapshot()
                    XCTAssertNotEqual(snapshot.phase.name, "READY")
                    if complete || error != nil {
                        self.onEOF(snapshot)
                        self.stop()
                        return
                    }
                    if !self.comparisonPublished, let comparison = try self.bridge.comparison() {
                        self.comparisonPublished = true
                        try self.onComparison(self, comparison)
                    }
                    self.receiveNext()
                } catch { self.fail(error) }
            }
        }

        private func fail(_ error: Error) {
            XCTFail("Scripted TLS fixture failed: \(error)")
            stop()
        }
    }

    private static func bytes(_ data: Data) -> KotlinByteArray {
        let result = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() { result.set(index: Int32(index), value: Int8(bitPattern: byte)) }
        return result
    }

    private static func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }
}
