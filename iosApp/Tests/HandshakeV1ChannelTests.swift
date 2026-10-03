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
    private var connections: [NWConnection] = []
    private var listeners: [NWListener] = []
    private var namespaces: [String] = []

    override func tearDown() {
        queue.sync {
            channels.forEach { $0.cancel() }
            channels.removeAll()
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

    private func readyPair() throws -> Pair {
        let clientIdentity = try identity()
        let serverIdentity = try identity()
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
}
