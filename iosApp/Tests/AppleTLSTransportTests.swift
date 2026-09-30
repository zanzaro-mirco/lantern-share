import Foundation
import Network
import Security
import XCTest
import LanternIdentity
@testable import Lantern

final class AppleTLSTransportTests: XCTestCase {
    private var namespaces: [String] = []
    private var listener: NWListener?
    private var client: NWConnection?
    private var server: NWConnection?
    private var channels: [PairingChannel] = []

    override func tearDown() {
        channels.forEach { $0.cancel() }
        channels.removeAll()
        client?.cancel()
        server?.cancel()
        listener?.cancel()
        namespaces.forEach(removeIdentity)
        super.tearDown()
    }

    func testPairingPersistsOnlyAfterBothConfirmations() throws {
        try exercisePairing(cancelDuringApproval: false)
    }

    func testCandidateExpiresEvenBeforeTimeoutCallbackRuns() {
        var time: UInt64 = 0
        let allowed = AllowedPeerStore(now: { time })
        allowed.replaceTrusted(["trusted"])
        allowed.select("candidate")
        XCTAssertTrue(allowed.contains("candidate"))
        time = 120_000_000_000
        XCTAssertFalse(allowed.contains("candidate"))
        XCTAssertEqual(allowed.values(), ["trusted"])
        XCTAssertTrue(allowed.contains("trusted"))
        allowed.select("replacement")
        XCTAssertFalse(allowed.contains("candidate"))
        XCTAssertTrue(allowed.contains("replacement"))
        allowed.select(nil)
        XCTAssertFalse(allowed.contains("replacement"))
    }

    func testCancellationIgnoresPendingApprovalCompletion() throws {
        try exercisePairing(cancelDuringApproval: true)
    }

    private func exercisePairing(cancelDuringApproval: Bool) throws {
        let serverIdentity = try identity("pair-server")
        let clientIdentity = try identity("pair-client")
        let serverTransport = AppleTLSTransport(identity: serverIdentity)
        let clientTransport = AppleTLSTransport(identity: clientIdentity)
        let queue = DispatchQueue(label: "dev.lantern.poc.tests.pairing")
        let ready = expectation(description: "pairing listener ready")
        let comparisons = expectation(description: "both comparison codes available")
        comparisons.expectedFulfillmentCount = 2
        let serverConnected = expectation(description: "server admitted")
        let clientConnected = expectation(description: "client admitted")
        clientConnected.isInverted = cancelDuringApproval
        var codes: [String] = []
        var serverAdmissions = 0
        var clientAdmissions = 0
        var serverChannel: PairingChannel?
        let listener = try serverTransport.listen { [clientIdentity.id] }
        self.listener = listener
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.fulfill() }
        }
        listener.newConnectionHandler = { [weak self] connection in
            do {
                let channel = try PairingChannel(
                    connection: connection, identity: serverIdentity, transport: serverTransport,
                    expectedPeerID: clientIdentity.id,
                    isAllowed: { $0 == clientIdentity.id }, isTrusted: { _ in false },
                    persistTrust: { peerID, _ in
                        XCTAssertEqual(peerID, clientIdentity.id)
                        serverAdmissions += 1
                    },
                    onComparison: { _, code in codes.append(code); comparisons.fulfill() },
                    onConnected: { _ in serverConnected.fulfill() },
                    onFailure: { message, _ in
                        if !cancelDuringApproval { XCTFail(message) }
                    }
                )
                serverChannel = channel
                self?.channels.append(channel)
                channel.start(queue: queue)
            } catch { XCTFail(error.localizedDescription) }
        }
        listener.start(queue: queue)
        wait(for: [ready], timeout: 10)
        let connection = try clientTransport.connect(
            host: "127.0.0.1", port: try XCTUnwrap(listener.port), expectedPeerID: serverIdentity.id
        )
        let clientChannel = try PairingChannel(
            connection: connection, identity: clientIdentity, transport: clientTransport,
            expectedPeerID: serverIdentity.id,
            isAllowed: { $0 == serverIdentity.id }, isTrusted: { _ in false },
            persistTrust: { peerID, _ in
                XCTAssertEqual(peerID, serverIdentity.id)
                clientAdmissions += 1
            },
            onComparison: { _, code in codes.append(code); comparisons.fulfill() },
            onConnected: { _ in clientConnected.fulfill() },
            onFailure: { message, _ in XCTFail(message) }
        )
        queue.sync { channels.append(clientChannel); clientChannel.start(queue: queue) }
        wait(for: [comparisons], timeout: 10)
        queue.sync {
            XCTAssertEqual(codes.count, 2)
            XCTAssertEqual(codes.first, codes.last)
            XCTAssertEqual(clientAdmissions, 0)
            XCTAssertEqual(serverAdmissions, 0)
            serverChannel?.confirm()
            clientChannel.confirm()
            clientChannel.confirm() // A second tap must not enqueue a duplicate APPROVE.
            if cancelDuringApproval { clientChannel.cancel() }
        }
        if cancelDuringApproval {
            wait(for: [clientConnected], timeout: 1)
        } else {
            wait(for: [serverConnected, clientConnected], timeout: 10)
        }
        queue.sync {
            XCTAssertEqual(clientAdmissions, cancelDuringApproval ? 0 : 1)
            if !cancelDuringApproval { XCTAssertEqual(serverAdmissions, 1) }
            channels.forEach { $0.cancel() }
        }
    }

    func testMutualTLS13WithExactPinsTransfersBytes() throws {
        let serverIdentity = try identity("server")
        let clientIdentity = try identity("client")
        let queue = DispatchQueue(label: "dev.lantern.poc.tests.tls")
        let listenerReady = expectation(description: "listener ready")
        let serverReady = expectation(description: "server TLS ready")
        let clientReady = expectation(description: "client TLS ready")

        let serverTransport = AppleTLSTransport(identity: serverIdentity)
        let clientTransport = AppleTLSTransport(identity: clientIdentity)
        let listener = try serverTransport.listen {
            [clientIdentity.id]
        }
        self.listener = listener
        listener.newConnectionHandler = { [weak self] connection in
            self?.server = connection
            connection.stateUpdateHandler = { state in
                if case .ready = state { serverReady.fulfill() }
            }
            connection.start(queue: queue)
        }
        listener.stateUpdateHandler = { state in
            if case .ready = state { listenerReady.fulfill() }
        }
        listener.start(queue: queue)
        wait(for: [listenerReady], timeout: 10)

        let port = try XCTUnwrap(listener.port)
        let client = try clientTransport.connect(
            endpoint: .hostPort(host: "127.0.0.1", port: port),
            expectedPeerID: serverIdentity.id
        )
        self.client = client
        client.stateUpdateHandler = { state in
            if case .ready = state { clientReady.fulfill() }
        }
        client.start(queue: queue)
        wait(for: [serverReady, clientReady], timeout: 10)
        let server = try XCTUnwrap(self.server)
        XCTAssertEqual(AppleIdentity.fingerprint(try XCTUnwrap(serverTransport.certificate(for: server))), clientIdentity.id)
        XCTAssertEqual(AppleIdentity.fingerprint(try XCTUnwrap(clientTransport.certificate(for: client))), serverIdentity.id)
        // An earlier successful handshake must never supply a certificate to a new channel.
        let unopened = try clientTransport.connect(host: "127.0.0.1", port: port, expectedPeerID: serverIdentity.id)
        XCTAssertNil(clientTransport.certificate(for: unopened))
        unopened.cancel()

        let received = expectation(description: "encrypted payload received")
        server.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, _, error in
            XCTAssertNil(error)
            XCTAssertEqual(data, Data("lantern-tls".utf8))
            received.fulfill()
        }
        client.send(content: Data("lantern-tls".utf8), completion: .contentProcessed { error in
            XCTAssertNil(error)
        })
        wait(for: [received], timeout: 10)
    }

    func testWrongPinRejectsHandshake() throws {
        let serverIdentity = try identity("reject-server")
        let clientIdentity = try identity("reject-client")
        let queue = DispatchQueue(label: "dev.lantern.poc.tests.tls-reject")
        let listenerReady = expectation(description: "listener ready")
        let rejected = expectation(description: "client rejected")

        let listener = try AppleTLSTransport(identity: serverIdentity).listen {
            [clientIdentity.id]
        }
        self.listener = listener
        listener.newConnectionHandler = { [weak self] connection in
            self?.server = connection
            connection.start(queue: queue)
        }
        listener.stateUpdateHandler = { state in
            if case .ready = state { listenerReady.fulfill() }
        }
        listener.start(queue: queue)
        wait(for: [listenerReady], timeout: 10)

        let client = try AppleTLSTransport(identity: clientIdentity).connect(
            host: "127.0.0.1",
            port: try XCTUnwrap(listener.port),
            expectedPeerID: String(repeating: "0", count: 64)
        )
        self.client = client
        client.stateUpdateHandler = { state in
            if case .failed = state { rejected.fulfill() }
        }
        client.start(queue: queue)
        wait(for: [rejected], timeout: 10)
    }

    private func identity(_ suffix: String) throws -> AppleIdentity {
        let namespace = "dev.lantern.poc.tls-tests.\(UUID().uuidString).\(suffix)"
        namespaces.append(namespace)
        return try AppleIdentityStore(namespace: namespace).open()
    }

    private func removeIdentity(_ namespace: String) {
        let queries: [[String: Any]] = [
            [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: Data("\(namespace).key".utf8)],
            [kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: "\(namespace).certificate"],
            [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: namespace],
        ]
        queries.forEach { SecItemDelete($0 as CFDictionary) }
    }
}
