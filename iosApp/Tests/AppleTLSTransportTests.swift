import Foundation
import Network
import Security
import XCTest
import LanternIdentity

final class AppleTLSTransportTests: XCTestCase {
    private var namespaces: [String] = []
    private var listener: NWListener?
    private var client: NWConnection?
    private var server: NWConnection?

    override func tearDown() {
        client?.cancel()
        server?.cancel()
        listener?.cancel()
        namespaces.forEach(removeIdentity)
        super.tearDown()
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
        XCTAssertNotNil(serverTransport.certificate(forPeerID: clientIdentity.id))
        XCTAssertNotNil(clientTransport.certificate(forPeerID: serverIdentity.id))

        let received = expectation(description: "encrypted payload received")
        server?.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, _, error in
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
