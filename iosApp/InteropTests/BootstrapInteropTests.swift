import Foundation
import Network
import Security
import XCTest
import LanternIdentity
import LanternUI
@testable import Lantern

/// Dedicated opt-in scheme. Uses actual OS keys/TLS and the existing Kotlin bootstrap owners.
final class BootstrapInteropTests: XCTestCase {
    func testJVMAndIOSBootstrapWithExplicitComparisonAndObservedCleanup() throws {
        try runBootstrap(expectMismatch: false)
    }

    func testDiscordantComparisonClosesWithoutApprovalOrReady() throws {
        try runBootstrap(expectMismatch: true)
    }

    private func runBootstrap(expectMismatch: Bool) throws {
        let config = ProcessInfo.processInfo.environment["LANTERN_INTEROP_CONTROL"] ?? ""
        let parts = config.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "127.0.0.1",
              let controlPort = UInt16(parts[1]), controlPort > 0,
              parts[2].count == 32, Self.isHex(String(parts[2])) else {
            throw TestError.controlConfiguration // Never skip an accidentally unconfigured opt-in run.
        }
        let token = String(parts[2])
        let namespace = "dev.lantern.tests.bootstrap-interop.\(UUID().uuidString)"
        let queue = DispatchQueue(label: "dev.lantern.tests.bootstrap-interop")
        var owner: HandshakeV1Channel?
        var connection: NWConnection?
        var cleaned = false
        func cleanup() {
            guard !cleaned else { return }
            cleaned = true
            queue.sync {
                owner?.cancel()
                owner = nil
                connection?.stateUpdateHandler = nil
                connection?.cancel()
                connection = nil
            }
            let queries: [[String: Any]] = [
                [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: Data("\(namespace).key".utf8)],
                [kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: "\(namespace).certificate"],
                [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: namespace],
            ]
            for query in queries {
                let status = SecItemDelete(query as CFDictionary)
                XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound, "Test namespace cleanup failed")
            }
        }
        defer { cleanup() }
        let identity = try AppleIdentityStore(namespace: namespace).open()
        let endpoint = try exchange("SELECT \(identity.id)", port: controlPort, token: token, timeout: 95)
        let selected = endpoint.split(separator: " ", omittingEmptySubsequences: false)
        guard selected.count == 4, selected[0] == "LISTENING", selected[1] == "127.0.0.1",
              let peerPort = UInt16(selected[2]), peerPort > 0,
              selected[3].count == 64, Self.isHex(String(selected[3])) else {
            throw TestError.endpoint
        }
        // Explicit test selection through the isolated controller, BEFORE TLS, never discovery.
        let selectedPin = String(selected[3])
        let selectedAt = HandshakeV1Channel.monotonicMillis()
        let transport = AppleTLSTransport(identity: identity)
        let tlsPort = try XCTUnwrap(NWEndpoint.Port(rawValue: peerPort))
        let client = try transport.connect(host: "127.0.0.1", port: tlsPort, expectedPeerID: selectedPin)
        connection = client
        let tlsReady = expectation(description: "actual pinned JVM/iOS TLS ready")
        queue.sync {
            var reported = false
            client.stateUpdateHandler = { state in
                guard !reported else { return }
                switch state {
                case .ready: reported = true; tlsReady.fulfill()
                case .failed, .waiting, .cancelled:
                    reported = true
                    XCTFail("Interop TLS could not become ready")
                    tlsReady.fulfill()
                default: break
                }
            }
            client.start(queue: queue)
        }
        wait(for: [tlsReady], timeout: 10)
        let comparisonAvailable = expectation(description: "iOS comparison available")
        let appleReady = expectMismatch ? nil : expectation(description: "iOS bootstrap ready")
        let appleClosed = expectation(description: "iOS observed JVM transport cleanup")
        var comparison: (IosHandshakeV1Comparison, String)?
        var confirmed = false
        var readyCount = 0
        var closedCount = 0
        try queue.sync {
            owner = try HandshakeV1Channel(
                connection: client, identity: identity, transport: transport,
                selectedPeerID: selectedPin, selectedAtMillis: selectedAt, queue: queue,
                onSnapshot: { snapshot in
                    if expectMismatch {
                        XCTAssertFalse(snapshot.remoteApproved)
                        XCTAssertNotEqual(snapshot.phase.name, "READY")
                    }
                    if snapshot.phase.name == "READY" {
                        XCTAssertTrue(confirmed) // No READY before both explicit test UI actions.
                        XCTAssertTrue(snapshot.remoteApproved)
                        XCTAssertEqual(snapshot.negotiatedFeatures, ["receipts", "text"])
                        readyCount += 1
                        XCTAssertEqual(readyCount, 1)
                        if readyCount == 1 { appleReady?.fulfill() }
                    }
                }, onComparison: { ticket, code in
                    XCTAssertNil(comparison)
                    comparison = (ticket, code)
                    comparisonAvailable.fulfill()
                }, onClosed: { failure in
                    closedCount += 1
                    XCTAssertEqual(closedCount, 1)
                    XCTAssertEqual(readyCount, expectMismatch ? 0 : 1)
                    switch failure {
                    case .transport: break
                    case .bootstrap(let reason): XCTAssertEqual(reason.name, "TRANSPORT")
                    default: XCTFail("Expected JVM transport closure")
                    }
                    if closedCount == 1 { appleClosed.fulfill() }
                }
            )
            owner?.start()
        }
        wait(for: [comparisonAvailable], timeout: 10)
        let current = try queue.sync { try XCTUnwrap(comparison) }
        XCTAssertEqual(current.1.count, 64)
        if expectMismatch {
            // Preserve the actual full transcript digest, then deliberately alter one character.
            let changed = (current.1.first == "0" ? "1" : "0") + String(current.1.dropFirst())
            let rejection = try exchange("MISMATCH \(current.1):\(changed)", port: controlPort, token: token)
            guard rejection == "REJECTED COMPARISON" else { throw TestError.comparison }
            wait(for: [appleClosed], timeout: 5)
            try queue.sync {
                XCTAssertFalse(confirmed)
                XCTAssertEqual(readyCount, 0)
                guard closedCount == 1 else { throw TestError.notClosed }
                owner?.confirm(current.0) // Closed attempt: retained UI cannot resurrect progress.
                owner?.start()
                owner?.cancel()
                XCTAssertEqual(closedCount, 1)
                XCTAssertEqual(readyCount, 0)
            }
            cleanup()
            let complete = try exchange("CLOSED TRANSPORT", port: controlPort, token: token)
            XCTAssertEqual(complete, "COMPLETE")
            return
        }
        // The controller compares the complete JVM digest and performs only the JVM UI action.
        let approval = try exchange("COMPARE \(current.1)", port: controlPort, token: token)
        guard approval == "CONFIRM \(current.1)" else { throw TestError.comparison }
        queue.sync {
            XCTAssertEqual(readyCount, 0)
            confirmed = true
            owner?.confirm(current.0) // Only the original iOS-owned ticket, never one from the host.
        }
        let requiredReady = try XCTUnwrap(appleReady)
        wait(for: [requiredReady], timeout: 10)
        guard queue.sync(execute: { readyCount == 1 }) else { throw TestError.notReady }
        let bothReady = try exchange("READY receipts,text", port: controlPort, token: token)
        XCTAssertEqual(bothReady, "READY receipts,text")
        wait(for: [appleClosed], timeout: 5)
        guard queue.sync(execute: { closedCount == 1 }) else { throw TestError.notClosed }
        cleanup() // Delete only this test namespace before acknowledging COMPLETE.
        let complete = try exchange("CLOSED TRANSPORT", port: controlPort, token: token)
        XCTAssertEqual(complete, "COMPLETE")
    }

    /// One bounded ASCII request per local TCP connection. Not a TLS/bootstrap implementation.
    private func exchange(_ command: String, port: UInt16, token: String, timeout: TimeInterval = 15) throws -> String {
        let queue = DispatchQueue(label: "dev.lantern.tests.interop-control")
        let controlPort = try XCTUnwrap(NWEndpoint.Port(rawValue: port))
        let connection = NWConnection(host: "127.0.0.1", port: controlPort, using: .tcp)
        let done = expectation(description: "local interop control response")
        var result: Result<String, Error>?
        var buffer = Data()
        func finish(_ value: Result<String, Error>) {
            guard result == nil else { return }
            result = value
            connection.stateUpdateHandler = nil
            connection.cancel()
            done.fulfill()
        }
        func receive() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 256 - buffer.count) { data, _, complete, error in
                if let error { finish(.failure(error)); return }
                if let data { buffer.append(data) }
                if let newline = buffer.firstIndex(of: 10) {
                    guard newline == buffer.index(before: buffer.endIndex),
                          let text = String(data: buffer.dropLast(), encoding: .ascii), text != "ERROR" else {
                        finish(.failure(TestError.controlResponse)); return
                    }
                    finish(.success(text))
                } else if complete || buffer.count >= 256 {
                    finish(.failure(TestError.controlResponse))
                } else { receive() }
            }
        }
        queue.sync {
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: Data("\(token) \(command)\n".utf8), completion: .contentProcessed { error in
                        if let error { finish(.failure(error)) } else { receive() }
                    })
                case .failed(let error), .waiting(let error): finish(.failure(error))
                case .cancelled: finish(.failure(TestError.controlResponse))
                default: break
                }
            }
            connection.start(queue: queue)
        }
        defer { queue.sync { connection.stateUpdateHandler = nil; connection.cancel() } }
        guard XCTWaiter.wait(for: [done], timeout: timeout) == .completed else { throw TestError.controlTimeout }
        return try queue.sync { try XCTUnwrap(result).get() }
    }

    private static func isHex(_ value: String) -> Bool {
        value.allSatisfy { "0123456789abcdef".contains($0) }
    }

    private enum TestError: Error {
        case controlConfiguration, controlResponse, controlTimeout, endpoint, comparison, notReady, notClosed
    }
}
