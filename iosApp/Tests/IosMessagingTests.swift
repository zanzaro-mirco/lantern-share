import Foundation
import Network
import Security
import XCTest
import LanternIdentity
import LanternUI
@testable import Lantern

final class IosMessagingTests: XCTestCase {
    private let queue = DispatchQueue(label: "dev.lantern.poc.tests.messages")
    private var listener: NWListener?
    private var connection: NWConnection?
    private var clientChannel: PairingChannel?
    private var serverChannel: PairingChannel?
    private var clientStore: IosPersistence?
    private var serverStore: IosPersistence?
    private var directories: [URL] = []
    private var namespaces: [String] = []
    private var clientIdentity: AppleIdentity?
    private var lastClientFrame: IosPairingFrame?
    private let wire = IosPairingProtocol()
    private var serverChanged: () -> Void = {}
    private var serverFailure: (String) -> Void = { XCTFail($0) }
    private var clientFailure: (String) -> Void = { XCTFail($0) }
    private var receipt: () -> Void = {}
    private var rejectServerSave = false

    override func tearDown() {
        queue.sync {
            clientChannel?.cancel()
            serverChannel?.cancel()
            listener?.cancel()
            connection?.cancel()
            clientStore?.close()
            serverStore?.close()
        }
        directories.forEach { try? FileManager.default.removeItem(at: $0) }
        for namespace in namespaces {
            let queries: [[String: Any]] = [
                [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: Data("\(namespace).key".utf8)],
                [kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: "\(namespace).certificate"],
                [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: namespace],
            ]
            queries.forEach { _ = SecItemDelete($0 as CFDictionary) }
        }
        super.tearDown()
    }

    func testBidirectionalTextIsSavedBeforeReceiptAndSurvivesReopen() throws {
        try connect()
        let receipts = expectation(description: "both messages acknowledged after commit")
        receipts.expectedFulfillmentCount = 2
        queue.sync { receipt = { receipts.fulfill() } }
        try queue.sync {
            try XCTUnwrap(clientChannel).sendText("Caffè ☕ dal client")
            try XCTUnwrap(serverChannel).sendText("Risposta dal server")
        }
        wait(for: [receipts], timeout: 10)
        try queue.sync {
            let client = try XCTUnwrap(clientStore)
            let server = try XCTUnwrap(serverStore)
            XCTAssertEqual(try client.history().count, 2)
            XCTAssertEqual(try server.history().count, 2)
            clientChannel?.cancel()
            serverChannel?.cancel()
            client.close()
            clientStore = nil
            let reopened = try IosEntryKt.openIosPersistence(databaseDirectory: directories[0].path)
            clientStore = reopened
            let history = try reopened.history()
            XCTAssertEqual(history.count, 2)
            XCTAssertTrue(try XCTUnwrap(history.first { $0.sender == clientIdentity?.id }).received)
            XCTAssertTrue(history.contains { $0.text == "Risposta dal server" })
        }
    }

    func testDuplicateTextIsIdempotentAndGetsAnotherReceipt() throws {
        try connect()
        try sendInitialText()
        let stored = expectation(description: "duplicate processed")
        let duplicateReceipt = expectation(description: "duplicate ACK rejected as no longer pending")
        queue.sync {
            serverChanged = { stored.fulfill() }
            clientFailure = { message in
                XCTAssertEqual(message, "Ricevuta inattesa.")
                duplicateReceipt.fulfill()
            }
            // The client closes after rejecting a duplicate, no-longer-pending ACK.
            serverFailure = { _ in }
        }
        try queue.sync { sendRaw(try wire.frame(json: XCTUnwrap(lastClientFrame).json)) }
        wait(for: [stored, duplicateReceipt], timeout: 10)
        try queue.sync { XCTAssertEqual(try serverStore?.history().count, 1) }
    }

    func testInvalidSignatureIsRejectedWithoutSavingOrReceipt() throws {
        try rejectText(kind: .signature)
    }

    func testWrongSessionIsRejectedWithoutSavingOrReceipt() throws {
        try rejectText(kind: .session)
    }

    func testConflictingDuplicateIsRejectedWithoutReceipt() throws {
        try rejectText(kind: .conflict)
    }

    func testTextBeforeConfirmationIsRejectedWithoutSaving() throws {
        try connect(trusted: false)
        let rejected = expectation(description: "unconfirmed text rejected")
        queue.sync {
            serverFailure = { _ in rejected.fulfill() }
            clientFailure = { _ in }
        }
        try queue.sync {
            XCTAssertThrowsError(try XCTUnwrap(clientChannel).sendText("Non autorizzato"))
            let frame = try wire.text(
                sender: XCTUnwrap(clientIdentity).id, id: UUID().uuidString.lowercased(),
                session: String(repeating: "a", count: 64), body: "Non autorizzato", signature: "invalid"
            )
            sendRaw(try wire.frame(json: frame.json))
        }
        wait(for: [rejected], timeout: 10)
        try queue.sync { XCTAssertEqual(try serverStore?.history().count, 0) }
    }

    func testFailedSaveDoesNotProduceReceipt() throws {
        try connect()
        let rejected = expectation(description: "storage failure closes channel")
        let noReceipt = expectation(description: "no receipt before successful commit")
        noReceipt.isInverted = true
        queue.sync {
            rejectServerSave = true
            serverFailure = { _ in rejected.fulfill() }
            clientFailure = { _ in }
            receipt = { noReceipt.fulfill() }
        }
        try queue.sync { try XCTUnwrap(clientChannel).sendText("Errore disco simulato nel test") }
        wait(for: [rejected], timeout: 10)
        wait(for: [noReceipt], timeout: 1)
        try queue.sync {
            XCTAssertEqual(try serverStore?.history().count, 0)
            XCTAssertFalse(try XCTUnwrap(clientStore?.history().first).received)
        }
    }

    func testUnsolicitedReceiptDoesNotUpdateHistory() throws {
        try connect()
        let rejected = expectation(description: "unsolicited receipt rejected")
        queue.sync {
            serverFailure = { message in
                XCTAssertEqual(message, "Ricevuta inattesa.")
                rejected.fulfill()
            }
            clientFailure = { _ in }
        }
        try queue.sync {
            sendRaw(try wire.acknowledgement(sender: XCTUnwrap(clientIdentity).id, id: UUID().uuidString.lowercased()))
        }
        wait(for: [rejected], timeout: 10)
        try queue.sync { XCTAssertEqual(try serverStore?.history().count, 0) }
    }

    func testInvalidOutgoingTextIsNotSaved() throws {
        try connect()
        try queue.sync {
            let channel = try XCTUnwrap(clientChannel)
            XCTAssertThrowsError(try channel.sendText(""))
            XCTAssertThrowsError(try channel.sendText(String(repeating: "é", count: 4097)))
            XCTAssertEqual(try clientStore?.history().count, 0)
        }
    }

    private enum InvalidText: Equatable { case signature, session, conflict }

    private func rejectText(kind: InvalidText) throws {
        try connect()
        try sendInitialText()
        let rejected = expectation(description: "invalid text rejected")
        let noReceipt = expectation(description: "no receipt for rejected text")
        noReceipt.isInverted = true
        queue.sync {
            serverFailure = { _ in rejected.fulfill() }
            clientFailure = { message in
                if message == "Ricevuta inattesa." { noReceipt.fulfill() }
            }
            receipt = { noReceipt.fulfill() }
        }
        try queue.sync {
            let previous = try XCTUnwrap(lastClientFrame)
            let sender = try XCTUnwrap(clientIdentity)
            let id = kind == .conflict ? previous.id : UUID().uuidString.lowercased()
            let session = kind == .session ? String(repeating: "0", count: 64) : previous.session
            let body = "Messaggio alterato"
            let signature: String
            if kind == .signature {
                signature = previous.signature
            } else {
                signature = try sender.sign(data(try wire.textSigningBytes(
                    sender: sender.id, id: id, session: session, body: body
                )))
            }
            let frame = try wire.text(sender: sender.id, id: id, session: session, body: body, signature: signature)
            sendRaw(try wire.frame(json: frame.json))
        }
        wait(for: [rejected], timeout: 10)
        wait(for: [noReceipt], timeout: 1)
        try queue.sync {
            let history = try XCTUnwrap(serverStore).history()
            XCTAssertEqual(history.count, 1)
            XCTAssertEqual(history.first?.text, "Originale")
        }
    }

    private func sendInitialText() throws {
        let acknowledged = expectation(description: "initial text acknowledged")
        queue.sync { receipt = { acknowledged.fulfill() } }
        try queue.sync { try XCTUnwrap(clientChannel).sendText("Originale") }
        wait(for: [acknowledged], timeout: 10)
        queue.sync { receipt = {} }
    }

    private func connect(trusted: Bool = true) throws {
        let clientIdentity = try identity()
        let serverIdentity = try identity()
        self.clientIdentity = clientIdentity
        let clientTransport = AppleTLSTransport(identity: clientIdentity)
        let serverTransport = AppleTLSTransport(identity: serverIdentity)
        try queue.sync {
            clientStore = try store()
            serverStore = try store()
        }
        let ready = expectation(description: "listener ready")
        let channelsReady = expectation(description: trusted ? "both channels authorized" : "both comparisons available")
        channelsReady.expectedFulfillmentCount = 2
        let listener = try serverTransport.listen { [clientIdentity.id] }
        self.listener = listener
        listener.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            do {
                let channel = try self.makeChannel(
                    connection: connection, identity: serverIdentity, transport: serverTransport,
                    peer: clientIdentity.id, trusted: trusted, client: false, ready: channelsReady
                )
                self.serverChannel = channel
                channel.start(queue: self.queue)
            } catch { XCTFail(error.localizedDescription) }
        }
        listener.start(queue: queue)
        wait(for: [ready], timeout: 10)
        let connection = try clientTransport.connect(host: "127.0.0.1", port: XCTUnwrap(listener.port), expectedPeerID: serverIdentity.id)
        self.connection = connection
        try queue.sync {
            let channel = try makeChannel(
                connection: connection, identity: clientIdentity, transport: clientTransport,
                peer: serverIdentity.id, trusted: trusted, client: true, ready: channelsReady
            )
            clientChannel = channel
            channel.start(queue: queue)
        }
        wait(for: [channelsReady], timeout: 10)
    }

    private func makeChannel(
        connection: NWConnection, identity: AppleIdentity, transport: AppleTLSTransport,
        peer: String, trusted: Bool, client: Bool, ready: XCTestExpectation
    ) throws -> PairingChannel {
        let repository = try XCTUnwrap(client ? clientStore : serverStore)
        return try PairingChannel(
            connection: connection, identity: identity, transport: transport, expectedPeerID: peer,
            isAllowed: { $0 == peer }, isTrusted: { _ in trusted },
            persistTrust: { _, _ in XCTFail("No approval expected in messaging fixture") },
            persistMessage: { [weak self] frame in
                if !client, self?.rejectServerSave == true {
                    throw NSError(domain: "Lantern.Test.Storage", code: 1)
                }
                _ = try repository.saveMessage(frame: frame)
                if client, frame.sender == identity.id { self?.lastClientFrame = frame }
            },
            acknowledge: { [weak self] id in
                guard let self else { return }
                let destination = try XCTUnwrap(client ? self.serverStore : self.clientStore)
                XCTAssertTrue(try destination.history().contains { $0.id == id })
                try repository.acknowledge(id: id)
                self.receipt()
            },
            onMessagesChanged: { [weak self] in if !client { self?.serverChanged() } },
            onComparison: { _, _ in if !trusted { ready.fulfill() } else { XCTFail("Trusted peer requested approval") } },
            onConnected: { _ in if trusted { ready.fulfill() } else { XCTFail("Unconfirmed peer admitted") } },
            onFailure: { [weak self] message, _ in
                if client { self?.clientFailure(message) } else { self?.serverFailure(message) }
            }
        )
    }

    private func sendRaw(_ bytes: KotlinByteArray) {
        connection?.send(content: data(bytes), completion: .contentProcessed { _ in })
    }

    private func store() throws -> IosPersistence {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lantern-messages-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        directories.append(directory)
        return try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
    }

    private func identity() throws -> AppleIdentity {
        let namespace = "dev.lantern.poc.messages-tests.\(UUID().uuidString)"
        namespaces.append(namespace)
        return try AppleIdentityStore(namespace: namespace).open()
    }

    private func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }
}
