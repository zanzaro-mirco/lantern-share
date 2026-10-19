import Foundation
import Network
import Security
import XCTest
import LanternIdentity
import LanternUI
@testable import Lantern

/// Actual app session, real mutually pinned TLS/Keychain/SQLite; endpoint discovery and clicks
/// are fixtures. No handcrafted wire, fake cryptography, bootstrap offers or direct commit calls.
final class GroupAdmissionSessionTests: XCTestCase {
    private let queue = DispatchQueue(label: "dev.lantern.tests.group-service")
    private var listeners: [NWListener] = []
    private var stores: [IosPersistence] = []
    private var directories: [URL] = []
    private var namespaces: [String] = []
    private var sides: [Side] = []

    private final class Side {
        let identity: AppleIdentity
        var store: IosPersistence
        let directory: URL
        let transport: AppleTLSTransport
        var presentation: IosGroupAdmissionController!
        var session: GroupAdmissionSession?
        var selection: IosGroupAdmissionSelection?
        var endpoint: NWEndpoint?
        var membershipReads = 0
        init(identity: AppleIdentity, store: IosPersistence, directory: URL) {
            self.identity = identity
            self.store = store
            self.directory = directory
            transport = AppleTLSTransport(identity: identity)
        }
    }

    override func tearDown() {
        let drained = expectation(description: "all service owners drain before SQLite/Keychain cleanup")
        let group = DispatchGroup()
        queue.sync {
            for side in sides {
                if let session = side.session {
                    group.enter()
                    session.cancel()
                    session.whenClosedAndDrained { group.leave() }
                }
            }
            for listener in listeners {
                listener.stateUpdateHandler = nil
                listener.newConnectionHandler = nil
                listener.cancel()
            }
            group.notify(queue: queue) { drained.fulfill() }
        }
        wait(for: [drained], timeout: 10)
        queue.sync { stores.forEach { $0.close() }; sides.removeAll(); stores.removeAll(); listeners.removeAll() }
        for directory in directories { try? FileManager.default.removeItem(at: directory) }
        for namespace in namespaces {
            let queries: [[String: Any]] = [
                [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: Data("\(namespace).key".utf8)],
                [kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: "\(namespace).certificate"],
                [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: namespace,
                 kSecAttrAccount as String: "certificate-pin"]
            ]
            for query in queries {
                let status = SecItemDelete(query as CFDictionary)
                XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
            }
        }
        super.tearDown()
    }

    func testExplicitServiceAdmissionBothTLSOrdersAndDatabaseReopen() throws {
        for founderInitiates in [true, false] {
            let pair = try fixture(founderInitiates: founderInitiates)
            try awaitComparison(pair.issuer, pair.member)
            let (issuerTicket, memberTicket) = try queue.sync {
                (try XCTUnwrap(pair.issuer.presentation.displayedComparison()),
                 try XCTUnwrap(pair.member.presentation.displayedComparison()))
            }
            XCTAssertEqual(issuerTicket.code, memberTicket.code)
            XCTAssertEqual(issuerTicket.code.count, 64)
            XCTAssertEqual(issuerTicket.groupId, memberTicket.groupId)
            queue.sync { pair.member.presentation.confirmDisplayed(ticket: memberTicket) }
            try queue.sync {
                XCTAssertNil(try pair.member.store.localGroup())
                XCTAssertNil(try pair.member.store.pendingGroupAdoption())
                XCTAssertEqual(pair.issuer.presentation.snapshot().phase, .comparing)
                pair.issuer.presentation.confirmDisplayed(ticket: issuerTicket)
            }
            awaitState { pair.member.presentation.snapshot().phase == .completed }
            try queue.sync {
                XCTAssertTrue(pair.member.presentation.snapshot().adoptedLocally)
                XCTAssertEqual(try pair.member.store.localGroup()?.groupId, memberTicket.groupId)
                XCTAssertEqual(pair.member.membershipReads, 1)
                XCTAssertEqual(try pair.member.store.trusted(), [])
                XCTAssertEqual(try pair.member.store.history().count, 0)
                XCTAssertNil(try pair.member.store.pendingGroupAdoption())
            }
            closeAndDrain(pair.member)
            try queue.sync {
                pair.member.store.close()
                stores.removeAll { $0 === pair.member.store }
                let reopened = try IosEntryKt.openIosPersistence(databaseDirectory: pair.member.directory.path)
                defer { reopened.close() }
                let marker = try XCTUnwrap(reopened.committedGroupAdoption())
                XCTAssertEqual(try GroupAdoptionJournalInspector.inspect(marker, currentIdentityID: pair.member.identity.id), .historicalSignaturesValid)
                XCTAssertEqual(try reopened.localGroup()?.groupId, memberTicket.groupId)
                let display = IosLocalGroupController(requestCreate: { XCTFail("already adopted") }, requestReload: {})
                try GroupAdoptionJournalInspector.loadLocalGroup(display, identityID: pair.member.identity.id, persistence: reopened)
                XCTAssertEqual(display.snapshot().phase, .adopted)
            }
            closeAndDrain(pair.issuer)
        }
    }

    func testReopenedMemberInvitesThirdDeviceWithoutFounderInBothTLSOrders() throws {
        for issuerInitiates in [true, false] {
            let sorted = try [side(), side(), side()].sorted { $0.identity.id < $1.identity.id }
            let founder = sorted[1], issuer = sorted[issuerInitiates ? 0 : 2], candidate = sorted[issuerInitiates ? 2 : 0]
            try queue.sync {
                let foundation = try LocalGroupFoundation(identity: founder.identity)
                let ticket = try XCTUnwrap(foundation.prepare(persistence: founder.store))
                XCTAssertEqual(try foundation.commit(ticket: ticket, currentIdentity: founder.identity, persistence: founder.store).name, "COMMITTED")
            }
            try connect(founder, issuer)
            try confirmBoth(founder, issuer)
            closeAndDrain(founder)
            closeAndDrain(issuer)
            try queue.sync {
                // Founder no longer participates; the issuer's actual app store is reopened.
                for listener in listeners {
                    listener.stateUpdateHandler = nil
                    listener.newConnectionHandler = nil
                    listener.cancel()
                }
                listeners.removeAll()
                issuer.store.close()
                stores.removeAll { $0 === issuer.store }
                issuer.store = try IosEntryKt.openIosPersistence(databaseDirectory: issuer.directory.path)
                stores.append(issuer.store)
                XCTAssertEqual(try GroupAdoptionJournalInspector.inspect(
                    XCTUnwrap(issuer.store.committedGroupAdoption()), currentIdentityID: issuer.identity.id), .historicalSignaturesValid)
                // A saved proof cannot be used with a different current OS identity.
                XCTAssertThrowsError(try LocalGroupAdmission.prepare(identity: candidate.identity, persistence: issuer.store,
                    memberID: founder.identity.id))
            }
            try connect(issuer, candidate)
            try awaitComparison(issuer, candidate)
            let groupID = try queue.sync { try XCTUnwrap(candidate.presentation.displayedComparison()).groupId }
            try confirmBoth(issuer, candidate)
            closeAndDrain(issuer)
            closeAndDrain(candidate)
            try queue.sync {
                XCTAssertEqual(try candidate.store.localGroup()?.groupId, groupID)
                XCTAssertEqual(try candidate.store.trusted(), [])
                XCTAssertEqual(try candidate.store.history().count, 0)
                XCTAssertNil(try candidate.store.pendingGroupAdoption())
                candidate.store.close()
                stores.removeAll { $0 === candidate.store }
                candidate.store = try IosEntryKt.openIosPersistence(databaseDirectory: candidate.directory.path)
                stores.append(candidate.store)
                XCTAssertEqual(try GroupAdoptionJournalInspector.inspect(
                    XCTUnwrap(candidate.store.committedGroupAdoption()), currentIdentityID: candidate.identity.id), .historicalSignaturesValid)
                // A third member retains all certificates needed for a further delegation.
                let next = try LocalGroupAdmission.prepare(identity: candidate.identity, persistence: candidate.store,
                    memberID: String(repeating: "e", count: 64))
                XCTAssertEqual(next.certificates.count, 3)
                let display = IosLocalGroupController(requestCreate: { XCTFail("already adopted") }, requestReload: {})
                try GroupAdoptionJournalInspector.loadLocalGroup(display, identityID: candidate.identity.id, persistence: candidate.store)
                XCTAssertEqual(display.snapshot().phase, .adopted)
            }
        }
    }

    private func confirmBoth(_ issuer: Side, _ member: Side) throws {
        try awaitComparison(issuer, member)
        try queue.sync {
            let offer = try XCTUnwrap(issuer.presentation.displayedComparison())
            let accept = try XCTUnwrap(member.presentation.displayedComparison())
            XCTAssertEqual(offer.code, accept.code)
            member.presentation.confirmDisplayed(ticket: accept)
        }
        awaitState { member.presentation.snapshot().phase == .awaitingPeer }
        try queue.sync {
            XCTAssertNil(try member.store.localGroup())
            XCTAssertNil(try member.store.pendingGroupAdoption())
            issuer.presentation.confirmDisplayed(ticket: try XCTUnwrap(issuer.presentation.displayedComparison()))
        }
        awaitState { member.presentation.snapshot().phase == .completed && issuer.presentation.snapshot().phase == .completed }
        queue.sync {
            XCTAssertTrue(member.presentation.snapshot().adoptedLocally)
            XCTAssertFalse(issuer.presentation.snapshot().adoptedLocally)
        }
    }

    func testCancelledSelectionOldClickCannotAdoptAndNewComparisonIsFresh() throws {
        let pair = try fixture(founderInitiates: true)
        try awaitComparison(pair.issuer, pair.member)
        let old = try queue.sync { try XCTUnwrap(pair.member.presentation.displayedComparison()) }
        closeAndDrain(pair.member)
        closeAndDrain(pair.issuer)
        queue.sync {
            pair.member.presentation.cancelled()
            pair.issuer.presentation.cancelled()
            pair.member.presentation.selectPeer(id: pair.issuer.identity.id, name: "founder", replaceInterrupted: false)
            pair.issuer.presentation.selectPeer(id: pair.member.identity.id, name: "member", replaceInterrupted: false)
        }
        try awaitComparison(pair.issuer, pair.member)
        try queue.sync {
            let current = try XCTUnwrap(pair.member.presentation.displayedComparison())
            XCTAssertNotEqual(old.code, current.code)
            pair.member.presentation.confirmDisplayed(ticket: old)
            XCTAssertEqual(pair.member.presentation.snapshot().phase, .comparing)
            XCTAssertNil(try pair.member.store.localGroup())
            XCTAssertNil(try pair.member.store.pendingGroupAdoption())
        }
    }

    func testTwoCandidatesFailBeforeEvidenceWithoutTrustOrMembership() throws {
        let pair = try fixture(founderInitiates: true, foundGroup: false)
        awaitState { pair.issuer.presentation.snapshot().phase == .failed && pair.member.presentation.snapshot().phase == .failed }
        try queue.sync {
            for side in [pair.issuer, pair.member] {
                XCTAssertNil(try side.store.localGroup())
                XCTAssertNil(try side.store.pendingGroupAdoption())
                XCTAssertEqual(try side.store.trusted(), [])
            }
        }
    }

    func testExclusiveGroupSelectionDoesNotAdmitPreviouslyTrustedPoCPin() {
        var now: UInt64 = 0
        let allowed = AllowedPeerStore(now: { now })
        allowed.replaceTrusted(["old"])
        allowed.selectGroup("new")
        XCTAssertEqual(allowed.values(), ["new"])
        XCTAssertFalse(allowed.contains("old"))
        now = 120_000_000_000
        XCTAssertEqual(allowed.values(), [])
        XCTAssertFalse(allowed.contains("new"))
        allowed.select(nil)
        XCTAssertTrue(allowed.contains("old"))
    }

    private func fixture(founderInitiates: Bool, foundGroup: Bool = true) throws -> (issuer: Side, member: Side) {
        let sorted = try [side(), side()].sorted { $0.identity.id < $1.identity.id }
        let issuer = sorted[founderInitiates ? 0 : 1], member = sorted[founderInitiates ? 1 : 0]
        if foundGroup {
            try queue.sync {
                let foundation = try LocalGroupFoundation(identity: issuer.identity)
                let ticket = try XCTUnwrap(foundation.prepare(persistence: issuer.store))
                XCTAssertEqual(try foundation.commit(ticket: ticket, currentIdentity: issuer.identity, persistence: issuer.store).name, "COMMITTED")
            }
        }
        try connect(issuer, member)
        return (issuer, member)
    }

    private func connect(_ issuer: Side, _ member: Side) throws {
        let issuerListener = try listen(issuer, selectedPeer: member.identity.id)
        let memberListener = try listen(member, selectedPeer: issuer.identity.id)
        queue.sync {
            issuer.endpoint = .hostPort(host: "127.0.0.1", port: memberListener)
            member.endpoint = .hostPort(host: "127.0.0.1", port: issuerListener)
            for side in [issuer, member] {
                side.presentation = IosGroupAdmissionController(requestSelect: { [weak self, weak side] selection in
                    guard let self, let side else { return }
                    // Same non-blocking callback boundary used by BonjourProbe.
                    self.queue.async {
                        side.selection = selection
                        side.presentation.selected(value: selection)
                        let session = GroupAdmissionSession(identity: side.identity, persistence: side.store,
                            transport: side.transport, selection: selection, presentation: side.presentation,
                            endpoint: side.endpoint!, queue: self.queue, onMembershipChanged: { [weak side] in side?.membershipReads += 1 })
                        side.session = session
                        session.start()
                    }
                }, requestConfirm: { [weak self, weak side] ticket in
                    self?.queue.async { side?.session?.confirm(ticket) }
                }, requestCancel: { [weak self, weak side] in
                    self?.queue.async { side?.session?.cancel(); side?.presentation.cancelled() }
                })
            }
            issuer.presentation.selectPeer(id: member.identity.id, name: "member", replaceInterrupted: false)
            member.presentation.selectPeer(id: issuer.identity.id, name: "founder", replaceInterrupted: false)
        }
    }

    private func side() throws -> Side {
        let namespace = "dev.lantern.tests.group-service.\(UUID().uuidString)"
        namespaces.append(namespace)
        let identity = try AppleIdentityStore(namespace: namespace).open()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lantern-service-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        directories.append(directory)
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        stores.append(store)
        let result = Side(identity: identity, store: store, directory: directory)
        sides.append(result)
        return result
    }

    private func listen(_ side: Side, selectedPeer: String) throws -> NWEndpoint.Port {
        let ready = expectation(description: "service listener ready")
        let listener = try side.transport.listen { [selectedPeer] }
        queue.sync {
            listeners.append(listener)
            listener.stateUpdateHandler = { state in if case .ready = state { ready.fulfill() } }
            listener.newConnectionHandler = { [weak side] connection in
                guard let session = side?.session else { connection.cancel(); return }
                session.accept(connection)
            }
            listener.start(queue: queue)
        }
        wait(for: [ready], timeout: 10)
        return try XCTUnwrap(listener.port)
    }

    private func awaitComparison(_ issuer: Side, _ member: Side) throws {
        awaitState { issuer.presentation.snapshot().phase == .comparing && member.presentation.snapshot().phase == .comparing }
    }

    private func awaitState(_ predicate: @escaping () -> Bool) {
        let observed = XCTNSPredicateExpectation(predicate: NSPredicate { [self] _, _ in queue.sync(execute: predicate) }, object: nil)
        wait(for: [observed], timeout: 15)
    }

    private func closeAndDrain(_ side: Side) {
        let drained = expectation(description: "selection closed and all callbacks drained")
        queue.sync {
            guard let session = side.session else { drained.fulfill(); return }
            session.cancel()
            session.whenClosedAndDrained { drained.fulfill() }
        }
        wait(for: [drained], timeout: 10)
    }
}
