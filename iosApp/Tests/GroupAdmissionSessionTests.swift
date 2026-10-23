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
    private var bootstrapOwners: [HandshakeV1Channel] = []

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
        var prepared = 0
        let sessionMemory = IosGroupSessionMemory()
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
            bootstrapOwners.forEach { $0.cancel() }
            bootstrapOwners.removeAll()
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
            // Both adopted stores have reopened; founder/listener remains offline.
            beginMembershipCheck(issuer, candidate)
            awaitMembershipVerified(issuer, candidate)
            closeAndDrain(issuer)
            closeAndDrain(candidate)
            beginSession(issuer, candidate)
            _ = awaitSession(issuer, candidate)
            closeAndDrain(issuer)
            closeAndDrain(candidate)
            queue.sync {
                XCTAssertEqual(issuer.membershipReads, 1)
                XCTAssertEqual(candidate.membershipReads, 1)
                XCTAssertNil(issuer.presentation.displayedComparison())
                XCTAssertNil(candidate.presentation.displayedComparison())
            }
        }
    }

    func testMembershipCheckAfterReopenDoesNotInviteOrCommitInBothTLSOrders() throws {
        for founderInitiates in [true, false] {
            let pair = try fixture(founderInitiates: founderInitiates)
            try confirmBoth(pair.issuer, pair.member)
            closeAndDrain(pair.issuer)
            closeAndDrain(pair.member)
            let original = try queue.sync { () throws -> IosGroupAdoptionJournalSnapshot in
                pair.member.store.close()
                stores.removeAll { $0 === pair.member.store }
                pair.member.store = try IosEntryKt.openIosPersistence(databaseDirectory: pair.member.directory.path)
                stores.append(pair.member.store)
                XCTAssertThrowsError(try GroupMembership.prepare(identity: pair.issuer.identity, persistence: pair.member.store))
                return try XCTUnwrap(pair.member.store.committedGroupAdoption())
            }
            beginMembershipCheck(pair.issuer, pair.member)
            awaitMembershipVerified(pair.issuer, pair.member)
            closeAndDrain(pair.issuer)
            closeAndDrain(pair.member)
            try queue.sync {
                XCTAssertTrue(original.sameRecord(other: try XCTUnwrap(pair.member.store.committedGroupAdoption())))
                XCTAssertEqual(pair.member.membershipReads, 1) // Only the earlier admission.
                XCTAssertEqual(pair.issuer.membershipReads, 0)
                XCTAssertNil(try pair.issuer.store.committedGroupAdoption())
                for side in [pair.issuer, pair.member] {
                    XCTAssertNil(side.presentation.displayedComparison())
                    XCTAssertNil(try side.store.pendingGroupAdoption())
                    XCTAssertEqual(try side.store.trusted(), [])
                    XCTAssertEqual(try side.store.history().count, 0)
                    XCTAssertEqual(side.presentation.snapshot().phase, .idle)
                }
            }
        }
    }

    func testMembershipCheckRejectsDifferentGroupsWithoutChangingEitherStore() throws {
        let a = try side(), b = try side()
        try found(a)
        try found(b)
        let roots = try queue.sync { (try a.store.localGroup()?.groupId, try b.store.localGroup()?.groupId) }
        try connect(a, b, checking: [a.identity.id, b.identity.id])
        awaitState { a.presentation.membershipSnapshot().phase == .failed && b.presentation.membershipSnapshot().phase == .failed }
        try queue.sync {
            XCTAssertEqual(try a.store.localGroup()?.groupId, roots.0)
            XCTAssertEqual(try b.store.localGroup()?.groupId, roots.1)
            for side in [a, b] {
                XCTAssertNil(try side.store.committedGroupAdoption())
                XCTAssertNil(try side.store.pendingGroupAdoption())
                XCTAssertEqual(try side.store.trusted(), [])
            }
        }
    }

    func testMembershipAndAdmissionModesCannotBeConfused() throws {
        let a = try side(), b = try side()
        try found(a)
        try connect(a, b, checking: [a.identity.id])
        awaitState { a.presentation.membershipSnapshot().phase == .failed && b.presentation.snapshot().phase == .failed }
        try queue.sync {
            XCTAssertNil(try b.store.localGroup())
            XCTAssertNil(try b.store.pendingGroupAdoption())
            XCTAssertEqual(try a.store.trusted(), [])
            XCTAssertEqual(try b.store.trusted(), [])
        }
    }

    func testMembershipWithoutGroupFailsBeforeEnablingSelectedPin() throws {
        let a = try side(), b = try side()
        try connect(a, b, checking: [a.identity.id, b.identity.id])
        awaitState { a.presentation.membershipSnapshot().phase == .failed && b.presentation.membershipSnapshot().phase == .failed }
        try queue.sync {
            for side in [a, b] {
                XCTAssertEqual(side.prepared, 0)
                XCTAssertNil(try side.store.localGroup())
                XCTAssertNil(try side.store.pendingGroupAdoption())
                XCTAssertEqual(try side.store.trusted(), [])
            }
        }
    }

    func testMembershipCancelAndNewSelectionCannotReviveOldResult() throws {
        let pair = try fixture(founderInitiates: true)
        try confirmBoth(pair.issuer, pair.member)
        closeAndDrain(pair.issuer)
        closeAndDrain(pair.member)
        queue.sync {
            pair.issuer.presentation.verifyPeer(id: pair.member.identity.id, name: "member")
            pair.issuer.presentation.cancelGroup()
        }
        awaitState { pair.issuer.presentation.membershipSnapshot().phase == .idle }
        closeAndDrain(pair.issuer)
        beginMembershipCheck(pair.issuer, pair.member)
        awaitMembershipVerified(pair.issuer, pair.member)
        closeAndDrain(pair.issuer)
        closeAndDrain(pair.member)
        try queue.sync {
            XCTAssertEqual(pair.member.membershipReads, 1)
            XCTAssertNotNil(try pair.member.store.committedGroupAdoption())
            XCTAssertNil(try pair.member.store.pendingGroupAdoption())
        }
    }

    private func beginMembershipCheck(_ a: Side, _ b: Side) {
        queue.sync {
            a.presentation.verifyPeer(id: b.identity.id, name: "member")
            b.presentation.verifyPeer(id: a.identity.id, name: "member")
        }
    }

    func testInitialSessionAfterReopenContinuityAndRunResetInBothTLSOrders() throws {
        for founderInitiates in [true, false] {
            let pair = try fixture(founderInitiates: founderInitiates)
            try confirmBoth(pair.issuer, pair.member)
            closeAndDrain(pair.issuer)
            closeAndDrain(pair.member)
            let marker = try queue.sync { () throws -> IosGroupAdoptionJournalSnapshot in
                pair.member.store.close()
                stores.removeAll { $0 === pair.member.store }
                pair.member.store = try IosEntryKt.openIosPersistence(databaseDirectory: pair.member.directory.path)
                stores.append(pair.member.store)
                return try XCTUnwrap(pair.member.store.committedGroupAdoption())
            }
            beginSession(pair.issuer, pair.member)
            let first = awaitSession(pair.issuer, pair.member)
            closeAndDrain(pair.issuer)
            closeAndDrain(pair.member)
            beginSession(pair.issuer, pair.member)
            XCTAssertEqual(awaitSession(pair.issuer, pair.member), first) // Dismissal retains the run.
            closeAndDrain(pair.issuer)
            closeAndDrain(pair.member)
            queue.sync { pair.member.sessionMemory.reset() } // Only one participant stopped.
            beginSession(pair.issuer, pair.member)
            XCTAssertEqual(awaitSession(pair.issuer, pair.member), first)
            closeAndDrain(pair.issuer)
            closeAndDrain(pair.member)
            queue.sync { pair.issuer.sessionMemory.reset(); pair.member.sessionMemory.reset() }
            beginSession(pair.issuer, pair.member)
            XCTAssertNotEqual(awaitSession(pair.issuer, pair.member), first)
            closeAndDrain(pair.issuer)
            closeAndDrain(pair.member)
            try queue.sync {
                XCTAssertTrue(marker.sameRecord(other: try XCTUnwrap(pair.member.store.committedGroupAdoption())))
                XCTAssertEqual(pair.member.membershipReads, 1)
                for side in [pair.issuer, pair.member] {
                    XCTAssertNil(try side.store.pendingGroupAdoption())
                    XCTAssertEqual(try side.store.trusted(), [])
                    XCTAssertEqual(try side.store.history().count, 0)
                    XCTAssertNil(side.presentation.displayedComparison())
                    XCTAssertEqual(side.presentation.membershipSnapshot().phase, .idle)
                    XCTAssertEqual(side.presentation.snapshot().phase, .idle)
                }
            }
        }
    }

    func testSessionCannotFallbackToMembershipAndFailureDoesNotReplaceHeldSession() throws {
        let pair = try fixture(founderInitiates: true)
        try confirmBoth(pair.issuer, pair.member)
        closeAndDrain(pair.issuer)
        closeAndDrain(pair.member)
        beginSession(pair.issuer, pair.member)
        let first = awaitSession(pair.issuer, pair.member)
        closeAndDrain(pair.issuer)
        closeAndDrain(pair.member)
        queue.sync {
            pair.issuer.presentation.negotiateSession(id: pair.member.identity.id, name: "member")
            pair.member.presentation.verifyPeer(id: pair.issuer.identity.id, name: "founder")
        }
        awaitState { pair.issuer.presentation.sessionSnapshot().phase == .failed && pair.member.presentation.membershipSnapshot().phase == .failed }
        closeAndDrain(pair.issuer)
        closeAndDrain(pair.member)
        beginSession(pair.issuer, pair.member)
        XCTAssertEqual(awaitSession(pair.issuer, pair.member), first)
    }

    func testSessionRejectsDifferentRootsAndMissingLocalMembershipBeforePin() throws {
        for foundGroups in [false, true] {
            let a = try side(), b = try side()
            if foundGroups { try found(a); try found(b) }
            let roots = try queue.sync { (try a.store.localGroup()?.groupId, try b.store.localGroup()?.groupId) }
            try connect(a, b, negotiating: [a.identity.id, b.identity.id])
            awaitState { a.presentation.sessionSnapshot().phase == .failed && b.presentation.sessionSnapshot().phase == .failed }
            try queue.sync {
                XCTAssertEqual(try a.store.localGroup()?.groupId, roots.0)
                XCTAssertEqual(try b.store.localGroup()?.groupId, roots.1)
                for side in [a, b] {
                    if !foundGroups { XCTAssertEqual(side.prepared, 0) }
                    XCTAssertNil(try side.store.committedGroupAdoption())
                    XCTAssertNil(try side.store.pendingGroupAdoption())
                    XCTAssertEqual(try side.store.trusted(), [])
                }
            }
        }
    }

    func testSessionCancelReselectCannotPublishOldResult() throws {
        let pair = try fixture(founderInitiates: false)
        try confirmBoth(pair.issuer, pair.member)
        closeAndDrain(pair.issuer)
        closeAndDrain(pair.member)
        queue.sync {
            pair.issuer.presentation.negotiateSession(id: pair.member.identity.id, name: "member")
            pair.issuer.presentation.cancelGroup()
        }
        awaitState { pair.issuer.presentation.sessionSnapshot().phase == .idle }
        closeAndDrain(pair.issuer)
        beginSession(pair.issuer, pair.member)
        _ = awaitSession(pair.issuer, pair.member)
        closeAndDrain(pair.issuer)
        closeAndDrain(pair.member)
        queue.sync {
            pair.issuer.presentation.cancelled()
            pair.member.presentation.cancelled()
        }
        awaitState { pair.issuer.presentation.sessionSnapshot().phase == .idle && pair.member.presentation.sessionSnapshot().phase == .idle }
    }

    func testSessionPendingOfferAfterRealMembershipIsRevokedByCancelAndOriginalDeadline() throws {
        for expire in [false, true] {
            let pair = try fixture(founderInitiates: expire)
            try confirmBoth(pair.issuer, pair.member)
            closeAndDrain(pair.issuer)
            closeAndDrain(pair.member)
            let sorted = [pair.issuer, pair.member].sorted { $0.identity.id < $1.identity.id }
            let lower = sorted[0], higher = sorted[1]
            let ready = expectation(description: "partial session peer listener ready")
            let paused = expectation(description: "fresh proofs verified, session offer received but no reply")
            let revoked = expectation(description: "same owner revokes blocked session read")
            var localOwner: HandshakeV1Channel?
            let listener = try higher.transport.listen { [lower.identity.id] }
            let memberFeature = IosLocalGroupMembership.shared.feature
            let sessionFeature = lower.sessionMemory.feature
            let capabilities = "{\"version\":1,\"supportedFeatures\":[\"\(memberFeature)\",\"\(sessionFeature)\"],\"requiredFeatures\":[\"\(memberFeature)\",\"\(sessionFeature)\"]}"
            queue.sync {
                listeners.append(listener)
                listener.stateUpdateHandler = { state in if case .ready = state { ready.fulfill() } }
                listener.newConnectionHandler = { connection in
                    connection.stateUpdateHandler = { state in
                        guard case .ready = state else { return }
                        connection.stateUpdateHandler = nil
                        do {
                            let proof = try GroupMembership.prepare(identity: higher.identity, persistence: higher.store)
                            let anchor = try XCTUnwrap(higher.store.localGroup())
                            let peer = try HandshakeV1Channel(connection: connection, identity: higher.identity,
                                transport: higher.transport, selectedPeerID: lower.identity.id,
                                selectedAtMillis: HandshakeV1Channel.monotonicMillis(), queue: self.queue,
                                continuation: .groupAdmission(onHello: {
                                    let decoder = IosGroupMembershipDecoder()
                                    self.readExact(connection, budget: { try decoder.nextReadBytes() },
                                        accept: { try decoder.accept(chunk: $0).evidence }) { remote in
                                        XCTAssertTrue(try GroupMembership.verify(remote, anchor: anchor, peerID: lower.identity.id))
                                        connection.send(content: self.data(try proof.framedBytes()), completion: .contentProcessed { error in
                                            self.queue.async {
                                                XCTAssertNil(error)
                                                let sessionDecoder = IosGroupSessionDecoder()
                                                self.readExact(connection, budget: { try sessionDecoder.nextReadBytes() },
                                                    accept: { try sessionDecoder.accept(chunk: $0).offer }) { _ in
                                                    paused.fulfill() // Deliberately no LSN response.
                                                    if !expire { self.queue.asyncAfter(deadline: .now() + .milliseconds(50)) { localOwner?.cancel() } }
                                                }
                                            }
                                        })
                                    }
                                }), capabilitiesJson: capabilities, onSnapshot: { _ in },
                                onComparison: { _, _ in XCTFail("No old approval") }, onClosed: { _ in })
                            self.bootstrapOwners.append(peer)
                            peer.start()
                        } catch { XCTFail("Peer setup failed: \(error)") }
                    }
                    connection.start(queue: self.queue)
                }
                listener.start(queue: queue)
            }
            wait(for: [ready], timeout: 10)
            let port = try XCTUnwrap(listener.port)
            try queue.sync {
                let connection = try lower.transport.connect(endpoint: .hostPort(host: "127.0.0.1", port: port), expectedPeerID: higher.identity.id)
                connection.stateUpdateHandler = { state in
                    guard case .ready = state else { return }
                    connection.stateUpdateHandler = nil
                    do {
                        let anchor = try XCTUnwrap(lower.store.localGroup())
                        let proof = try GroupMembership.prepare(identity: lower.identity, persistence: lower.store)
                        let offer = try lower.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId,
                            marker: lower.store.committedGroupAdoption(), newSessionId: String(repeating: "e", count: 64))
                        let owner = try HandshakeV1Channel(connection: connection, identity: lower.identity, transport: lower.transport,
                            selectedPeerID: higher.identity.id,
                            selectedAtMillis: HandshakeV1Channel.monotonicMillis() - (expire ? 117_000 : 0), queue: self.queue,
                            continuation: .groupAdmission(onHello: {
                                XCTAssertTrue(localOwner?.negotiateSession(membership: proof, offer: offer,
                                    verifyRemote: { try GroupMembership.verify($0, anchor: anchor, peerID: higher.identity.id) },
                                    onReceived: { _ in XCTFail("Peer did not send a session offer") }) ?? false)
                            }), capabilitiesJson: capabilities, onSnapshot: { _ in },
                            onComparison: { _, _ in XCTFail("No old approval") }, onClosed: { failure in
                                if expire {
                                    if case .bootstrap(let reason) = failure { XCTAssertEqual(reason.name, "EXPIRED") }
                                    else { XCTFail("Expected original deadline") }
                                } else if case .cancelled = failure {} else { XCTFail("Expected cancellation") }
                                revoked.fulfill()
                            })
                        localOwner = owner
                        self.bootstrapOwners.append(owner)
                        owner.start()
                    } catch { XCTFail("Session setup failed: \(error)") }
                }
                connection.start(queue: queue)
            }
            wait(for: [paused, revoked], timeout: 8)
            queue.sync { bootstrapOwners.forEach { $0.cancel() }; bootstrapOwners.removeAll() }
        }
    }

    private func readExact<T>(_ connection: NWConnection, budget: @escaping () throws -> Int32,
                              accept: @escaping (KotlinByteArray) throws -> T?, completion: @escaping (T) throws -> Void) {
        do {
            connection.receive(minimumIncompleteLength: 1, maximumLength: Int(try budget())) { data, _, complete, error in
                self.queue.async {
                    do {
                        guard error == nil, !complete else { XCTFail("Truncated test peer frame"); return }
                        guard let data, !data.isEmpty else {
                            self.readExact(connection, budget: budget, accept: accept, completion: completion)
                            return
                        }
                        let bytes = KotlinByteArray(size: Int32(data.count))
                        for (index, byte) in data.enumerated() { bytes.set(index: Int32(index), value: Int8(bitPattern: byte)) }
                        if let value = try accept(bytes) { try completion(value) }
                        else { self.readExact(connection, budget: budget, accept: accept, completion: completion) }
                    } catch { XCTFail("Test peer frame failed: \(error)") }
                }
            }
        } catch { XCTFail("Test peer budget failed: \(error)") }
    }

    private func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }

    private func beginSession(_ a: Side, _ b: Side) {
        queue.sync {
            a.presentation.negotiateSession(id: b.identity.id, name: "member")
            b.presentation.negotiateSession(id: a.identity.id, name: "member")
        }
    }

    private func awaitSession(_ a: Side, _ b: Side) -> String {
        awaitState { a.presentation.sessionSnapshot().phase == .selected && b.presentation.sessionSnapshot().phase == .selected }
        return queue.sync {
            let local = a.presentation.sessionSnapshot(), remote = b.presentation.sessionSnapshot()
            XCTAssertEqual(local.groupId, remote.groupId)
            XCTAssertEqual(local.sessionId, remote.sessionId)
            XCTAssertEqual(local.sessionId.count, 64)
            return local.sessionId
        }
    }

    private func awaitMembershipVerified(_ a: Side, _ b: Side) {
        awaitState { a.presentation.membershipSnapshot().phase == .verified && b.presentation.membershipSnapshot().phase == .verified }
        queue.sync {
            XCTAssertEqual(a.presentation.membershipSnapshot().groupId, b.presentation.membershipSnapshot().groupId)
            XCTAssertEqual(a.presentation.membershipSnapshot().groupId.count, 64)
        }
    }

    private func found(_ side: Side) throws {
        try queue.sync {
            let foundation = try LocalGroupFoundation(identity: side.identity)
            let ticket = try XCTUnwrap(foundation.prepare(persistence: side.store))
            XCTAssertEqual(try foundation.commit(ticket: ticket, currentIdentity: side.identity, persistence: side.store).name, "COMMITTED")
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

    private func connect(_ issuer: Side, _ member: Side, checking: Set<String> = [], negotiating: Set<String> = []) throws {
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
                            endpoint: side.endpoint!, queue: self.queue, sessionMemory: side.sessionMemory,
                            onPrepared: { [weak side] in side?.prepared += 1 },
                            onMembershipChanged: { [weak side] in side?.membershipReads += 1 })
                        side.session = session
                        session.start()
                    }
                }, requestConfirm: { [weak self, weak side] ticket in
                    self?.queue.async { side?.session?.confirm(ticket) }
                }, requestCancel: { [weak self, weak side] in
                    self?.queue.async { side?.session?.cancel(); side?.presentation.cancelled() }
                })
            }
            for (side, peer) in [(issuer, member), (member, issuer)] {
                if negotiating.contains(side.identity.id) { side.presentation.negotiateSession(id: peer.identity.id, name: "member") }
                else if checking.contains(side.identity.id) { side.presentation.verifyPeer(id: peer.identity.id, name: "member") }
                else { side.presentation.selectPeer(id: peer.identity.id, name: "member", replaceInterrupted: false) }
            }
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
