import CryptoKit
import Foundation
import Network
import Security
import XCTest
import LanternIdentity
import LanternUI
@testable import Lantern

/// Actual app session, pinned TLS/Keychain/SQLite; discovery and clicks are fixtures.
/// Explicit facade tests isolate OS/storage boundaries; raw peers inject malformed controls.
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
            beginText(issuer, candidate, body: "Delegati senza fondatore")
            let transferred = awaitText(issuer, candidate)
            try queue.sync {
                XCTAssertEqual(try candidate.store.groupText(id: transferred.messageId)?.envelope.body, "Delegati senza fondatore")
            }
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
        try pendingExchangeIsRevoked(text: false)
    }

    func testTextPendingAcknowledgementAfterRealMembershipAndScopeIsRevokedByCancelAndOriginalDeadline() throws {
        try pendingExchangeIsRevoked(text: true)
    }

    func testRosterPendingAgreementAfterFreshProofsIsRevokedByCancelAndOriginalDeadline() throws {
        try pendingExchangeIsRevoked(text: false, roster: true)
    }

    func testRosterAlteredAgreementNeverInstallsTheMergedView() throws {
        try pendingExchangeIsRevoked(text: false, roster: true, corruptAgreement: true)
    }

    func testRosterTextPendingACKUsesCancellationAndOriginalDeadline() throws {
        try pendingExchangeIsRevoked(text: false, rosterText: true)
    }

    func testRosterTextRejectsAlteredScopeBeforeOutgoingCopy() throws {
        try pendingExchangeIsRevoked(text: false, rosterText: true, textFault: .scope)
    }

    func testRosterTextRejectsAlteredACKAfterDurableReceive() throws {
        try pendingExchangeIsRevoked(text: false, rosterText: true, textFault: .acknowledgement)
    }

    private enum RosterTextFault: Equatable { case scope, acknowledgement }

    private func pendingExchangeIsRevoked(text: Bool, roster: Bool = false, corruptAgreement: Bool = false,
                                         rosterText: Bool = false, textFault: RosterTextFault? = nil) throws {
        for expire in (corruptAgreement || textFault != nil ? [false] : [false, true]) {
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
            var attemptedMessageID: String?
            let listener = try higher.transport.listen { [lower.identity.id] }
            let memberFeature = IosLocalGroupMembership.shared.feature
            let sessionFeature = lower.sessionMemory.feature
            let capabilities = rosterText ? IosGroupRosterTextProtocol.shared.capabilities(sending: true) : roster ? IosGroupRosterProtocol.shared.capabilities() : text ? IosGroupTextProtocol.shared.capabilities(sending: true) :
                "{\"version\":1,\"supportedFeatures\":[\"\(memberFeature)\",\"\(sessionFeature)\"],\"requiredFeatures\":[\"\(memberFeature)\",\"\(sessionFeature)\"]}"
            let pause: () -> Void = {
                paused.fulfill()
                if !expire && !corruptAgreement && textFault == nil { self.queue.asyncAfter(deadline: .now() + .milliseconds(50)) { localOwner?.cancel() } }
            }
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
                                                    accept: { try sessionDecoder.accept(chunk: $0).offer }) { remoteOffer in
                                                    if roster || rosterText {
                                                        try self.pauseBeforeRosterAgreement(connection, higher: higher, lower: lower,
                                                            remoteOffer: remoteOffer, corruptAgreement: corruptAgreement,
                                                            rosterText: rosterText, textFault: textFault, pause: pause)
                                                    } else if text {
                                                        try self.pauseBeforeTextACK(connection, receiver: higher, sender: lower,
                                                            remoteOffer: remoteOffer, pause: pause)
                                                    } else { pause() } // Deliberately no LSN response.
                                                }
                                            }
                                        })
                                    }
                                }), capabilitiesJson: rosterText ? IosGroupRosterTextProtocol.shared.capabilities(sending: false) : text ? IosGroupTextProtocol.shared.capabilities(sending: false) : capabilities, onSnapshot: { _ in },
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
                        var rosterExchange: IosGroupRosterExchange?
                        let owner = try HandshakeV1Channel(connection: connection, identity: lower.identity, transport: lower.transport,
                            selectedPeerID: higher.identity.id,
                            selectedAtMillis: HandshakeV1Channel.monotonicMillis() - (expire ? (rosterText ? 115_000 : 117_000) : 0), queue: self.queue,
                            continuation: .groupAdmission(onHello: {
                                if rosterText {
                                    XCTAssertTrue(localOwner?.transferRosterText(membership: proof, offer: offer, sending: true,
                                        verifyRemote: { try GroupMembership.verify($0, anchor: anchor, peerID: higher.identity.id) },
                                        propose: { remote in
                                            let selected = try lower.sessionMemory.selectRoster(local: offer, remote: remote,
                                                groupId: anchor.groupId, founderId: anchor.founderId, marker: lower.store.committedGroupAdoption())
                                            let exchange = try XCTUnwrap(selected.exchange)
                                            rosterExchange = exchange
                                            return try self.proposeRoster(lower, exchange: exchange)
                                        }, merge: { payload, certificate in
                                            XCTAssertEqual(SecCertificateCopyData(certificate) as Data, SecCertificateCopyData(higher.identity.certificate) as Data)
                                            return try self.mergeRoster(XCTUnwrap(rosterExchange), payload: payload, peer: higher)
                                        }, selectRoster: { snapshot, digest in
                                            let scope = try XCTUnwrap(rosterExchange).installForText(snapshot: snapshot,
                                                senderId: lower.identity.id, recipientId: higher.identity.id, digest: digest,
                                                isCurrent: { KotlinBoolean(bool: true) })
                                            return IosGroupTextTransfer(persistence: lower.store, memory: lower.sessionMemory,
                                                scope: scope, localIdentity: lower.identity.id)
                                        }, outgoing: { transfer in
                                            XCTAssertFalse(textFault == .scope, "Outgoing called after bad scope")
                                            let id = UUID().uuidString.lowercased()
                                            attemptedMessageID = id
                                            return try transfer.prepareOutgoing(id: id, body: "Roster pending ACK",
                                                isCurrent: { KotlinBoolean(bool: true) }, sign: { try? lower.identity.sign(self.data($0)) })
                                        }, incoming: { _, _, _ in throw PendingTextError.unexpected },
                                        acknowledged: { _, _, _, _ in XCTFail("No valid recipient ACK") },
                                        received: { _ in XCTFail("Local role is sender") }) ?? false)
                                } else if roster {
                                    XCTAssertTrue(localOwner?.synchronizeRoster(membership: proof, offer: offer,
                                        verifyRemote: { try GroupMembership.verify($0, anchor: anchor, peerID: higher.identity.id) },
                                        propose: { remote in
                                            let selected = try lower.sessionMemory.selectRoster(local: offer, remote: remote,
                                                groupId: anchor.groupId, founderId: anchor.founderId, marker: lower.store.committedGroupAdoption())
                                            let exchange = try XCTUnwrap(selected.exchange)
                                            rosterExchange = exchange
                                            return try self.proposeRoster(lower, exchange: exchange)
                                        }, merge: { payload, certificate in
                                            XCTAssertEqual(SecCertificateCopyData(certificate) as Data, SecCertificateCopyData(higher.identity.certificate) as Data)
                                            return try self.mergeRoster(XCTUnwrap(rosterExchange), payload: payload, peer: higher)
                                        }, completed: { _ in XCTFail("Peer sent no LRA") }) ?? false)
                                } else if text {
                                    XCTAssertTrue(localOwner?.transferGroupText(membership: proof, offer: offer, sending: true,
                                        verifyRemote: { try GroupMembership.verify($0, anchor: anchor, peerID: higher.identity.id) },
                                        selectSession: { remote in
                                            let selected = try lower.sessionMemory.selectText(local: offer, remote: remote,
                                                groupId: anchor.groupId, founderId: anchor.founderId,
                                                marker: lower.store.committedGroupAdoption(), senderId: lower.identity.id, recipientId: higher.identity.id)
                                            return IosGroupTextTransfer(persistence: lower.store, memory: lower.sessionMemory,
                                                scope: try XCTUnwrap(selected.context), localIdentity: lower.identity.id)
                                        }, outgoing: { transfer in
                                            try transfer.prepareOutgoing(id: UUID().uuidString.lowercased(), body: "Pending ACK",
                                                isCurrent: { KotlinBoolean(bool: true) },
                                                sign: { try? lower.identity.sign(self.data($0)) })
                                        }, incoming: { _, _, _ in throw PendingTextError.unexpected },
                                        acknowledged: { _, _, _, _ in XCTFail("Peer sent no ACK") },
                                        received: { _ in XCTFail("Local role is sender") }) ?? false)
                                } else {
                                    XCTAssertTrue(localOwner?.negotiateSession(membership: proof, offer: offer,
                                        verifyRemote: { try GroupMembership.verify($0, anchor: anchor, peerID: higher.identity.id) },
                                        onReceived: { _ in XCTFail("Peer did not send a session offer") }) ?? false)
                                }
                            }), capabilitiesJson: capabilities, onSnapshot: { _ in },
                            onComparison: { _, _ in XCTFail("No old approval") }, onClosed: { failure in
                                if expire {
                                    if case .bootstrap(let reason) = failure { XCTAssertEqual(reason.name, "EXPIRED") }
                                    else { XCTFail("Expected original deadline") }
                                } else if corruptAgreement || textFault != nil {
                                    if case .adapter = failure {} else { XCTFail("Expected exact agreement rejection") }
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
            try queue.sync {
                if textFault == .scope { XCTAssertNil(attemptedMessageID) }
                if let id = attemptedMessageID {
                    XCTAssertEqual(try lower.store.groupText(id: id)?.receivedBy, [lower.identity.id])
                }
                bootstrapOwners.forEach { $0.cancel() }; bootstrapOwners.removeAll()
            }
        }
    }

    private enum PendingTextError: Error { case unexpected }

    private func pauseBeforeRosterAgreement(_ connection: NWConnection, higher: Side, lower: Side,
                                           remoteOffer: IosGroupSessionOffer, corruptAgreement: Bool,
                                           rosterText: Bool = false, textFault: RosterTextFault? = nil,
                                           pause: @escaping () -> Void) throws {
        let anchor = try XCTUnwrap(higher.store.localGroup())
        let marker = try higher.store.committedGroupAdoption()
        let offer = try higher.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId,
            marker: marker, newSessionId: String(repeating: "f", count: 64))
        let selected = try higher.sessionMemory.selectRoster(local: offer, remote: remoteOffer,
            groupId: anchor.groupId, founderId: anchor.founderId, marker: marker)
        let exchange = try XCTUnwrap(selected.exchange)
        let local = try proposeRoster(higher, exchange: exchange)
        connection.send(content: data(try offer.framedBytes()), completion: .contentProcessed { error in
            self.queue.async {
                XCTAssertNil(error)
                let decoder = IosGroupRosterDecoder(agreement: false)
                self.readExact(connection, budget: { try decoder.nextReadBytes() }, accept: { try decoder.accept(chunk: $0).payload }) { payload in
                    let merged = try self.mergeRoster(exchange, payload: payload, peer: lower)
                    let digest = SHA256.hash(data: self.data(try merged.payload())).map { String(format: "%02x", $0) }.joined()
                    let expected = self.data(try merged.agreement(digest: digest))
                    connection.send(content: self.data(try local.framedBytes()), completion: .contentProcessed { error in
                        self.queue.async {
                            XCTAssertNil(error)
                            let agreement = IosGroupRosterDecoder(agreement: true)
                            self.readExact(connection, budget: { try agreement.nextReadBytes() }, accept: { try agreement.accept(chunk: $0).payload }) { value in
                                XCTAssertEqual(self.data(value), expected)
                                if corruptAgreement {
                                    var altered = expected
                                    altered[altered.count - 1] = altered.last == 48 ? 49 : 48
                                    connection.send(content: self.data(try IosGroupRosterProtocol.shared.frame(payload: self.bytes(altered))),
                                        completion: .contentProcessed { error in XCTAssertNil(error) })
                                } else if rosterText {
                                    connection.send(content: self.data(try IosGroupRosterProtocol.shared.frame(payload: value)),
                                        completion: .contentProcessed { error in
                                            self.queue.async {
                                                do {
                                                    XCTAssertNil(error)
                                                    let scope = try exchange.installForText(snapshot: merged,
                                                        senderId: lower.identity.id, recipientId: higher.identity.id, digest: digest,
                                                        isCurrent: { KotlinBoolean(bool: true) })
                                                    let transfer = IosGroupTextTransfer(persistence: higher.store, memory: higher.sessionMemory,
                                                        scope: scope, localIdentity: higher.identity.id)
                                                    try self.pauseBeforeRosterTextACK(connection, receiver: higher, sender: lower,
                                                        transfer: transfer, fault: textFault, pause: pause)
                                                } catch { XCTFail("Roster text test setup failed: \(error)") }
                                            }
                                        })
                                    return
                                }
                                pause() // Full verified union, but deliberately no LRA response/installation.
                            }
                        }
                    })
                }
            }
        })
    }

    private func pauseBeforeRosterTextACK(_ connection: NWConnection, receiver: Side, sender: Side,
                                          transfer: IosGroupTextTransfer, fault: RosterTextFault?, pause: @escaping () -> Void) throws {
        let decoder = try transfer.decoder(expectedBytes: transfer.scopeBytes)
        readExact(connection, budget: { try decoder.nextReadBytes() }, accept: { try decoder.accept(chunk: $0).payload }) { scope in
            try transfer.checkScope(payload: scope)
            var response = self.data(try transfer.scopeFrame())
            if fault == .scope { response[response.count - 1] = 0 }
            connection.send(content: response, completion: .contentProcessed { error in
                self.queue.async {
                    do {
                        XCTAssertNil(error)
                        if fault == .scope { pause(); return }
                        let body = try transfer.decoder(expectedBytes: 0)
                        self.readExact(connection, budget: { try body.nextReadBytes() }, accept: { try body.accept(chunk: $0).payload }) { payload in
                            let message = try transfer.receive(payload: payload, isCurrent: { KotlinBoolean(bool: true) },
                                verify: { bytes, signature in KotlinBoolean(bool: AppleIdentity.verify(
                                    certificate: sender.identity.certificate, message: self.data(bytes), signature: signature)) })
                            XCTAssertEqual(try sender.store.groupText(id: message.id)?.receivedBy, [sender.identity.id])
                            XCTAssertEqual(try receiver.store.groupText(id: message.id)?.receivedBy, [receiver.identity.id])
                            if fault == .acknowledgement {
                                let digest = SHA256.hash(data: self.data(try message.payload())).map { String(format: "%02x", $0) }.joined()
                                var ack = self.data(try transfer.acknowledgementFrame(envelope: message, digest: digest))
                                ack[ack.count - 1] = 0
                                connection.send(content: ack, completion: .contentProcessed { error in XCTAssertNil(error) })
                            }
                            pause() // Real commit, but no matching ACK; timer/cancel must still revoke.
                        }
                    } catch { XCTFail("Roster text test peer failed: \(error)") }
                }
            })
        }
    }

    private func pauseBeforeTextACK(_ connection: NWConnection, receiver: Side, sender: Side,
                                    remoteOffer: IosGroupSessionOffer, pause: @escaping () -> Void) throws {
        let anchor = try XCTUnwrap(receiver.store.localGroup())
        let marker = try receiver.store.committedGroupAdoption()
        let offer = try receiver.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId,
            marker: marker, newSessionId: String(repeating: "f", count: 64))
        let selected = try receiver.sessionMemory.selectText(local: offer, remote: remoteOffer,
            groupId: anchor.groupId, founderId: anchor.founderId, marker: marker,
            senderId: sender.identity.id, recipientId: receiver.identity.id)
        let transfer = IosGroupTextTransfer(persistence: receiver.store, memory: receiver.sessionMemory,
            scope: try XCTUnwrap(selected.context), localIdentity: receiver.identity.id)
        connection.send(content: data(try offer.framedBytes()), completion: .contentProcessed { error in
            self.queue.async {
                XCTAssertNil(error)
                let scopeDecoder = IosGroupTextDecoder(expectedBytes: IosGroupTextProtocol.shared.scopeBytes)
                self.readExact(connection, budget: { try scopeDecoder.nextReadBytes() },
                    accept: { try scopeDecoder.accept(chunk: $0).payload }) { scope in
                    try transfer.checkScope(payload: scope)
                    connection.send(content: self.data(try transfer.scopeFrame()), completion: .contentProcessed { error in
                        self.queue.async {
                            XCTAssertNil(error)
                            let decoder = IosGroupTextDecoder(expectedBytes: 0)
                            self.readExact(connection, budget: { try decoder.nextReadBytes() },
                                accept: { try decoder.accept(chunk: $0).payload }) { payload in
                                let message = try transfer.receive(payload: payload, isCurrent: { KotlinBoolean(bool: true) },
                                    verify: { bytes, signature in KotlinBoolean(bool: AppleIdentity.verify(
                                        certificate: sender.identity.certificate, message: self.data(bytes), signature: signature)) })
                                let sent = try XCTUnwrap(sender.store.groupText(id: message.id))
                                XCTAssertEqual(sent.receivedBy, [sender.identity.id]) // No remote receipt yet.
                                XCTAssertEqual(try receiver.store.groupText(id: message.id)?.receivedBy, [receiver.identity.id])
                                pause() // Save succeeded, but deliberately no ACK on the wire.
                            }
                        }
                    })
                }
            }
        })
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

    func testGroupTextBothTLSOrdersDirectionsReceiptsAndReopenedStores() throws {
        for founderInitiates in [true, false] {
            let pair = try fixture(founderInitiates: founderInitiates)
            try confirmBoth(pair.issuer, pair.member)
            closeAndDrain(pair.issuer); closeAndDrain(pair.member)
            try reopen(pair.issuer); try reopen(pair.member)
            let marker = try queue.sync { try XCTUnwrap(pair.member.store.committedGroupAdoption()) }
            var previousSession: String?
            for (sender, receiver, body) in [(pair.issuer, pair.member, "Primo · è 📩"), (pair.member, pair.issuer, "Risposta") ] {
                beginText(sender, receiver, body: body)
                let display = awaitText(sender, receiver)
                if let previousSession { XCTAssertEqual(display.sessionId, previousSession) }
                previousSession = display.sessionId
                try queue.sync {
                    let sent = try XCTUnwrap(sender.store.groupText(id: display.messageId))
                    let saved = try XCTUnwrap(receiver.store.groupText(id: display.messageId))
                    XCTAssertEqual(sent.envelope.body, body)
                    XCTAssertEqual(saved.envelope.body, body)
                    XCTAssertEqual(Set(sent.receivedBy), Set([sender.identity.id, receiver.identity.id]))
                    XCTAssertEqual(saved.receivedBy, [receiver.identity.id])
                    XCTAssertTrue(try marker.sameRecord(other: XCTUnwrap(pair.member.store.committedGroupAdoption())))
                    for side in [sender, receiver] {
                        XCTAssertEqual(try side.store.trusted(), [])
                        XCTAssertEqual(try side.store.history().count, 0)
                        XCTAssertNil(try side.store.pendingGroupAdoption())
                    }
                }
                closeAndDrain(sender); closeAndDrain(receiver)
                try reopen(sender); try reopen(receiver)
                try queue.sync {
                    XCTAssertEqual(try sender.store.groupText(id: display.messageId)?.envelope.body, body)
                    XCTAssertEqual(try receiver.store.groupText(id: display.messageId)?.envelope.sessionId, display.sessionId)
                }
                // B5 does not authorize text, but cannot lose an already-known exact scope.
                beginSession(sender, receiver)
                XCTAssertEqual(awaitSession(sender, receiver), display.sessionId)
                closeAndDrain(sender); closeAndDrain(receiver)
            }
            queue.sync { pair.issuer.sessionMemory.reset(); pair.member.sessionMemory.reset() }
            beginText(pair.issuer, pair.member, body: "Nuova run")
            let next = awaitText(pair.issuer, pair.member)
            XCTAssertNotEqual(next.sessionId, previousSession)
            try queue.sync {
                XCTAssertEqual(try pair.issuer.store.groupText(id: next.messageId)?.envelope.authorSequence, 2)
            }
            closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        }
    }

    func testGroupTextCannotRecreateLostUsedScopeFromB5OrCurrentEndpoints() throws {
        let pair = try fixture(founderInitiates: true)
        try confirmBoth(pair.issuer, pair.member)
        closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        beginText(pair.issuer, pair.member, body: "Conservato")
        let first = awaitText(pair.issuer, pair.member)
        closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        queue.sync { pair.member.sessionMemory.reset() }
        beginSession(pair.issuer, pair.member)
        XCTAssertEqual(awaitSession(pair.issuer, pair.member), first.sessionId)
        closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        beginText(pair.issuer, pair.member, body: "Non deve partire")
        awaitState { pair.issuer.presentation.textSnapshot().phase == .failed && pair.member.presentation.textSnapshot().phase == .failed }
        queue.sync {
            XCTAssertEqual(pair.member.presentation.textSnapshot().failure, .rosterRequired)
            XCTAssertEqual(pair.issuer.presentation.textSnapshot().messageId, "")
            XCTAssertEqual(pair.member.presentation.textSnapshot().messageId, "")
        }
        closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        try queue.sync {
            XCTAssertNotNil(try pair.member.store.groupText(id: first.messageId))
            // Stop all creates a genuinely new session; refused attempt consumed no sequence.
            pair.issuer.sessionMemory.reset(); pair.member.sessionMemory.reset()
        }
        beginText(pair.issuer, pair.member, body: "Dopo stop di tutti")
        let next = awaitText(pair.issuer, pair.member)
        try queue.sync { XCTAssertEqual(try pair.issuer.store.groupText(id: next.messageId)?.envelope.authorSequence, 2) }
    }

    func testGroupTextRolesAndDiagnosticModeMismatchFailBeforeAnyTextThenFreshRetryWorks() throws {
        let pair = try fixture(founderInitiates: false)
        try confirmBoth(pair.issuer, pair.member)
        closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        queue.sync {
            pair.issuer.presentation.sendText(id: pair.member.identity.id, name: "member", body: "A")
            pair.member.presentation.sendText(id: pair.issuer.identity.id, name: "member", body: "B")
        }
        awaitState { pair.issuer.presentation.textSnapshot().phase == .failed && pair.member.presentation.textSnapshot().phase == .failed }
        queue.sync {
            XCTAssertEqual(pair.issuer.presentation.textSnapshot().messageId, "")
            XCTAssertEqual(pair.member.presentation.textSnapshot().messageId, "")
        }
        closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        queue.sync {
            pair.issuer.presentation.sendText(id: pair.member.identity.id, name: "member", body: "A")
            pair.member.presentation.negotiateSession(id: pair.issuer.identity.id, name: "member")
        }
        awaitState { pair.issuer.presentation.textSnapshot().phase == .failed && pair.member.presentation.sessionSnapshot().phase == .failed }
        closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        beginText(pair.issuer, pair.member, body: "Consentito")
        let result = awaitText(pair.issuer, pair.member)
        try queue.sync { XCTAssertEqual(try pair.issuer.store.groupText(id: result.messageId)?.envelope.authorSequence, 1) }
    }

    func testGroupTextMissingMembershipFailsBeforePinAndCancelCannotPublishOldResult() throws {
        let a = try side(), b = try side()
        try connect(a, b)
        closeAndDrain(a); closeAndDrain(b)
        queue.sync {
            a.prepared = 0; b.prepared = 0
            a.presentation.sendText(id: b.identity.id, name: "member", body: "Non ammesso")
            b.presentation.receiveText(id: a.identity.id, name: "member")
        }
        awaitState { a.presentation.textSnapshot().phase == .failed && b.presentation.textSnapshot().phase == .failed }
        queue.sync {
            XCTAssertEqual(a.prepared, 0); XCTAssertEqual(b.prepared, 0)
            XCTAssertEqual(a.presentation.textSnapshot().failure, .unavailable)
            XCTAssertEqual(b.presentation.textSnapshot().failure, .unavailable)
        }
        closeAndDrain(a); closeAndDrain(b)
        let pair = try fixture(founderInitiates: true)
        try confirmBoth(pair.issuer, pair.member)
        closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        queue.sync { pair.issuer.presentation.sendText(id: pair.member.identity.id, name: "member", body: "Annullato") }
        awaitState { pair.issuer.presentation.textSnapshot().phase == .waiting }
        let old = try queue.sync { try XCTUnwrap(pair.issuer.selection) }
        queue.sync { pair.issuer.presentation.cancelGroup() }
        awaitState { pair.issuer.presentation.textSnapshot().phase == .idle }
        beginText(pair.issuer, pair.member, body: "Nuova selezione")
        let result = awaitText(pair.issuer, pair.member)
        queue.sync {
            pair.issuer.presentation.failed(value: old, reason: .failed)
            XCTAssertEqual(pair.issuer.presentation.textSnapshot().messageId, result.messageId)
            XCTAssertEqual(pair.issuer.presentation.textSnapshot().phase, .sent)
        }
    }

    func testGroupTextFacadeRejectsWrongTLSKeyScopeACKAndExpiredContextBeforeReceipts() throws {
        let pair = try fixture(founderInitiates: true)
        try confirmBoth(pair.issuer, pair.member)
        closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        try queue.sync {
            let sender = pair.issuer, receiver = pair.member
            let anchor = try XCTUnwrap(sender.store.localGroup())
            let senderMarker = try sender.store.committedGroupAdoption(), receiverMarker = try receiver.store.committedGroupAdoption()
            let local = try sender.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId,
                marker: senderMarker, newSessionId: String(repeating: "c", count: 64))
            let remote = try receiver.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId,
                marker: receiverMarker, newSessionId: String(repeating: "d", count: 64))
            func transfer(_ side: Side, _ offer: IosGroupSessionOffer, _ peerOffer: IosGroupSessionOffer,
                          _ marker: IosGroupAdoptionJournalSnapshot?) throws -> IosGroupTextTransfer {
                let selected = try side.sessionMemory.selectText(local: offer, remote: peerOffer,
                    groupId: anchor.groupId, founderId: anchor.founderId, marker: marker,
                    senderId: sender.identity.id, recipientId: receiver.identity.id)
                return IosGroupTextTransfer(persistence: side.store, memory: side.sessionMemory,
                    scope: try XCTUnwrap(selected.context), localIdentity: side.identity.id)
            }
            let outgoing = try transfer(sender, local, remote, senderMarker)
            let incoming = try transfer(receiver, remote, local, receiverMarker)
            let current = { KotlinBoolean(bool: true) }
            let expired = { KotlinBoolean(bool: false) }
            let message = try outgoing.prepareOutgoing(id: UUID().uuidString.lowercased(), body: "Firmato",
                isCurrent: current, sign: { try? sender.identity.sign(self.data($0)) })
            let beforeInvalid = data(try receiver.sessionMemory.propose(groupId: anchor.groupId,
                founderId: anchor.founderId, marker: receiverMarker, newSessionId: String(repeating: "e", count: 64)).framedBytes())
            XCTAssertThrowsError(try incoming.receive(payload: message.payload(), isCurrent: current,
                verify: { bytes, signature in KotlinBoolean(bool: AppleIdentity.verify(
                    certificate: receiver.identity.certificate, message: self.data(bytes), signature: signature)) }))
            XCTAssertNil(incoming.attemptedMessageId)
            XCTAssertNil(try receiver.store.groupText(id: message.id))
            XCTAssertEqual(data(try receiver.sessionMemory.propose(groupId: anchor.groupId,
                founderId: anchor.founderId, marker: receiverMarker, newSessionId: String(repeating: "e", count: 64)).framedBytes()), beforeInvalid)
            XCTAssertThrowsError(try incoming.receive(payload: message.payload(), isCurrent: expired,
                verify: { _, _ in XCTFail("Expired before OS verification"); return KotlinBoolean(bool: true) }))
            let saved = try incoming.receive(payload: message.payload(), isCurrent: current,
                verify: { bytes, signature in KotlinBoolean(bool: AppleIdentity.verify(
                    certificate: sender.identity.certificate, message: self.data(bytes), signature: signature)) })
            let digest = SHA256.hash(data: data(try message.payload())).map { String(format: "%02x", $0) }.joined()
            let ack = Data(data(try incoming.acknowledgementFrame(envelope: saved, digest: digest)).dropFirst(4))
            var changedACK = ack
            changedACK[changedACK.count - 1] ^= 1
            XCTAssertThrowsError(try outgoing.acknowledge(payload: bytes(changedACK), envelope: message, digest: digest, isCurrent: current))
            XCTAssertThrowsError(try outgoing.acknowledge(payload: bytes(ack), envelope: message, digest: digest, isCurrent: expired))
            XCTAssertEqual(try sender.store.groupText(id: message.id)?.receivedBy, [sender.identity.id])
            var changedScope = Data(data(try incoming.scopeFrame()).dropFirst(4))
            changedScope[changedScope.count - 1] ^= 1
            XCTAssertThrowsError(try outgoing.checkScope(payload: bytes(changedScope)))
            try outgoing.acknowledge(payload: bytes(ack), envelope: message, digest: digest, isCurrent: current)
            XCTAssertEqual(Set(try XCTUnwrap(sender.store.groupText(id: message.id)).receivedBy),
                Set([sender.identity.id, receiver.identity.id]))
        }
    }

    private func bytes(_ data: Data) -> KotlinByteArray {
        let result = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() { result.set(index: Int32(index), value: Int8(bitPattern: byte)) }
        return result
    }

    func testRosterRestoresUsedSessionAfterEitherMemberReopensWithoutHistoryReplay() throws {
        for founderInitiates in [true, false] {
            let pair = try fixture(founderInitiates: founderInitiates)
            try confirmBoth(pair.issuer, pair.member)
            closeAndDrain(pair.issuer); closeAndDrain(pair.member)
            beginRoster(pair.issuer, pair.member)
            let first = awaitRoster(pair.issuer, pair.member)
            closeAndDrain(pair.issuer); closeAndDrain(pair.member)
            beginText(pair.issuer, pair.member, body: "Prima del rientro")
            let message = awaitText(pair.issuer, pair.member)
            XCTAssertEqual(message.sessionId, first.sessionId)
            closeAndDrain(pair.issuer); closeAndDrain(pair.member)
            for returning in [pair.member, pair.issuer] {
                queue.sync { returning.sessionMemory.reset() }
                try reopen(returning)
                beginRoster(pair.issuer, pair.member)
                XCTAssertEqual(awaitRoster(pair.issuer, pair.member).sessionId, first.sessionId)
                closeAndDrain(pair.issuer); closeAndDrain(pair.member)
                beginSession(pair.issuer, pair.member)
                XCTAssertEqual(awaitSession(pair.issuer, pair.member), first.sessionId)
                closeAndDrain(pair.issuer); closeAndDrain(pair.member)
            }
            beginText(pair.issuer, pair.member, body: "Dopo il rientro")
            let next = awaitText(pair.issuer, pair.member)
            try queue.sync {
                XCTAssertEqual(next.sessionId, first.sessionId)
                XCTAssertEqual(try pair.issuer.store.groupText(id: next.messageId)?.envelope.authorSequence, 2)
                XCTAssertEqual(try pair.member.store.groupText(id: message.messageId)?.envelope.body, message.body)
                for side in [pair.issuer, pair.member] {
                    XCTAssertEqual(try side.store.trusted(), [])
                    XCTAssertEqual(try side.store.history().count, 0)
                    XCTAssertNil(try side.store.pendingGroupAdoption())
                }
            }
            closeAndDrain(pair.issuer); closeAndDrain(pair.member)
        }
    }

    func testRosterPreservesThreeParticipantsWithFounderThenDelegateOfflineAndRefusesLegacyText() throws {
        let pair = try fixture(founderInitiates: true)
        let a = pair.issuer, b = pair.member, c = try side()
        try confirmBoth(a, b)
        closeAndDrain(a); closeAndDrain(b)
        beginRoster(a, b)
        let original = awaitRoster(a, b)
        closeAndDrain(a); closeAndDrain(b)
        beginText(a, b, body: "Non retroattivo")
        let old = awaitText(a, b)
        closeAndDrain(a); closeAndDrain(b)
        try connect(b, c)
        try confirmBoth(b, c)
        closeAndDrain(b); closeAndDrain(c)
        beginRoster(b, c)
        let three = awaitRoster(b, c)
        XCTAssertEqual(three.sessionId, original.sessionId)
        XCTAssertEqual(Set(three.participants), Set([a.identity.id, b.identity.id, c.identity.id]))
        closeAndDrain(b); closeAndDrain(c)
        queue.sync { a.sessionMemory.reset() }
        try reopen(a)
        try connect(a, c, roster: true)
        XCTAssertEqual(awaitRoster(a, c).participants, three.participants)
        closeAndDrain(a); closeAndDrain(c)
        beginSession(a, c)
        XCTAssertEqual(awaitSession(a, c), original.sessionId)
        closeAndDrain(a); closeAndDrain(c)
        beginText(a, c, body: "Non ridurre agli endpoint")
        awaitState { a.presentation.textSnapshot().phase == .failed && c.presentation.textSnapshot().phase == .failed }
        try queue.sync {
            XCTAssertEqual(a.presentation.textSnapshot().failure, .rosterRequired)
            XCTAssertEqual(c.presentation.textSnapshot().failure, .rosterRequired)
            XCTAssertEqual(a.presentation.textSnapshot().messageId, "")
            XCTAssertNil(try c.store.groupText(id: old.messageId))
            XCTAssertEqual(Set(try XCTUnwrap(a.store.groupText(id: old.messageId)).receivedBy), Set([a.identity.id, b.identity.id]))
        }
    }

    func testRosterRefusesLostSnapshotsAndMissingLegacyOfflineProofs() throws {
        let pair = try fixture(founderInitiates: false)
        let a = pair.issuer, b = pair.member, c = try side()
        try confirmBoth(a, b)
        closeAndDrain(a); closeAndDrain(b)
        beginText(a, b, body: "Scope legacy")
        let old = awaitText(a, b)
        closeAndDrain(a); closeAndDrain(b)
        try connect(b, c)
        try confirmBoth(b, c)
        closeAndDrain(b); closeAndDrain(c)
        beginRoster(b, c)
        awaitState { b.presentation.rosterSnapshot().phase == .failed && c.presentation.rosterSnapshot().phase == .failed }
        queue.sync { XCTAssertEqual(b.presentation.rosterSnapshot().failure, .missingParticipants) }
        closeAndDrain(b); closeAndDrain(c)
        try connect(a, b, roster: true)
        XCTAssertEqual(awaitRoster(a, b).sessionId, old.sessionId) // Both actual legacy members supply their signatures.
        closeAndDrain(a); closeAndDrain(b)
        queue.sync { b.sessionMemory.reset() }
        beginSession(a, b)
        _ = awaitSession(a, b) // B learns used ID, never the roster.
        closeAndDrain(a); closeAndDrain(b)
        queue.sync { a.sessionMemory.reset() }
        beginSession(a, b)
        _ = awaitSession(a, b) // Both now have used ID but no snapshot.
        closeAndDrain(a); closeAndDrain(b)
        beginRoster(a, b)
        awaitState { a.presentation.rosterSnapshot().phase == .failed && b.presentation.rosterSnapshot().phase == .failed }
        try queue.sync {
            XCTAssertEqual(a.presentation.rosterSnapshot().failure, .missingParticipants)
            XCTAssertEqual(b.presentation.rosterSnapshot().failure, .missingParticipants)
            XCTAssertNotNil(try a.store.groupText(id: old.messageId))
        }
    }

    func testEmptyThreeMemberRosterCannotBeReducedToTwoOnlineTextEndpoints() throws {
        let pair = try fixture(founderInitiates: false)
        let a = pair.issuer, b = pair.member, c = try side()
        try confirmBoth(a, b)
        closeAndDrain(a); closeAndDrain(b)
        beginRoster(a, b)
        let empty = awaitRoster(a, b)
        closeAndDrain(a); closeAndDrain(b)
        try connect(b, c)
        try confirmBoth(b, c)
        closeAndDrain(b); closeAndDrain(c)
        beginRoster(b, c)
        XCTAssertEqual(awaitRoster(b, c).participants.count, 3)
        closeAndDrain(b); closeAndDrain(c)
        beginText(b, c, body: "Ancora nessun testo nella sessione")
        awaitState { b.presentation.textSnapshot().phase == .failed && c.presentation.textSnapshot().phase == .failed }
        queue.sync {
            XCTAssertEqual(b.presentation.textSnapshot().failure, .rosterRequired)
            XCTAssertEqual(c.presentation.textSnapshot().failure, .rosterRequired)
            XCTAssertEqual(b.presentation.textSnapshot().messageId, "")
        }
        closeAndDrain(b); closeAndDrain(c)
        beginRoster(b, c)
        XCTAssertEqual(awaitRoster(b, c).sessionId, empty.sessionId)
    }

    func testRosterModeMismatchAndCancelledReselectionCannotPublishOldResult() throws {
        let pair = try fixture(founderInitiates: true)
        let a = pair.issuer, b = pair.member
        try confirmBoth(a, b)
        closeAndDrain(a); closeAndDrain(b)
        queue.sync {
            a.presentation.synchronizeRoster(id: b.identity.id, name: "member")
            b.presentation.negotiateSession(id: a.identity.id, name: "member")
        }
        awaitState { a.presentation.rosterSnapshot().phase == .failed && b.presentation.sessionSnapshot().phase == .failed }
        closeAndDrain(a); closeAndDrain(b)
        queue.sync { a.presentation.synchronizeRoster(id: b.identity.id, name: "member") }
        queue.sync {} // Drain the queued selection before cancellation.
        closeAndDrain(a)
        beginRoster(a, b)
        _ = awaitRoster(a, b)
    }

    func testRosterFacadeRejectsWrongTLSCertificateChangedRunAndInvalidSignatureWithoutInstalling() throws {
        let pair = try fixture(founderInitiates: true)
        let a = pair.issuer, b = pair.member
        try confirmBoth(a, b)
        closeAndDrain(a); closeAndDrain(b)
        try queue.sync {
            let anchor = try XCTUnwrap(a.store.localGroup())
            let am = try a.store.committedGroupAdoption(), bm = try b.store.committedGroupAdoption()
            let ao = try a.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId, marker: am, newSessionId: String(repeating: "c", count: 64))
            let bo = try b.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId, marker: bm, newSessionId: String(repeating: "d", count: 64))
            let ae = try XCTUnwrap(a.sessionMemory.selectRoster(local: ao, remote: bo, groupId: anchor.groupId, founderId: anchor.founderId, marker: am).exchange)
            let be = try XCTUnwrap(b.sessionMemory.selectRoster(local: bo, remote: ao, groupId: anchor.groupId, founderId: anchor.founderId, marker: bm).exchange)
            let ap = try proposeRoster(a, exchange: ae), bp = try proposeRoster(b, exchange: be)
            let original = data(try a.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId, marker: am, newSessionId: String(repeating: "e", count: 64)).framedBytes())
            XCTAssertThrowsError(try GroupMembership.withVerifier { verify in
                try ae.merge(payload: bp.payload(), peerId: b.identity.id, peerCertificateDer: certificateDer(a),
                    isCurrent: { KotlinBoolean(bool: true) }, verify: verify)
            })
            XCTAssertThrowsError(try ae.merge(payload: bp.payload(), peerId: b.identity.id, peerCertificateDer: certificateDer(b),
                isCurrent: { KotlinBoolean(bool: true) }, verify: { _, _, _ in KotlinBoolean(bool: false) }))
            XCTAssertThrowsError(try ae.install(snapshot: ap, isCurrent: { KotlinBoolean(bool: true) }))
            XCTAssertEqual(data(try a.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId, marker: am,
                newSessionId: String(repeating: "e", count: 64)).framedBytes()), original)
            let merged = try mergeRoster(ae, payload: bp.payload(), peer: b)
            XCTAssertEqual(Set(merged.participants), Set([a.identity.id, b.identity.id]))
            a.sessionMemory.reset()
            XCTAssertThrowsError(try ae.install(snapshot: merged, isCurrent: { KotlinBoolean(bool: true) }))
            XCTAssertThrowsError(try be.merge(payload: ap.payload(), peerId: a.identity.id, peerCertificateDer: certificateDer(a),
                isCurrent: { KotlinBoolean(bool: false) }, verify: { _, _, _ in XCTFail("Expired before OS"); return nil }))
        }
    }

    func testMembershipVerifierChecksExactDEROnCacheHitAcrossChains() throws {
        let a = try side(), b = try side()
        try found(a)
        try queue.sync {
            let bytes = self.bytes(Data("cache-hit".utf8))
            let signature = try a.identity.sign(Data("cache-hit".utf8))
            let proof = try LocalGroupAdmission.prepare(identity: a.identity, persistence: a.store, memberID: b.identity.id)
            let valid = try XCTUnwrap(proof.certificates.first { $0.identity == a.identity.id })
            let substituted = try XCTUnwrap(proof.withIssuerCertificate(identity: a.identity.id, der: certificateDer(b)).certificates.first { $0.identity == a.identity.id })
            let verifier = GroupAdoptionJournalInspector.CertificateVerifier(maximumDerBytes: Int(proof.maximumDerBytes), now: Date())
            XCTAssertTrue(verifier.verify(valid, bytes, signature).boolValue)
            XCTAssertFalse(verifier.verify(substituted, bytes, signature).boolValue)
            XCTAssertNotNil(verifier.failure)
        }
    }

    private func certificateDer(_ side: Side) -> String {
        (SecCertificateCopyData(side.identity.certificate) as Data).base64EncodedString()
    }

    private func proposeRoster(_ side: Side, exchange: IosGroupRosterExchange) throws -> IosGroupRosterSnapshot {
        try exchange.propose(membership: GroupMembership.prepare(identity: side.identity, persistence: side.store),
            certificateDer: certificateDer(side), isCurrent: { KotlinBoolean(bool: true) },
            sign: { try? side.identity.sign(self.data($0)) })
    }

    private func mergeRoster(_ exchange: IosGroupRosterExchange, payload: KotlinByteArray, peer: Side) throws -> IosGroupRosterSnapshot {
        try GroupMembership.withVerifier { verify in
            try exchange.merge(payload: payload, peerId: peer.identity.id, peerCertificateDer: certificateDer(peer),
                isCurrent: { KotlinBoolean(bool: true) }, verify: verify)
        }
    }

    private func beginRoster(_ a: Side, _ b: Side) {
        queue.sync {
            a.presentation.synchronizeRoster(id: b.identity.id, name: "member")
            b.presentation.synchronizeRoster(id: a.identity.id, name: "member")
        }
    }

    private func awaitRoster(_ a: Side, _ b: Side) -> IosGroupRosterDisplay {
        awaitState { a.presentation.rosterSnapshot().phase == .synchronized && b.presentation.rosterSnapshot().phase == .synchronized }
        return queue.sync {
            let local = a.presentation.rosterSnapshot(), remote = b.presentation.rosterSnapshot()
            XCTAssertEqual(local.sessionId, remote.sessionId)
            XCTAssertEqual(local.participants, remote.participants)
            XCTAssertEqual(local.sessionId.count, 64)
            return local
        }
    }

    private func beginText(_ sender: Side, _ receiver: Side, body: String) {
        queue.sync {
            sender.presentation.sendText(id: receiver.identity.id, name: "member", body: body)
            receiver.presentation.receiveText(id: sender.identity.id, name: "member")
        }
    }

    /// Facade boundary tests use real membership/OS signatures and explicit agreement, not a live socket.
    private func rosterTransfers(_ sender: Side, _ receiver: Side) throws -> (IosGroupTextTransfer, IosGroupTextTransfer) {
        let anchor = try XCTUnwrap(sender.store.localGroup())
        let sm = try sender.store.committedGroupAdoption(), rm = try receiver.store.committedGroupAdoption()
        let so = try sender.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId,
            marker: sm, newSessionId: String(repeating: "c", count: 64))
        let ro = try receiver.sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId,
            marker: rm, newSessionId: String(repeating: "d", count: 64))
        let se = try XCTUnwrap(sender.sessionMemory.selectRoster(local: so, remote: ro,
            groupId: anchor.groupId, founderId: anchor.founderId, marker: sm).exchange)
        let re = try XCTUnwrap(receiver.sessionMemory.selectRoster(local: ro, remote: so,
            groupId: anchor.groupId, founderId: anchor.founderId, marker: rm).exchange)
        let sp = try proposeRoster(sender, exchange: se), rp = try proposeRoster(receiver, exchange: re)
        let mergedSender = try mergeRoster(se, payload: rp.payload(), peer: receiver)
        let mergedReceiver = try mergeRoster(re, payload: sp.payload(), peer: sender)
        XCTAssertEqual(try data(mergedSender.payload()), try data(mergedReceiver.payload()))
        let digest = SHA256.hash(data: data(try mergedSender.payload())).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(try data(mergedSender.agreement(digest: digest)), try data(mergedReceiver.agreement(digest: digest)))
        let current = { KotlinBoolean(bool: true) }
        let sc = try se.installForText(snapshot: mergedSender, senderId: sender.identity.id, recipientId: receiver.identity.id,
            digest: digest, isCurrent: current)
        let rc = try re.installForText(snapshot: mergedReceiver, senderId: sender.identity.id, recipientId: receiver.identity.id,
            digest: digest, isCurrent: current)
        return (IosGroupTextTransfer(persistence: sender.store, memory: sender.sessionMemory, scope: sc, localIdentity: sender.identity.id),
                IosGroupTextTransfer(persistence: receiver.store, memory: receiver.sessionMemory, scope: rc, localIdentity: receiver.identity.id))
    }

    func testRosterTextFacadeSavedCopyRequiresValidSignatureCurrentRunAndExactACK() throws {
        let pair = try fixture(founderInitiates: true)
        let sender = pair.issuer, receiver = pair.member
        try confirmBoth(sender, receiver)
        closeAndDrain(sender); closeAndDrain(receiver)
        try queue.sync {
            let (outgoing, incoming) = try rosterTransfers(sender, receiver)
            let current = { KotlinBoolean(bool: true) }
            let expired = { KotlinBoolean(bool: false) }
            var selected: IosGroupAdmissionSelection?
            let display = IosGroupAdmissionController(requestSelect: { selected = $0 }, requestConfirm: { _ in }, requestCancel: {})
            display.sendRosterText(id: receiver.identity.id, name: "member", body: "Copia immutabile")
            let selection = try XCTUnwrap(selected)
            display.selected(value: selection)
            display.textTransferring(value: selection)
            let message = try outgoing.prepareOutgoing(id: UUID().uuidString.lowercased(), body: "Copia immutabile",
                isCurrent: current, sign: { try? sender.identity.sign(self.data($0)) })
            let original = try data(message.payload())
            XCTAssertEqual(outgoing.scopeBytes, 324)
            XCTAssertEqual(try data(outgoing.scopeFrame()).count, 328)
            XCTAssertThrowsError(try outgoing.prepareSaved(id: message.id, isCurrent: expired,
                verify: { _, _ in XCTFail("Expired before OS"); return KotlinBoolean(bool: true) }))
            XCTAssertThrowsError(try outgoing.prepareSaved(id: message.id, isCurrent: current,
                verify: { bytes, signature in KotlinBoolean(bool: AppleIdentity.verify(certificate: receiver.identity.certificate,
                    message: self.data(bytes), signature: signature)) }))
            let saved = try outgoing.prepareSaved(id: message.id, isCurrent: current,
                verify: { bytes, signature in KotlinBoolean(bool: AppleIdentity.verify(certificate: sender.identity.certificate,
                    message: self.data(bytes), signature: signature)) })
            XCTAssertEqual(try data(saved.payload()), original)
            XCTAssertThrowsError(try incoming.receive(payload: message.payload(), isCurrent: current,
                verify: { bytes, signature in KotlinBoolean(bool: AppleIdentity.verify(certificate: receiver.identity.certificate,
                    message: self.data(bytes), signature: signature)) }))
            XCTAssertNil(incoming.attemptedMessageId)
            XCTAssertNil(try receiver.store.groupText(id: message.id))
            let received = try incoming.receive(payload: message.payload(), isCurrent: current,
                verify: { bytes, signature in KotlinBoolean(bool: AppleIdentity.verify(certificate: sender.identity.certificate,
                    message: self.data(bytes), signature: signature)) })
            let digest = SHA256.hash(data: original).map { String(format: "%02x", $0) }.joined()
            let ack = Data(data(try incoming.acknowledgementFrame(envelope: received, digest: digest)).dropFirst(4))
            XCTAssertEqual(Array(ack.prefix(4)), [76, 71, 65, 1])
            var wrongDomain = ack
            wrongDomain[1] = 84 // LTA must not be accepted as LGA, even with matching remaining fields.
            XCTAssertThrowsError(try outgoing.acknowledge(payload: bytes(wrongDomain), envelope: saved, digest: digest, isCurrent: current))
            XCTAssertThrowsError(try outgoing.acknowledge(payload: bytes(ack), envelope: saved, digest: digest, isCurrent: expired))
            XCTAssertEqual(try sender.store.groupText(id: saved.id)?.receivedBy, [sender.identity.id])
            XCTAssertThrowsError(try outgoing.publishDelivery(controller: display, selection: selection, envelope: saved, isCurrent: current))
            XCTAssertEqual(display.textSnapshot().phase, .transferring)
            try outgoing.acknowledge(payload: bytes(ack), envelope: saved, digest: digest, isCurrent: current)
            try outgoing.publishDelivery(controller: display, selection: selection, envelope: saved, isCurrent: current)
            XCTAssertEqual(display.textSnapshot().phase, .sent)
            XCTAssertEqual(Set(try XCTUnwrap(sender.store.groupText(id: saved.id)).receivedBy), Set([sender.identity.id, receiver.identity.id]))
            let next = try outgoing.prepareOutgoing(id: UUID().uuidString.lowercased(), body: "Dopo copia",
                isCurrent: current, sign: { try? sender.identity.sign(self.data($0)) })
            XCTAssertEqual(next.authorSequence, 2)
            sender.sessionMemory.reset()
            XCTAssertThrowsError(try outgoing.publishDelivery(controller: display, selection: selection, envelope: saved, isCurrent: current))
            XCTAssertThrowsError(try outgoing.prepareSaved(id: saved.id, isCurrent: current,
                verify: { _, _ in XCTFail("Reset run before OS"); return KotlinBoolean(bool: true) }))
        }
    }

    func testRosterTextFacadeRevokedAfterOSOrAfterCommitCannotReturnReceipt() throws {
        let pair = try fixture(founderInitiates: false)
        let sender = pair.issuer, receiver = pair.member
        try confirmBoth(sender, receiver)
        closeAndDrain(sender); closeAndDrain(receiver)
        try queue.sync {
            let (outgoing, incoming) = try rosterTransfers(sender, receiver)
            let current = { KotlinBoolean(bool: true) }
            let message = try outgoing.prepareOutgoing(id: UUID().uuidString.lowercased(), body: "Revoca ai confini",
                isCurrent: current, sign: { try? sender.identity.sign(self.data($0)) })
            var live = true
            XCTAssertThrowsError(try incoming.receive(payload: message.payload(), isCurrent: { KotlinBoolean(bool: live) },
                verify: { bytes, signature in
                    let valid = AppleIdentity.verify(certificate: sender.identity.certificate, message: self.data(bytes), signature: signature)
                    live = false
                    return KotlinBoolean(bool: valid)
                }))
            XCTAssertNil(try receiver.store.groupText(id: message.id))
            XCTAssertNil(incoming.attemptedMessageId)
            XCTAssertThrowsError(try incoming.receive(payload: message.payload(),
                isCurrent: { KotlinBoolean(bool: (try? receiver.store.groupText(id: message.id)) == nil) },
                verify: { bytes, signature in KotlinBoolean(bool: AppleIdentity.verify(certificate: sender.identity.certificate,
                    message: self.data(bytes), signature: signature)) }))
            // The real transaction entered and committed; the facade must not return ACK evidence.
            XCTAssertEqual(incoming.attemptedMessageId, message.id)
            XCTAssertEqual(try receiver.store.groupText(id: message.id)?.receivedBy, [receiver.identity.id])
            XCTAssertEqual(try sender.store.groupText(id: message.id)?.receivedBy, [sender.identity.id])
            let duplicate = try incoming.receive(payload: message.payload(), isCurrent: current,
                verify: { bytes, signature in KotlinBoolean(bool: AppleIdentity.verify(certificate: sender.identity.certificate,
                    message: self.data(bytes), signature: signature)) })
            XCTAssertEqual(try data(duplicate.payload()), try data(message.payload()))
        }
    }

    private func beginRosterText(_ sender: Side, _ receiver: Side, body: String) {
        queue.sync {
            sender.presentation.sendRosterText(id: receiver.identity.id, name: "member", body: body)
            receiver.presentation.receiveRosterText(id: sender.identity.id, name: "member")
        }
    }

    private func beginCopy(_ sender: Side, _ receiver: Side, id: String) {
        queue.sync {
            sender.presentation.deliverRosterText(id: receiver.identity.id, name: "member", messageId: id)
            receiver.presentation.receiveRosterText(id: sender.identity.id, name: "member")
        }
    }

    func testRosterTextBothTLSOrdersCopiesAfterAuthorReopensAndNoCounterReuse() throws {
        for founderInitiates in [true, false] {
            let pair = try fixture(founderInitiates: founderInitiates)
            let a = pair.issuer, b = pair.member
            try confirmBoth(a, b)
            closeAndDrain(a); closeAndDrain(b)
            beginRosterText(a, b, body: "Destinatari completi · ☕")
            let first = awaitText(a, b)
            let original = try queue.sync { try data(XCTUnwrap(a.store.groupText(id: first.messageId)).envelope.payload()) }
            closeAndDrain(a); closeAndDrain(b)
            queue.sync { a.sessionMemory.reset() }
            try reopen(a) // Author lost run memory; only B retains the live session snapshot.
            beginCopy(a, b, id: first.messageId)
            XCTAssertEqual(awaitText(a, b).messageId, first.messageId)
            closeAndDrain(a); closeAndDrain(b)
            beginCopy(a, b, id: first.messageId) // Exact duplicate does not reserve a new sequence.
            XCTAssertEqual(awaitText(a, b).sessionId, first.sessionId)
            closeAndDrain(a); closeAndDrain(b)
            beginRosterText(a, b, body: "Dopo due copie")
            let next = awaitText(a, b)
            try queue.sync {
                let saved = try XCTUnwrap(a.store.groupText(id: first.messageId))
                XCTAssertEqual(try data(saved.envelope.payload()), original)
                XCTAssertEqual(Set(saved.envelope.recipients), Set([a.identity.id, b.identity.id]))
                XCTAssertEqual(Set(saved.receivedBy), Set([a.identity.id, b.identity.id]))
                XCTAssertEqual(try a.store.groupText(id: next.messageId)?.envelope.authorSequence, 2)
            }
            closeAndDrain(a); closeAndDrain(b)
            beginRosterText(b, a, body: "Direzione opposta")
            XCTAssertEqual(awaitText(b, a).sessionId, first.sessionId)
            closeAndDrain(a); closeAndDrain(b)
            try reopen(a); try reopen(b)
            try queue.sync {
                XCTAssertEqual(try data(XCTUnwrap(b.store.groupText(id: first.messageId)).envelope.payload()), original)
                for side in [a, b] {
                    XCTAssertEqual(try side.store.trusted(), [])
                    XCTAssertEqual(try side.store.history().count, 0)
                    XCTAssertNil(try side.store.pendingGroupAdoption())
                }
            }
        }
    }

    func testRosterTextKeepsOfflineFounderAndDeliversSameEnvelopeToTwoRecipients() throws {
        let pair = try fixture(founderInitiates: true)
        let a = pair.issuer, b = pair.member, c = try side()
        try confirmBoth(a, b)
        closeAndDrain(a); closeAndDrain(b)
        beginRoster(a, b)
        let original = awaitRoster(a, b)
        closeAndDrain(a); closeAndDrain(b)
        try connect(b, c)
        try confirmBoth(b, c)
        closeAndDrain(b); closeAndDrain(c)
        beginRosterText(b, c, body: "Anche ad A offline")
        let first = awaitText(b, c)
        XCTAssertEqual(first.sessionId, original.sessionId)
        let payload = try queue.sync { () throws -> Data in
            let saved = try XCTUnwrap(b.store.groupText(id: first.messageId))
            XCTAssertEqual(Set(saved.envelope.recipients), Set([a.identity.id, b.identity.id, c.identity.id]))
            XCTAssertEqual(Set(saved.receivedBy), Set([b.identity.id, c.identity.id]))
            XCTAssertEqual(try c.store.groupText(id: first.messageId)?.receivedBy, [c.identity.id])
            XCTAssertNil(try a.store.groupText(id: first.messageId))
            return try data(saved.envelope.payload())
        }
        closeAndDrain(b); closeAndDrain(c)
        queue.sync { a.sessionMemory.reset() }
        try reopen(a)
        try connect(b, a, rosterTextSender: b, rosterTextMessageId: first.messageId)
        XCTAssertEqual(awaitText(b, a).messageId, first.messageId)
        closeAndDrain(b); closeAndDrain(a)
        beginCopy(b, a, id: first.messageId)
        _ = awaitText(b, a)
        closeAndDrain(b); closeAndDrain(a)
        try reopen(b); try reopen(a)
        try queue.sync {
            let authorCopy = try XCTUnwrap(b.store.groupText(id: first.messageId))
            XCTAssertEqual(Set(authorCopy.receivedBy), Set([a.identity.id, b.identity.id, c.identity.id]))
            XCTAssertEqual(try data(authorCopy.envelope.payload()), payload)
            XCTAssertEqual(try data(XCTUnwrap(a.store.groupText(id: first.messageId)).envelope.payload()), payload)
            XCTAssertEqual(try a.store.groupText(id: first.messageId)?.receivedBy, [a.identity.id])
        }
        beginRosterText(b, a, body: "Contatore dopo duplicati")
        let next = awaitText(b, a)
        try queue.sync { XCTAssertEqual(try b.store.groupText(id: next.messageId)?.envelope.authorSequence, 2) }
    }

    func testRosterTextLaterAdmissionCannotReceiveOldCopyOrResignItsRecipients() throws {
        let pair = try fixture(founderInitiates: false)
        let a = pair.issuer, b = pair.member, c = try side()
        try confirmBoth(a, b)
        closeAndDrain(a); closeAndDrain(b)
        beginRosterText(b, a, body: "Prima di C")
        let original = awaitText(b, a)
        closeAndDrain(a); closeAndDrain(b)
        try connect(b, c); try confirmBoth(b, c)
        closeAndDrain(b); closeAndDrain(c)
        beginRosterText(b, c, body: "Adesso in tre")
        _ = awaitText(b, c)
        closeAndDrain(b); closeAndDrain(c)
        let prepared = queue.sync { b.prepared }
        queue.sync { b.presentation.deliverRosterText(id: c.identity.id, name: "member", messageId: original.messageId) }
        awaitState { b.presentation.textSnapshot().phase == .failed }
        try queue.sync {
            XCTAssertEqual(b.prepared, prepared) // Reject non-recipient before enabling its pin.
            XCTAssertNil(try c.store.groupText(id: original.messageId))
        }
        closeAndDrain(b)
        try connect(b, a, rosterTextSender: b, rosterTextMessageId: original.messageId)
        awaitState { a.presentation.textSnapshot().phase == .failed && b.presentation.textSnapshot().phase == .failed }
        try queue.sync {
            XCTAssertEqual(b.presentation.textSnapshot().failure, .rosterRequired)
            XCTAssertEqual(b.presentation.textSnapshot().messageId, "")
            XCTAssertEqual(try b.store.groupText(id: original.messageId)?.envelope.recipients.count, 2)
            XCTAssertEqual(try a.store.groupText(id: original.messageId)?.envelope.recipients.count, 2)
        }
        closeAndDrain(a); closeAndDrain(b)
        beginRosterText(b, a, body: "La copia rifiutata non consuma contatori")
        let next = awaitText(b, a)
        try queue.sync { XCTAssertEqual(try b.store.groupText(id: next.messageId)?.envelope.authorSequence, 3) }
    }

    func testRosterTextModesAndCancellationCannotPublishStaleReceiptOrConsumeCounters() throws {
        let pair = try fixture(founderInitiates: true)
        let a = pair.issuer, b = pair.member
        try confirmBoth(a, b)
        closeAndDrain(a); closeAndDrain(b)
        queue.sync {
            a.presentation.sendRosterText(id: b.identity.id, name: "member", body: "Modalità diverse")
            b.presentation.receiveText(id: a.identity.id, name: "member")
        }
        awaitState { a.presentation.textSnapshot().phase == .failed && b.presentation.textSnapshot().phase == .failed }
        closeAndDrain(a); closeAndDrain(b)
        queue.sync { a.presentation.sendRosterText(id: b.identity.id, name: "member", body: "Vecchia selezione") }
        awaitState { a.presentation.textSnapshot().phase == .waiting }
        queue.sync { a.presentation.cancelGroup() }
        awaitState { a.presentation.textSnapshot().phase == .idle }
        beginRosterText(a, b, body: "Selezione corrente")
        let sent = awaitText(a, b)
        try queue.sync { XCTAssertEqual(try a.store.groupText(id: sent.messageId)?.envelope.authorSequence, 1) }
        closeAndDrain(a); closeAndDrain(b)
        queue.sync { b.presentation.deliverRosterText(id: a.identity.id, name: "member", messageId: sent.messageId) }
        awaitState { b.presentation.textSnapshot().phase == .failed } // Received copy is not B's authorship.
        closeAndDrain(b)
        queue.sync { a.sessionMemory.reset(); b.sessionMemory.reset() }
        beginCopy(a, b, id: sent.messageId)
        awaitState { a.presentation.textSnapshot().phase == .failed && b.presentation.textSnapshot().phase == .failed }
        queue.sync { XCTAssertEqual(a.presentation.textSnapshot().failure, .rosterRequired) }
        closeAndDrain(a); closeAndDrain(b)
        beginRosterText(a, b, body: "Nuova sessione")
        let fresh = awaitText(a, b)
        XCTAssertNotEqual(fresh.sessionId, sent.sessionId)
        try queue.sync { XCTAssertEqual(try a.store.groupText(id: fresh.messageId)?.envelope.authorSequence, 2) }
    }

    func testRosterTextCannotOmitLegacyOfflineParticipantWithoutItsSignedJoin() throws {
        let pair = try fixture(founderInitiates: true)
        let a = pair.issuer, b = pair.member, c = try side()
        try confirmBoth(a, b)
        closeAndDrain(a); closeAndDrain(b)
        beginText(a, b, body: "Scope precedente senza attestazioni roster")
        let old = awaitText(a, b)
        closeAndDrain(a); closeAndDrain(b)
        try connect(b, c); try confirmBoth(b, c)
        closeAndDrain(b); closeAndDrain(c)
        beginRosterText(b, c, body: "Non dimenticare A")
        awaitState { b.presentation.textSnapshot().phase == .failed && c.presentation.textSnapshot().phase == .failed }
        try queue.sync {
            XCTAssertEqual(b.presentation.textSnapshot().failure, .rosterRequired)
            XCTAssertEqual(b.presentation.textSnapshot().messageId, "")
            XCTAssertNil(try c.store.groupText(id: old.messageId))
            XCTAssertEqual(try b.store.groupText(id: old.messageId)?.envelope.recipients.count, 2)
        }
        closeAndDrain(b); closeAndDrain(c)
        try connect(b, a, rosterTextSender: b, rosterTextBody: "A torna e firma la propria presenza")
        let next = awaitText(b, a)
        XCTAssertEqual(next.sessionId, old.sessionId)
        try queue.sync { XCTAssertEqual(try b.store.groupText(id: next.messageId)?.envelope.authorSequence, 1) }
    }

    private func awaitText(_ sender: Side, _ receiver: Side) -> IosGroupTextDisplay {
        awaitState { sender.presentation.textSnapshot().phase == .sent && receiver.presentation.textSnapshot().phase == .received }
        return queue.sync {
            let result = sender.presentation.textSnapshot(), saved = receiver.presentation.textSnapshot()
            XCTAssertEqual(result.messageId, saved.messageId)
            XCTAssertEqual(result.sessionId, saved.sessionId)
            XCTAssertEqual(result.body, saved.body)
            XCTAssertEqual(result.messageId.count, 36)
            return result
        }
    }

    private func reopen(_ side: Side) throws {
        try queue.sync {
            side.store.close()
            stores.removeAll { $0 === side.store }
            side.store = try IosEntryKt.openIosPersistence(databaseDirectory: side.directory.path)
            stores.append(side.store)
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

    private func connect(_ issuer: Side, _ member: Side, checking: Set<String> = [], negotiating: Set<String> = [], roster: Bool = false,
                         rosterTextSender: Side? = nil, rosterTextBody: String = "", rosterTextMessageId: String? = nil) throws {
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
                if let sender = rosterTextSender {
                    if side === sender {
                        if let messageId = rosterTextMessageId { side.presentation.deliverRosterText(id: peer.identity.id, name: "member", messageId: messageId) }
                        else { side.presentation.sendRosterText(id: peer.identity.id, name: "member", body: rosterTextBody) }
                    } else { side.presentation.receiveRosterText(id: peer.identity.id, name: "member") }
                } else if roster { side.presentation.synchronizeRoster(id: peer.identity.id, name: "member") }
                else if negotiating.contains(side.identity.id) { side.presentation.negotiateSession(id: peer.identity.id, name: "member") }
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
