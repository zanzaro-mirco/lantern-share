import CryptoKit
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
    private var groupChannels: [GroupAdmissionChannel] = []
    private var scriptedPeers: [ScriptedPeer] = []
    private var connections: [NWConnection] = []
    private var listeners: [NWListener] = []
    private var namespaces: [String] = []

    func testEvidenceExchangeHandsOverActualTLSRequiresBothConfirmationsAndSurvivesOldDeinit() throws {
        let pair = try readyPair()
        let evidence = try groupEvidence(issuer: pair.clientIdentity, member: pair.serverIdentity.id)
        let group = String(repeating: "c", count: 64)
        let leftConfirmed = expectation(description: "issuer group confirmed")
        let rightConfirmed = expectation(description: "member group confirmed")
        let oldReleased = expectation(description: "both old owners destroyed without closing TLS")
        try queue.sync {
            weak var left: HandshakeV1Channel?
            weak var right: HandshakeV1Channel?
            weak var leftGroup: GroupAdmissionChannel?
            weak var rightGroup: GroupAdmissionChannel?
            var leftTicket: (IosGroupAdmissionComparison, String)?
            var rightTicket: (IosGroupAdmissionComparison, String)?
            var explicitlyConfirmed = false
            var leftDone = false
            var rightDone = false
            var transfers = 0
            func confirmBoth() {
                guard !explicitlyConfirmed, let leftTicket, let rightTicket else { return }
                XCTAssertEqual(leftTicket.1, rightTicket.1)
                XCTAssertEqual(leftTicket.1.count, 64)
                explicitlyConfirmed = true // Test-only explicit comparison of the two full codes.
                leftGroup?.confirm(leftTicket.0)
                rightGroup?.confirm(rightTicket.0)
            }
            func oldDestroyed() {
                transfers += 1
                if transfers == 2 {
                    self.queue.async {
                        XCTAssertNil(left)
                        XCTAssertNil(right)
                        oldReleased.fulfill()
                    }
                }
            }
            let leftCallbacks = GroupAdmissionChannelCallbacks(onSnapshot: { snapshot in
                if snapshot.phase == .confirmed, !leftDone {
                    XCTAssertTrue(explicitlyConfirmed)
                    leftDone = true
                    leftConfirmed.fulfill()
                }
            }, onComparison: { ticket, code in leftTicket = (ticket, code); confirmBoth() }, onClosed: { failure in
                if case .confirmation(let reason) = failure, reason.name == "CANCELLED" || reason.name == "TRANSPORT" {} else {
                    XCTFail("Unexpected group failure")
                }
            })
            let rightCallbacks = GroupAdmissionChannelCallbacks(onSnapshot: { snapshot in
                if snapshot.phase == .confirmed, !rightDone {
                    XCTAssertTrue(explicitlyConfirmed)
                    rightDone = true
                    rightConfirmed.fulfill()
                }
            }, onComparison: { ticket, code in rightTicket = (ticket, code); confirmBoth() }, onClosed: { failure in
                if case .confirmation(let reason) = failure, reason.name == "CANCELLED" || reason.name == "TRANSPORT" {} else {
                    XCTFail("Unexpected group failure")
                }
            })
            left = try adopt(pair, client: true, continuation: .groupAdmission(onHello: {
                XCTAssertTrue(left?.sendEvidenceAndTransfer(expectedGroup: group, expectedFounder: pair.clientIdentity.id,
                    evidence: evidence, callbacks: leftCallbacks, onTransferred: { next in
                        left?.cancel() // Must be inert even before the receiving owner starts.
                        left?.start()
                        self.channels.removeAll { $0 === left }
                        leftGroup = next
                        self.groupChannels.append(next)
                        next.start()
                        oldDestroyed()
                    }) ?? false)
                XCTAssertFalse(left?.sendEvidenceAndTransfer(expectedGroup: group, expectedFounder: pair.clientIdentity.id,
                    evidence: evidence, callbacks: leftCallbacks, onTransferred: { _ in XCTFail("Double transfer") }) ?? false)
            }), onComparison: { _, _ in XCTFail("Bootstrap APPROVE must remain unavailable") },
            onClosed: { _ in XCTFail("Old owner must not close after cession") })
            right = try adopt(pair, client: false, continuation: .groupAdmission(onHello: {
                XCTAssertTrue(right?.receiveEvidenceAndTransfer(expectedGroup: group, expectedFounder: pair.clientIdentity.id,
                    callbacks: rightCallbacks, onTransferred: { next in
                        right?.cancel()
                        right?.start()
                        self.channels.removeAll { $0 === right }
                        rightGroup = next
                        self.groupChannels.append(next)
                        next.start()
                        oldDestroyed()
                    }) ?? false)
            }), onComparison: { _, _ in XCTFail("No bootstrap comparison in group mode") },
            onClosed: { _ in XCTFail("Old owner must not close after cession") })
            left?.start()
            right?.start()
        }
        wait(for: [oldReleased, leftConfirmed, rightConfirmed], timeout: 10)
    }

    func testTransferredOwnerKeepsOriginalDeadlineAndOldCancelCannotRevokeIt() throws {
        let pair = try readyPair()
        let evidence = try groupEvidence(issuer: pair.clientIdentity, member: pair.serverIdentity.id)
        let transferred = expectation(description: "both owners handed over near original expiry")
        transferred.expectedFulfillmentCount = 2
        let expired = expectation(description: "both group owners expire without a new 120 second window")
        expired.expectedFulfillmentCount = 2
        let selectedAt = HandshakeV1Channel.monotonicMillis() - 117_000
        var expiryCount = 0
        try queue.sync {
            weak var left: HandshakeV1Channel?
            weak var right: HandshakeV1Channel?
            let callbacks = GroupAdmissionChannelCallbacks(onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "CONFIRMED")
            }, onComparison: { _, _ in }, onClosed: { failure in
                if case .confirmation(let reason) = failure, reason.name == "EXPIRED" || reason.name == "TRANSPORT" {
                    if reason.name == "EXPIRED" { expiryCount += 1 }
                    expired.fulfill()
                } else { XCTFail("Expected original deadline or its peer disconnect") }
            })
            func retain(_ next: GroupAdmissionChannel) {
                self.groupChannels.append(next)
                next.start()
                transferred.fulfill()
            }
            left = try adopt(pair, client: true, selectedAt: selectedAt, continuation: .groupAdmission(onHello: {
                XCTAssertTrue(left?.sendEvidenceAndTransfer(expectedGroup: String(repeating: "c", count: 64),
                    expectedFounder: pair.clientIdentity.id, evidence: evidence, callbacks: callbacks,
                    onTransferred: { next in left?.cancel(); retain(next) }) ?? false)
            }), onClosed: { _ in XCTFail("Old owner must not run its expired timer after release") })
            right = try adopt(pair, client: false, selectedAt: selectedAt, continuation: .groupAdmission(onHello: {
                XCTAssertTrue(right?.receiveEvidenceAndTransfer(expectedGroup: String(repeating: "c", count: 64),
                    expectedFounder: pair.clientIdentity.id, callbacks: callbacks,
                    onTransferred: { next in right?.cancel(); retain(next) }) ?? false)
            }), onClosed: { _ in XCTFail("Old owner must not close transferred TLS") })
            left?.start()
            right?.start()
        }
        wait(for: [transferred, expired], timeout: 8)
        queue.sync { XCTAssertGreaterThanOrEqual(expiryCount, 1) }
    }

    func testEvidenceReadRemainsOwnedAndCancellationClosesBlockedActualTLS() throws {
        try assertPendingEvidenceClosure(expire: false)
    }

    func testOriginalDeadlineClosesBlockedEvidenceReadBeforeAnyCession() throws {
        try assertPendingEvidenceClosure(expire: true)
    }

    private func assertPendingEvidenceClosure(expire: Bool) throws {
        let pair = try readyPair()
        let waiting = expectation(description: "member waiting for evidence")
        let cancelled = expectation(description: "bootstrap lifecycle interrupts evidence receive")
        let eof = expectation(description: "actual TLS peer observes closure")
        try queue.sync {
            weak var owner: HandshakeV1Channel?
            let remote = try scriptedPeer(pair, onComparison: { _, _ in }, onEOF: { _ in eof.fulfill() })
            let callbacks = GroupAdmissionChannelCallbacks(onSnapshot: { _ in XCTFail("No receiving group yet") },
                onComparison: { _, _ in XCTFail("No evidence proof") }, onClosed: { _ in XCTFail("No group owner") })
            owner = try adopt(pair, client: true,
                selectedAt: expire ? HandshakeV1Channel.monotonicMillis() - 118_000 : pair.selectedAt,
                continuation: .groupAdmission(onHello: {
                XCTAssertTrue(owner?.receiveEvidenceAndTransfer(expectedGroup: String(repeating: "c", count: 64),
                    expectedFounder: pair.serverIdentity.id, callbacks: callbacks,
                    onTransferred: { _ in XCTFail("Evidence was never sent") }) ?? false)
                waiting.fulfill()
                if !expire { self.queue.asyncAfter(deadline: .now() + .milliseconds(100)) { owner?.cancel() } }
            }), onComparison: { _, _ in XCTFail("No bootstrap comparison") }, onClosed: { failure in
                if expire {
                    if case .bootstrap(let reason) = failure { XCTAssertEqual(reason.name, "EXPIRED") }
                    else { XCTFail("Expected original deadline during evidence read") }
                } else if case .cancelled = failure {} else { XCTFail("Expected explicit cancellation during read") }
                cancelled.fulfill()
            })
            try remote.start()
            owner?.start()
        }
        wait(for: [waiting, cancelled, eof], timeout: 8)
    }

    func testEvidenceWrongRootAndWrongSendingRoleNeverTransferOrPublishComparison() throws {
        for wrongRole in [false, true] {
            let pair = try readyPair()
            let supplied = try groupEvidence(issuer: pair.serverIdentity, member: pair.clientIdentity.id)
            let rejected = expectation(description: "evidence context rejected before release")
            try queue.sync {
                weak var owner: HandshakeV1Channel?
                let remote = try scriptedPeer(pair, onComparison: { _, _ in }, onEOF: { _ in })
                let callbacks = GroupAdmissionChannelCallbacks(onSnapshot: { _ in XCTFail("No group owner") },
                    onComparison: { _, _ in XCTFail("No comparison on context mismatch") },
                    onClosed: { _ in XCTFail("Bootstrap still owns rejected evidence") })
                owner = try adopt(pair, client: true, continuation: .groupAdmission(onHello: {
                    if wrongRole {
                        XCTAssertFalse(owner?.sendEvidenceAndTransfer(expectedGroup: String(repeating: "c", count: 64),
                            expectedFounder: pair.serverIdentity.id, evidence: supplied, callbacks: callbacks,
                            onTransferred: { _ in XCTFail("Member cannot send issuer evidence") }) ?? true)
                    } else {
                        XCTAssertTrue(owner?.receiveEvidenceAndTransfer(expectedGroup: String(repeating: "d", count: 64),
                            expectedFounder: pair.serverIdentity.id, callbacks: callbacks,
                            onTransferred: { _ in XCTFail("Received root cannot replace expected root") }) ?? false)
                    }
                }), onComparison: { _, _ in XCTFail("No bootstrap comparison") }, onClosed: { failure in
                    if case .adapter = failure {} else { XCTFail("Expected sanitized context failure") }
                    rejected.fulfill()
                })
                try remote.start(tail: wrongRole ? Data() : Self.data(supplied.framedBytes()))
                owner?.start()
            }
            wait(for: [rejected], timeout: 5)
        }
    }

    func testInvalidAdmissionSignatureTransfersCleanupButNeverExposesGroupComparison() throws {
        let pair = try readyPair()
        let evidence = try groupEvidence(issuer: pair.clientIdentity, member: pair.serverIdentity.id, invalidSignature: true)
        let rejected = expectation(description: "full proof rejected by receiving owners")
        rejected.expectedFulfillmentCount = 2
        try queue.sync {
            weak var left: HandshakeV1Channel?
            weak var right: HandshakeV1Channel?
            let callbacks = GroupAdmissionChannelCallbacks(onSnapshot: { snapshot in
                XCTAssertEqual(snapshot.phase.name, "AWAITING_START")
            }, onComparison: { _, _ in XCTFail("Invalid proof must not expose UI confirmation") }, onClosed: { failure in
                if case .confirmation(let reason) = failure, reason.name == "INVALID_PROOF" || reason.name == "TRANSPORT" {
                    rejected.fulfill()
                } else { XCTFail("Expected invalid proof or resulting peer closure") }
            })
            func retain(_ next: GroupAdmissionChannel) { self.groupChannels.append(next); next.start() }
            left = try adopt(pair, client: true, continuation: .groupAdmission(onHello: {
                XCTAssertTrue(left?.sendEvidenceAndTransfer(expectedGroup: String(repeating: "c", count: 64),
                    expectedFounder: pair.clientIdentity.id, evidence: evidence, callbacks: callbacks, onTransferred: retain) ?? false)
            }), onClosed: { _ in XCTFail("Proof must be checked by new owner, not old APPROVE") })
            right = try adopt(pair, client: false, continuation: .groupAdmission(onHello: {
                XCTAssertTrue(right?.receiveEvidenceAndTransfer(expectedGroup: String(repeating: "c", count: 64),
                    expectedFounder: pair.clientIdentity.id, callbacks: callbacks, onTransferred: retain) ?? false)
            }), onClosed: { failure in
                // The issuer may reject and close before the member's final exact read completes.
                if case .transport = failure { rejected.fulfill() } else { XCTFail("Unexpected old-owner failure") }
            })
            left?.start()
            right?.start()
        }
        wait(for: [rejected], timeout: 10)
    }

    func testCoalescedEvidenceAndGroupConfirmationAreNotLostOrRoutedToBootstrap() throws {
        let pair = try readyPair()
        let evidence = try groupEvidence(issuer: pair.serverIdentity, member: pair.clientIdentity.id)
        let remoteConfirmed = expectation(description: "coalesced group confirmation consumed by new owner")
        let compared = expectation(description: "same full group comparison")
        let eof = expectation(description: "group cancellation closes TLS")
        try queue.sync {
            weak var owner: HandshakeV1Channel?
            var expectedCode: String?
            var observed = false
            let remote = try scriptedPeer(pair, onComparison: { peer, _ in
                // One OS write containing both evidence and a valid GROUP_CONFIRM.
                let confirmation = try peer.groupConfirmation(evidence: evidence, signer: pair.serverIdentity,
                    remoteCertificate: pair.clientIdentity.certificate, selectedAt: pair.selectedAt)
                expectedCode = confirmation.1
                peer.replay(Self.data(try evidence.framedBytes()) + confirmation.0)
            }, onEOF: { _ in eof.fulfill() })
            let callbacks = GroupAdmissionChannelCallbacks(onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "CONFIRMED") // No local user confirmation/write.
                if snapshot.remoteConfirmed, !observed {
                    observed = true
                    XCTAssertEqual(snapshot.phase.name, "AWAITING_CONFIRMATION")
                    remoteConfirmed.fulfill()
                }
            }, onComparison: { _, code in
                XCTAssertEqual(code, expectedCode)
                compared.fulfill()
            }, onClosed: { failure in
                if case .confirmation(let reason) = failure { XCTAssertEqual(reason.name, "CANCELLED") }
                else { XCTFail("Expected group cancellation") }
            })
            owner = try adopt(pair, client: true, continuation: .groupAdmission(onHello: {
                XCTAssertTrue(owner?.receiveEvidenceAndTransfer(expectedGroup: String(repeating: "c", count: 64),
                    expectedFounder: pair.serverIdentity.id, callbacks: callbacks, onTransferred: { next in
                        self.groupChannels.append(next)
                        owner?.cancel()
                        next.start()
                    }) ?? false)
            }), onComparison: { _, _ in XCTFail("GROUP_CONFIRM must not reach bootstrap") },
            onClosed: { _ in XCTFail("Released bootstrap must not close") })
            try remote.start()
            owner?.start()
        }
        wait(for: [compared, remoteConfirmed], timeout: 10)
        queue.sync { groupChannels.last?.cancel() }
        wait(for: [eof], timeout: 5)
    }

    func testHostileEvidenceLengthsAndMalformedPayloadCloseBootstrapBeforeCession() throws {
        let inputs: [Data] = [
            Data([0, 0, 0, 0]), Data([0, 4, 0, 1]), Data([0xff, 0xff, 0xff, 0xff]),
            Data([0, 0, 0, 1, 0xff]), Data([0, 0, 0, 2, 0x7b, 0x7d]),
        ]
        for input in inputs {
            let pair = try readyPair()
            let rejected = expectation(description: "hostile evidence closes old owner")
            let eof = expectation(description: "peer TLS closed after invalid evidence")
            try queue.sync {
                weak var owner: HandshakeV1Channel?
                let remote = try scriptedPeer(pair, onComparison: { _, _ in }, onEOF: { _ in eof.fulfill() })
                let callbacks = GroupAdmissionChannelCallbacks(onSnapshot: { _ in XCTFail("No group owner") },
                    onComparison: { _, _ in XCTFail("No evidence proof") }, onClosed: { _ in XCTFail("No receiving owner") })
                owner = try adopt(pair, client: true, continuation: .groupAdmission(onHello: {
                    XCTAssertTrue(owner?.receiveEvidenceAndTransfer(expectedGroup: String(repeating: "c", count: 64),
                        expectedFounder: pair.serverIdentity.id, callbacks: callbacks,
                        onTransferred: { _ in XCTFail("Malformed evidence cannot release TLS") }) ?? false)
                }), onComparison: { _, _ in XCTFail("No bootstrap comparison") }, onClosed: { failure in
                    if case .adapter = failure {} else { XCTFail("Expected sanitized evidence decoding failure") }
                    rejected.fulfill()
                })
                // HELLO and hostile evidence coalesced in one write, exact budgets keep decoders separate.
                try remote.start(tail: input)
                owner?.start()
            }
            wait(for: [rejected, eof], timeout: 5)
        }
    }

    func testTruncatedEvidenceEOFNeverTransfersOrPublishesConfirmation() throws {
        for prefix in [Data([0, 0, 1]), Data([0, 0, 0, 10, 0x7b])] {
            let pair = try readyPair()
            let written = expectation(description: "actual truncated evidence write completed")
            let rejected = expectation(description: "EOF revokes incomplete evidence")
            try queue.sync {
                weak var owner: HandshakeV1Channel?
                let remote = try scriptedPeer(pair, onComparison: { peer, _ in
                    peer.disconnectAfterSending(prefix) { written.fulfill() }
                }, onEOF: { _ in })
                let callbacks = GroupAdmissionChannelCallbacks(onSnapshot: { _ in XCTFail("No group owner") },
                    onComparison: { _, _ in XCTFail("Truncated evidence has no comparison") },
                    onClosed: { _ in XCTFail("No cession before EOF") })
                owner = try adopt(pair, client: true, continuation: .groupAdmission(onHello: {
                    XCTAssertTrue(owner?.receiveEvidenceAndTransfer(expectedGroup: String(repeating: "c", count: 64),
                        expectedFounder: pair.serverIdentity.id, callbacks: callbacks,
                        onTransferred: { _ in XCTFail("EOF cannot release the transport") }) ?? false)
                }), onComparison: { _, _ in XCTFail("No bootstrap comparison") }, onClosed: { failure in
                    switch failure {
                    case .adapter, .transport: break // NWConnection may report reset before decoder EOF.
                    default: XCTFail("Expected truncated frame/transport closure")
                    }
                    rejected.fulfill()
                })
                try remote.start()
                owner?.start()
            }
            wait(for: [written, rejected], timeout: 5)
        }
    }

    func testGroupBlockWhileRealSignerIsPendingClosesTLSAndIgnoresLateCompletion() throws {
        let pair = try readyPair()
        let evidence = try groupEvidence(issuer: pair.serverIdentity, member: pair.clientIdentity.id)
        let blocked = expectation(description: "group owner blocks while signature is queued")
        let eof = expectation(description: "TLS peer receives no local confirmation before block")
        let drained = expectation(description: "real signature and late callback drained")
        let cryptoQueue = DispatchQueue(label: "dev.lantern.tests.group-blocked-real-signer")
        let gate = DispatchSemaphore(value: 0)
        cryptoQueue.async { gate.wait() }
        defer { gate.signal() }
        var closedCount = 0
        try queue.sync {
            weak var owner: HandshakeV1Channel?
            weak var groupOwner: GroupAdmissionChannel?
            let remote = try scriptedPeer(pair, onComparison: { _, _ in }, onEOF: { snapshot in
                XCTAssertFalse(snapshot.remoteApproved)
                eof.fulfill()
            })
            let callbacks = GroupAdmissionChannelCallbacks(onSnapshot: { snapshot in
                XCTAssertNotEqual(snapshot.phase.name, "CONFIRMED")
            }, onComparison: { ticket, _ in
                groupOwner?.confirm(ticket)
                groupOwner?.block()
                groupOwner?.confirm(ticket) // Obsolete UI ticket cannot queue a replacement signature.
                cryptoQueue.async { self.queue.async { drained.fulfill() } }
            }, onClosed: { failure in
                closedCount += 1
                XCTAssertEqual(closedCount, 1)
                if case .confirmation(let reason) = failure { XCTAssertEqual(reason.name, "BLOCKED") }
                else { XCTFail("Expected explicit local block") }
                blocked.fulfill()
            })
            owner = try adopt(pair, client: true, signingQueue: cryptoQueue, continuation: .groupAdmission(onHello: {
                XCTAssertTrue(owner?.receiveEvidenceAndTransfer(expectedGroup: String(repeating: "c", count: 64),
                    expectedFounder: pair.serverIdentity.id, callbacks: callbacks, onTransferred: { next in
                        groupOwner = next
                        self.groupChannels.append(next)
                        owner?.cancel()
                        next.start()
                    }) ?? false)
            }), onComparison: { _, _ in XCTFail("No bootstrap APPROVE") },
            onClosed: { _ in XCTFail("Old owner cannot close receiving group") })
            try remote.start(tail: Self.data(evidence.framedBytes()))
            owner?.start()
        }
        wait(for: [blocked, eof], timeout: 5)
        gate.signal()
        wait(for: [drained], timeout: 5)
        queue.sync { XCTAssertEqual(closedCount, 1) }
    }

    func testReceivingInitializationOwnsCleanupEvenWhenEndpointBindingFails() throws {
        let pair = try readyPair()
        let evidence = try groupEvidence(issuer: pair.clientIdentity, member: pair.serverIdentity.id)
        let eof = expectation(description: "failed receiving initializer closes actual TLS")
        try queue.sync {
            // Core-only offers fixture bound to this ready TLS pair. No live OS bootstrap owner
            // or pending client receive/write exists when the receiving initializer is invoked.
            func bootstrap(local: String, remote: String, nonce: String) throws -> IosHandshakeV1 {
                try IosHandshakeV1.companion.create(
                    localIdentity: local, localNonce: String(repeating: nonce, count: 64),
                    capabilitiesJson: "{\"version\":1,\"supportedFeatures\":[\"text\"],\"requiredFeatures\":[]}",
                    authenticatedLocalIdentity: local, selectedPeerIdentity: remote, authenticatedPeerIdentity: remote,
                    selectedAtMillis: pair.selectedAt,
                    nowMillis: { KotlinLong(longLong: HandshakeV1Channel.monotonicMillis()) },
                    verifyRemoteSignature: { _, _ in KotlinBoolean(bool: false) }
                )
            }
            let core = try bootstrap(local: pair.clientIdentity.id, remote: pair.serverIdentity.id, nonce: "1")
            let remote = try bootstrap(local: pair.serverIdentity.id, remote: pair.clientIdentity.id, nonce: "2")
            XCTAssertTrue(try core.sent(ticket: try XCTUnwrap(core.start())))
            XCTAssertTrue(try core.accept(chunk: try XCTUnwrap(remote.start()).bytes))
            let offers = try XCTUnwrap(core.releaseForGroupAdmission())
            remote.cancel()
            pair.server.receive(minimumIncompleteLength: 1, maximumLength: 1) { data, _, complete, error in
                XCTAssertTrue(data?.isEmpty ?? true)
                XCTAssertTrue(complete || error != nil)
                eof.fulfill()
            }
            XCTAssertThrowsError(try GroupAdmissionChannel(
                connection: pair.client, identity: pair.clientIdentity,
                peerCertificate: pair.clientIdentity.certificate, // Deliberately not the selected peer.
                offers: offers, evidence: evidence, role: .issuer,
                expectedGroup: String(repeating: "c", count: 64), expectedFounder: pair.clientIdentity.id,
                evidenceCertificates: GroupAdmissionEvidenceCertificates.decode(evidence),
                selectedAtMillis: pair.selectedAt, queue: queue, signingQueue: .global(qos: .userInitiated),
                nowMillis: HandshakeV1Channel.monotonicMillis,
                onSnapshot: { _ in XCTFail("Invalid adoption cannot publish progress") },
                onComparison: { _, _ in XCTFail("Invalid endpoint cannot publish a comparison") },
                onClosed: { _ in XCTFail("Throwing initialization reports failure to the releasing caller") }
            ))
            core.cancel() // Old core remains terminal after failed receiving adoption.
            XCTAssertEqual(try core.snapshot().phase.name, "RELEASED_TO_GROUP")
        }
        wait(for: [eof], timeout: 5)
    }

    func testGroupBoundaryPausesBeforeCoalescedTailAndKeepsCancellationOwned() throws {
        let pair = try readyPair()
        let paused = expectation(description: "group HELLO boundary")
        let cancelled = expectation(description: "bootstrap still owns cancellation")
        try queue.sync {
            weak var owner: HandshakeV1Channel?
            var callbacks = 0
            let remote = try scriptedPeer(pair, onComparison: { _, _ in }, onEOF: { _ in })
            owner = try adopt(pair, client: true, continuation: .groupAdmission(onHello: {
                callbacks += 1
                XCTAssertEqual(callbacks, 1)
                paused.fulfill()
                owner?.start() // Reentry cannot queue another HELLO/read.
                self.queue.asyncAfter(deadline: .now() + .milliseconds(200)) { owner?.cancel() }
            }), onComparison: { _, _ in XCTFail("Group mode must not publish bootstrap comparison") },
            onClosed: { failure in
                if case .cancelled = failure {} else { XCTFail("Tail was incorrectly routed to bootstrap") }
                cancelled.fulfill()
            })
            // Invalid bootstrap tail in the same OS write: it must remain unread, not authorize anything.
            try remote.start(tail: Data([0, 0, 0, 1, 0]))
            owner?.start()
        }
        wait(for: [paused, cancelled], timeout: 5)
    }

    func testGroupBoundaryIdlePauseStillExpiresAtOriginalSelectionDeadline() throws {
        let pair = try readyPair()
        let paused = expectation(description: "paused before expiry")
        let expired = expectation(description: "original deadline closes idle pause")
        try queue.sync {
            let remote = try scriptedPeer(pair, onComparison: { _, _ in }, onEOF: { _ in })
            let owner = try adopt(pair, client: true,
                selectedAt: HandshakeV1Channel.monotonicMillis() - 119_000,
                continuation: .groupAdmission(onHello: { paused.fulfill() }),
                onComparison: { _, _ in XCTFail("No bootstrap comparison in group mode") },
                onClosed: { failure in
                    if case .bootstrap(let reason) = failure { XCTAssertEqual(reason.name, "EXPIRED") }
                    else { XCTFail("Expected original selection expiry") }
                    expired.fulfill()
                })
            try remote.start()
            owner.start()
        }
        wait(for: [paused, expired], timeout: 5)
    }

    override func tearDown() {
        queue.sync {
            groupChannels.forEach { $0.cancel() }
            groupChannels.removeAll()
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
        continuation: HandshakeV1Continuation = .approvals,
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
            continuation: continuation,
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

    private func groupEvidence(issuer: AppleIdentity, member: String, invalidSignature: Bool = false) throws -> IosGroupAdmissionEvidence {
        let group = String(repeating: "c", count: 64)
        var canonical = Data()
        // Independent fixture only; production canonical encoding/roles remain in Kotlin.
        for value in ["lantern-group-admission-1", "1", group, issuer.id, member] {
            let field = Data(value.utf8)
            canonical.append(Data("\(field.count):".utf8))
            canonical.append(field)
        }
        let signature = try (invalidSignature ? "cHJvb2Y=" : issuer.sign(canonical))
        let payload = try JSONSerialization.data(withJSONObject: [
            "version": 1, "type": "GROUP_EVIDENCE",
            "proof": ["version": 1, "anchor": ["group": group, "founder": issuer.id],
                "admissions": [["claim": ["version": 1, "group": group, "issuer": issuer.id, "member": member],
                    "signature": signature]]],
            "certificates": [["identity": issuer.id, "der": (SecCertificateCopyData(issuer.certificate) as Data).base64EncodedString()]],
        ], options: [.sortedKeys, .withoutEscapingSlashes])
        return try IosGroupAdmissionEvidence.companion.decode(payload: Self.bytes(payload))
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

        func start(tail: Data = Data()) throws {
            dispatchPrecondition(condition: .onQueue(queue))
            let hello = try XCTUnwrap(bridge.start())
            self.hello = HandshakeV1ChannelTests.data(hello.bytes)
            send(hello, tail: tail) { [weak self] in self?.receiveNext() }
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

        func groupConfirmation(
            evidence: IosGroupAdmissionEvidence, signer: AppleIdentity,
            remoteCertificate: SecCertificate, selectedAt: Int64
        ) throws -> (Data, String) {
            dispatchPrecondition(condition: .onQueue(queue))
            let context = try IosGroupAdmissionContext.companion.create(
                offers: XCTUnwrap(bridge.offersForGroupAdmission()), expectedGroup: String(repeating: "c", count: 64),
                expectedFounder: signer.id, evidence: evidence, role: .issuer
            )
            let attempt = try IosGroupAdmissionConfirmation.companion.create(
                context: context, selectedAtMillis: selectedAt,
                nowMillis: { KotlinLong(longLong: HandshakeV1Channel.monotonicMillis()) },
                verifyAdmissionSignature: { id, bytes, signature in
                    KotlinBoolean(bool: ApplePublicCertificate.verifySignature(certificate: signer.certificate,
                        expectedID: id, message: HandshakeV1ChannelTests.data(bytes), signature: signature))
                },
                verifyRemoteSignature: { bytes, signature in
                    KotlinBoolean(bool: AppleIdentity.verify(certificate: remoteCertificate,
                        message: HandshakeV1ChannelTests.data(bytes), signature: signature))
                }
            )
            XCTAssertTrue(try attempt.prepare())
            let comparison = try XCTUnwrap(attempt.comparison())
            let code = SHA256.hash(data: HandshakeV1ChannelTests.data(comparison.bytes))
                .map { String(format: "%02x", $0) }.joined()
            let sign = try XCTUnwrap(attempt.confirm(ticket: comparison))
            let signature = try signer.sign(HandshakeV1ChannelTests.data(sign.bytes))
            let write = try XCTUnwrap(attempt.signed(ticket: sign, signature: signature))
            let frame = HandshakeV1ChannelTests.data(write.bytes)
            attempt.cancel() // Fixture frame only; no fake OS acknowledgement or shared production owner.
            return (frame, code)
        }

        func send(_ ticket: IosHandshakeV1Write, tail: Data = Data(), onSent: @escaping () -> Void = {}) {
            dispatchPrecondition(condition: .onQueue(queue))
            connection.send(content: HandshakeV1ChannelTests.data(ticket.bytes) + tail, completion: .contentProcessed { [weak self] error in
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
