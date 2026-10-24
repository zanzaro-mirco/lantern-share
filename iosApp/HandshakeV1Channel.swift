import CryptoKit
import Foundation
import Network
import Security
import LanternIdentity
import LanternUI

enum HandshakeV1ChannelFailure {
    case bootstrap(IosHandshakeV1Failure)
    case transport
    case adapter
    case cancelled
}

enum HandshakeV1Continuation {
    case approvals
    // Bootstrap owns connection/deadline until the explicit evidence exchange releases it.
    case groupAdmission(onHello: () -> Void)
}

/// Owns one READY mutual-TLS connection created by the supplied AppleTLSTransport with the exact
/// explicitly selected pin. Caller must use the same serial queue for adoption and ALL methods.
/// Isolated from PairingChannel/v0; READY bootstrap progress never authorizes chat or persists trust.
final class HandshakeV1Channel {
    private let connection: NWConnection
    private let identity: AppleIdentity
    private let transport: AppleTLSTransport
    private let queue: DispatchQueue
    private let signingQueue: DispatchQueue
    private let bridge: IosHandshakeV1
    private let peerCertificate: SecCertificate
    private let selectedAtMillis: Int64
    private let nowMillis: () -> Int64
    private let onSnapshot: (IosHandshakeV1Snapshot) -> Void
    private let onComparison: (IosHandshakeV1Comparison, String) -> Void
    private let onClosed: (HandshakeV1ChannelFailure) -> Void
    private let continuation: HandshakeV1Continuation
    private var timer: DispatchSourceTimer?
    private var started = false
    private var closed = false
    private var comparisonPublished = false
    private var pausedForGroup = false
    private var exchangingEvidence = false
    private var receivePending = false
    private var writePending = false
    private var evidenceDecoder: IosGroupAdmissionEvidenceDecoder?
    private var membershipDecoder: IosGroupMembershipDecoder?
    private var sessionDecoder: IosGroupSessionDecoder?
    private var textDecoder: IosGroupTextDecoder?
    private var rosterDecoder: IosGroupRosterDecoder?

    /// Transfers connection ownership even if validation or initialization throws.
    /// TLS setup/listener ownership and the selection BEFORE TLS remain the caller's responsibility.
    init(
        connection: NWConnection,
        identity: AppleIdentity,
        transport: AppleTLSTransport,
        selectedPeerID: String,
        selectedAtMillis: Int64,
        queue: DispatchQueue,
        signingQueue: DispatchQueue = .global(qos: .userInitiated),
        nowMillis: @escaping () -> Int64 = HandshakeV1Channel.monotonicMillis,
        continuation: HandshakeV1Continuation = .approvals,
        capabilitiesJson: String = "{\"version\":1,\"supportedFeatures\":[\"text\",\"receipts\"],\"requiredFeatures\":[\"text\"]}",
        onSnapshot: @escaping (IosHandshakeV1Snapshot) -> Void,
        onComparison: @escaping (IosHandshakeV1Comparison, String) -> Void,
        onClosed: @escaping (HandshakeV1ChannelFailure) -> Void
    ) throws {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            guard case .ready = connection.state,
                  transport.localIdentityID == identity.id,
                  let certificate = transport.certificate(for: connection),
                  AppleIdentity.fingerprint(certificate) == selectedPeerID else {
                throw AdoptionError.invalidTLS
            }
            self.peerCertificate = certificate
            self.bridge = try IosHandshakeV1.companion.create(
                localIdentity: identity.id,
                localNonce: Self.randomNonce(),
                capabilitiesJson: capabilitiesJson,
                authenticatedLocalIdentity: transport.localIdentityID,
                selectedPeerIdentity: selectedPeerID,
                authenticatedPeerIdentity: AppleIdentity.fingerprint(certificate),
                selectedAtMillis: selectedAtMillis,
                nowMillis: { KotlinLong(longLong: nowMillis()) },
                verifyRemoteSignature: { bytes, signature in
                    KotlinBoolean(bool: AppleIdentity.verify(certificate: certificate, message: Self.data(bytes), signature: signature))
                }
            )
        } catch {
            connection.cancel()
            throw error
        }
        self.connection = connection
        self.identity = identity
        self.transport = transport
        self.queue = queue
        self.signingQueue = signingQueue
        self.selectedAtMillis = selectedAtMillis
        self.nowMillis = nowMillis
        self.onSnapshot = onSnapshot
        self.onComparison = onComparison
        self.onClosed = onClosed
        self.continuation = continuation
        // Deadline covers idle time even before start() and is not extended by HELLO or callbacks.
        armDeadline()
    }

    func start() {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !closed, !started else { return }
        started = true
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, !self.closed else { return }
                switch state {
                case .failed, .waiting, .cancelled: self.transportFailed()
                default: break
                }
            }
        }
        do {
            guard let hello = try bridge.start() else { _ = try observe(); return }
            send(hello, initialHello: true)
        } catch { adapterFailed() }
    }

    /// Only pass the ticket retained by UI after comparing the full code on both devices.
    func confirm(_ comparison: IosHandshakeV1Comparison) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !closed else { return }
        // Group mode never opens an APPROVE window, including reentrant UI callbacks.
        guard case .approvals = continuation else { return }
        do {
            guard let signing = try bridge.confirm(ticket: comparison) else { _ = try observe(); return }
            let identity = self.identity
            let message = Self.data(signing.bytes)
            signingQueue.async { [weak self] in
                let result = Result { try identity.sign(message) }
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    do {
                        switch result {
                        case .success(let signature):
                            if let sending = try self.bridge.signed(ticket: signing, signature: signature) {
                                self.send(sending, initialHello: false)
                            }
                        case .failure:
                            _ = try self.bridge.signingFailed(ticket: signing)
                        }
                        _ = try self.observe()
                    } catch { self.adapterFailed() }
                }
            }
        } catch { adapterFailed() }
    }

    func cancel() {
        dispatchPrecondition(condition: .onQueue(queue))
        terminate(.cancelled)
    }

    /// Public routing metadata of the HELLO verified on this exact selected TLS connection.
    func remoteSupportedFeaturesForGroup() throws -> [String]? {
        dispatchPrecondition(condition: .onQueue(queue))
        guard canExchangeEvidence else { return nil }
        return try bridge.offersForGroupAdmission()?.remoteSupportedFeatures
    }

    /// Same selected connection, timer and exclusive bootstrap owner. No APPROVE/handover.
    /// Kotlin checks negotiation/order and owns framing. Callback verifies against local storage.
    @discardableResult
    func exchangeMembership(
        _ local: IosGroupMembershipEvidence,
        onReceived: @escaping (IosGroupMembershipEvidence) throws -> Void
    ) -> Bool {
        beginMembershipExchange(local, awaitPeerClose: true, onReceived: onReceived)
    }

    /// Continuation chosen BEFORE any proof I/O. No B4 EOF reader or reusable B4 authority.
    @discardableResult
    func negotiateSession(
        membership: IosGroupMembershipEvidence, offer: IosGroupSessionOffer,
        verifyRemote: @escaping (IosGroupMembershipEvidence) throws -> Bool,
        onReceived: @escaping (IosGroupSessionOffer) throws -> Void
    ) -> Bool {
        beginSession(membership: membership, offer: offer, awaitPeerClose: true,
                     verifyRemote: verifyRemote, onReceived: onReceived)
    }

    private func beginSession(
        membership: IosGroupMembershipEvidence, offer: IosGroupSessionOffer, awaitPeerClose: Bool,
        verifyRemote: @escaping (IosGroupMembershipEvidence) throws -> Bool,
        onReceived: @escaping (IosGroupSessionOffer) throws -> Void
    ) -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        guard canExchangeEvidence else { return false }
        do {
            guard let offers = try bridge.offersForGroupAdmission(), try evidenceActive() else { return false }
            let sendsFirst = try offer.sendsFirst(offers: offers, membership: membership)
            return beginMembershipExchange(membership, awaitPeerClose: false) { [weak self] remote in
                guard let self, !self.closed else { return }
                // No session read/write until the actual TLS peer's proof has been verified.
                guard try verifyRemote(remote), try self.evidenceActive() else { self.adapterFailed(); return }
                self.sessionDecoder = IosGroupSessionDecoder()
                if sendsFirst {
                    self.sendGroupFrame(try offer.framedBytes()) { [weak self] in
                        self?.receiveSession(onReceived: onReceived)
                    }
                } else {
                    self.receiveSession { [weak self] remoteOffer in
                        guard let self else { return }
                        self.sendGroupFrame(try offer.framedBytes()) { [weak self] in
                            try onReceived(remoteOffer)
                            if awaitPeerClose, let self, !self.closed { self.receiveMembershipEnd() }
                        }
                    }
                }
            }
        } catch { adapterFailed(); return false }
    }

    /// One opt-in transfer, selected before LGM/LSN I/O. Same owner, reader and original timer.
    /// Storage/lifetime belong to the caller; the verifier receives the actual TLS certificate.
    @discardableResult
    func transferGroupText(
        membership: IosGroupMembershipEvidence, offer: IosGroupSessionOffer, sending: Bool,
        verifyRemote: @escaping (IosGroupMembershipEvidence) throws -> Bool,
        selectSession: @escaping (IosGroupSessionOffer) throws -> IosGroupTextTransfer,
        outgoing: @escaping (IosGroupTextTransfer) throws -> IosGroupTextEnvelope,
        incoming: @escaping (IosGroupTextTransfer, KotlinByteArray, SecCertificate) throws -> IosGroupTextEnvelope,
        acknowledged: @escaping (IosGroupTextTransfer, IosGroupTextEnvelope, KotlinByteArray, String) throws -> Void,
        received: @escaping (IosGroupTextEnvelope) throws -> Void
    ) -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        guard canExchangeEvidence else { return false }
        do {
            guard let offers = try bridge.offersForGroupAdmission(), try evidenceActive() else { return false }
            let first = try IosGroupTextProtocol.shared.sendsFirst(offers: offers, sending: sending)
            return beginSession(membership: membership, offer: offer, awaitPeerClose: false,
                verifyRemote: verifyRemote) { [weak self] remote in
                guard let self, try self.evidenceActive() else { return }
                let transfer = try selectSession(remote)
                try transfer.checkBinding(offers: offers, membership: membership, sending: sending)
                guard try self.evidenceActive() else { return }
                let scope = try transfer.scopeFrame()
                let afterScope: () throws -> Void = { [weak self] in
                    guard let self, try self.evidenceActive() else { return }
                    if sending {
                        let message = try outgoing(transfer)
                        guard try self.evidenceActive() else { return }
                        let digest = try Self.textDigest(message)
                        self.sendGroupFrame(try transfer.textFrame(envelope: message)) { [weak self] in
                            self?.receiveTextControl(expectedBytes: IosGroupTextProtocol.shared.acknowledgementBytes) { payload in
                                guard let self, try self.evidenceActive() else { return }
                                try acknowledged(transfer, message, payload, digest)
                                guard try self.evidenceActive() else { return }
                                self.cancel() // Sender consumed the exact ACK, not EOF as a receipt.
                            }
                        }
                    } else {
                        self.receiveTextControl(expectedBytes: 0) { [weak self] payload in
                            guard let self, try self.evidenceActive() else { return }
                            let message = try incoming(transfer, payload, self.peerCertificate)
                            guard try self.evidenceActive() else { return }
                            let digest = try Self.textDigest(message)
                            self.sendGroupFrame(try transfer.acknowledgementFrame(envelope: message, digest: digest)) { [weak self] in
                                guard let self, try self.evidenceActive() else { return }
                                try received(message) // Durable fact before EOF-only cleanup can fail.
                                if !self.closed { self.receiveMembershipEnd() }
                            }
                        }
                    }
                }
                if first {
                    self.sendGroupFrame(scope) { [weak self] in
                        self?.receiveTextControl(expectedBytes: IosGroupTextProtocol.shared.scopeBytes) { payload in
                            try transfer.checkScope(payload: payload)
                            try afterScope()
                        }
                    }
                } else {
                    self.receiveTextControl(expectedBytes: IosGroupTextProtocol.shared.scopeBytes) { [weak self] payload in
                        try transfer.checkScope(payload: payload)
                        self?.sendGroupFrame(scope, completion: afterScope)
                    }
                }
            }
        } catch { adapterFailed(); return false }
    }

    /// Opt-in LGM/LSN/LRO/LRA continuation selected before any proof I/O.
    @discardableResult
    func synchronizeRoster(
        membership: IosGroupMembershipEvidence, offer: IosGroupSessionOffer,
        verifyRemote: @escaping (IosGroupMembershipEvidence) throws -> Bool,
        propose: @escaping (IosGroupSessionOffer) throws -> IosGroupRosterSnapshot,
        merge: @escaping (KotlinByteArray, SecCertificate) throws -> IosGroupRosterSnapshot,
        completed: @escaping (IosGroupRosterSnapshot) throws -> Void
    ) -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        guard canExchangeEvidence else { return false }
        do {
            guard let offers = try bridge.offersForGroupAdmission(), try evidenceActive() else { return false }
            let first = try IosGroupRosterProtocol.shared.sendsFirst(offers: offers)
            return beginSession(membership: membership, offer: offer, awaitPeerClose: false,
                verifyRemote: verifyRemote) { [weak self] remote in
                guard let self, try self.evidenceActive() else { return }
                let local = try propose(remote)
                guard try self.evidenceActive() else { return }
                let afterSnapshot: (KotlinByteArray) throws -> Void = { [weak self] payload in
                    guard let self, try self.evidenceActive() else { return }
                    let merged = try merge(payload, self.peerCertificate)
                    guard try self.evidenceActive() else { return }
                    let digest = SHA256.hash(data: Self.data(try merged.payload())).map { String(format: "%02x", $0) }.joined()
                    let agreement = try merged.agreement(digest: digest)
                    let afterAgreement: (KotlinByteArray) throws -> Void = { [weak self] remoteAgreement in
                        guard let self, try self.evidenceActive() else { return }
                        guard Self.data(remoteAgreement) == Self.data(agreement) else { throw AdoptionError.invalidEvidence }
                        try completed(merged)
                        if !self.closed {
                            if first { self.cancel() } else { self.receiveMembershipEnd() }
                        }
                    }
                    if first {
                        self.sendGroupFrame(try IosGroupRosterProtocol.shared.frame(payload: agreement)) { [weak self] in
                            self?.receiveRosterControl(agreement: true, completion: afterAgreement)
                        }
                    } else {
                        self.receiveRosterControl(agreement: true) { [weak self] remoteAgreement in
                            guard let self, Self.data(remoteAgreement) == Self.data(agreement) else { throw AdoptionError.invalidEvidence }
                            self.sendGroupFrame(try IosGroupRosterProtocol.shared.frame(payload: agreement)) {
                                try afterAgreement(remoteAgreement)
                            }
                        }
                    }
                }
                if first {
                    self.sendGroupFrame(try local.framedBytes()) { [weak self] in
                        self?.receiveRosterControl(agreement: false, completion: afterSnapshot)
                    }
                } else {
                    self.receiveRosterControl(agreement: false) { [weak self] payload in
                        guard let self else { return }
                        self.sendGroupFrame(try local.framedBytes()) { try afterSnapshot(payload) }
                    }
                }
            }
        } catch { adapterFailed(); return false }
    }

    private func receiveRosterControl(agreement: Bool, completion: @escaping (KotlinByteArray) throws -> Void) {
        guard !closed, rosterDecoder == nil, !receivePending else { return }
        rosterDecoder = IosGroupRosterDecoder(agreement: agreement)
        receiveRosterControl(completion: completion)
    }

    private func receiveRosterControl(completion: @escaping (KotlinByteArray) throws -> Void) {
        guard !closed, !receivePending, let decoder = rosterDecoder else { return }
        do {
            guard try evidenceActive() else { return }
            let budget = Int(try decoder.nextReadBytes())
            receivePending = true
            connection.receive(minimumIncompleteLength: 1, maximumLength: budget) { [weak self] data, _, complete, error in
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    self.receivePending = false
                    do {
                        guard try self.evidenceActive() else { return }
                        if error != nil { self.transportFailed(); return }
                        var payload: KotlinByteArray?
                        if let data, !data.isEmpty {
                            let read = try decoder.accept(chunk: Self.bytes(data))
                            guard Int(read.consumedBytes) == data.count else { throw AdoptionError.invalidEvidence }
                            payload = read.payload
                        }
                        if complete {
                            if payload == nil { try decoder.finish() }
                            self.transportFailed()
                            return
                        }
                        if let payload {
                            self.rosterDecoder = nil
                            try completion(payload)
                        } else { self.receiveRosterControl(completion: completion) }
                    } catch { self.adapterFailed() }
                }
            }
        } catch { adapterFailed() }
    }

    private static func textDigest(_ message: IosGroupTextEnvelope) throws -> String {
        SHA256.hash(data: data(try message.payload())).map { String(format: "%02x", $0) }.joined()
    }

    private func receiveTextControl(expectedBytes: Int32, completion: @escaping (KotlinByteArray) throws -> Void) {
        guard !closed, textDecoder == nil, !receivePending else { return }
        textDecoder = IosGroupTextDecoder(expectedBytes: expectedBytes)
        receiveTextControl(completion: completion)
    }

    private func receiveTextControl(completion: @escaping (KotlinByteArray) throws -> Void) {
        guard !closed, !receivePending, let decoder = textDecoder else { return }
        do {
            guard try evidenceActive() else { return }
            let budget = Int(try decoder.nextReadBytes())
            receivePending = true
            connection.receive(minimumIncompleteLength: 1, maximumLength: budget) { [weak self] data, _, complete, error in
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    self.receivePending = false
                    do {
                        guard try self.evidenceActive() else { return }
                        if error != nil { self.transportFailed(); return }
                        var payload: KotlinByteArray?
                        if let data, !data.isEmpty {
                            let read = try decoder.accept(chunk: Self.bytes(data))
                            guard Int(read.consumedBytes) == data.count else { throw AdoptionError.invalidEvidence }
                            payload = read.payload
                        }
                        if complete {
                            if payload == nil { try decoder.finish() }
                            self.transportFailed()
                            return
                        }
                        if let payload {
                            self.textDecoder = nil
                            try completion(payload)
                        } else { self.receiveTextControl(completion: completion) }
                    } catch { self.adapterFailed() }
                }
            }
        } catch { adapterFailed() }
    }

    private func beginMembershipExchange(
        _ local: IosGroupMembershipEvidence, awaitPeerClose: Bool,
        onReceived: @escaping (IosGroupMembershipEvidence) throws -> Void
    ) -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        guard canExchangeEvidence else { return false }
        do {
            guard let offers = try bridge.offersForGroupAdmission(), try evidenceActive() else { return false }
            let sendsFirst = try local.sendsFirst(offers: offers)
            exchangingEvidence = true
            membershipDecoder = IosGroupMembershipDecoder()
            if sendsFirst {
                sendGroupFrame(try local.framedBytes()) { [weak self] in
                    self?.receiveMembership { remote in try onReceived(remote) }
                }
            } else {
                receiveMembership { [weak self] remote in
                    self?.sendGroupFrame(try local.framedBytes()) { [weak self] in
                        try onReceived(remote)
                        // Last writer stays alive until the first has consumed its proof and
                        // closes. No queued TLS bytes lost, no ACK/traffic/remote success inferred.
                        if awaitPeerClose, let self, !self.closed { self.receiveMembershipEnd() }
                    }
                }
            }
            return !closed
        } catch { adapterFailed(); return false }
    }

    private func sendGroupFrame(_ bytes: KotlinByteArray, completion: @escaping () throws -> Void) {
        do {
            guard try evidenceActive(), !writePending else { return }
            let content = Self.data(bytes)
            writePending = true
            connection.send(content: content, completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    self.writePending = false
                    do {
                        guard try self.evidenceActive() else { return }
                        if error != nil { self.transportFailed(); return }
                        try completion()
                    } catch { self.adapterFailed() }
                }
            })
        } catch { adapterFailed() }
    }

    private func receiveMembership(onReceived: @escaping (IosGroupMembershipEvidence) throws -> Void) {
        guard !closed, !receivePending, let decoder = membershipDecoder else { return }
        do {
            guard try evidenceActive() else { return }
            let budget = Int(try decoder.nextReadBytes())
            receivePending = true
            connection.receive(minimumIncompleteLength: 1, maximumLength: budget) { [weak self] data, _, complete, error in
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    self.receivePending = false
                    do {
                        guard try self.evidenceActive() else { return }
                        if error != nil { self.transportFailed(); return }
                        var evidence: IosGroupMembershipEvidence?
                        if let data, !data.isEmpty {
                            let read = try decoder.accept(chunk: Self.bytes(data))
                            guard Int(read.consumedBytes) == data.count else { throw AdoptionError.invalidEvidence }
                            evidence = read.evidence
                        }
                        if complete {
                            if evidence == nil { try decoder.finish() }
                            self.transportFailed()
                            return
                        }
                        if let evidence {
                            self.membershipDecoder = nil
                            try onReceived(evidence)
                        } else { self.receiveMembership(onReceived: onReceived) }
                    } catch { self.adapterFailed() }
                }
            }
        } catch { adapterFailed() }
    }

    private func receiveMembershipEnd() {
        guard !closed, !receivePending else { return }
        do {
            guard try evidenceActive() else { return }
            receivePending = true
            connection.receive(minimumIncompleteLength: 1, maximumLength: 1) { [weak self] data, _, complete, error in
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    self.receivePending = false
                    do {
                        guard try self.evidenceActive() else { return }
                        if error != nil { self.transportFailed(); return }
                        guard data?.isEmpty != false else { self.adapterFailed(); return }
                        if complete { self.transportFailed() } else { self.receiveMembershipEnd() }
                    } catch { self.adapterFailed() }
                }
            }
        } catch { adapterFailed() }
    }

    private func receiveSession(onReceived: @escaping (IosGroupSessionOffer) throws -> Void) {
        guard !closed, !receivePending, let decoder = sessionDecoder else { return }
        do {
            guard try evidenceActive() else { return }
            let budget = Int(try decoder.nextReadBytes())
            receivePending = true
            connection.receive(minimumIncompleteLength: 1, maximumLength: budget) { [weak self] data, _, complete, error in
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    self.receivePending = false
                    do {
                        guard try self.evidenceActive() else { return }
                        if error != nil { self.transportFailed(); return }
                        var offer: IosGroupSessionOffer?
                        if let data, !data.isEmpty {
                            let read = try decoder.accept(chunk: Self.bytes(data))
                            guard Int(read.consumedBytes) == data.count else { throw AdoptionError.invalidEvidence }
                            offer = read.offer
                        }
                        if complete {
                            if offer == nil { try decoder.finish() }
                            self.transportFailed()
                            return
                        }
                        if let offer {
                            self.sessionDecoder = nil
                            try onReceived(offer)
                        } else { self.receiveSession(onReceived: onReceived) }
                    } catch { self.adapterFailed() }
                }
            }
        } catch { adapterFailed() }
    }

    /// Issuer-only write. Success means exchange started, not sent, confirmed or authorized.
    @discardableResult
    func sendEvidenceAndTransfer(
        expectedGroup: String, expectedFounder: String, evidence: IosGroupAdmissionEvidence,
        callbacks: GroupAdmissionChannelCallbacks,
        onTransferred: @escaping (GroupAdmissionChannel) -> Void
    ) -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        guard canExchangeEvidence else { return false }
        do {
            guard let offers = try bridge.offersForGroupAdmission() else { _ = try observe(); return false }
            _ = try IosGroupAdmissionContext.companion.create(
                offers: offers, expectedGroup: expectedGroup, expectedFounder: expectedFounder,
                evidence: evidence, role: .issuer
            )
            let certificates = try GroupAdmissionEvidenceCertificates.decode(evidence)
            let content = Self.data(try evidence.framedBytes())
            guard try evidenceActive() else { return false }
            exchangingEvidence = true
            writePending = true
            connection.send(content: content, completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    self.writePending = false
                    if error != nil { self.transportFailed(); return }
                    self.transferEvidence(evidence, certificates: certificates, role: .issuer,
                        expectedGroup: expectedGroup, expectedFounder: expectedFounder,
                        callbacks: callbacks, onTransferred: onTransferred)
                }
            })
            return true
        } catch { adapterFailed(); return false }
    }

    /// Member-only exact reads. Bootstrap keeps cancellation/timer during the entire exchange.
    @discardableResult
    func receiveEvidenceAndTransfer(
        expectedGroup: String, expectedFounder: String, callbacks: GroupAdmissionChannelCallbacks,
        onTransferred: @escaping (GroupAdmissionChannel) -> Void
    ) -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        guard canExchangeEvidence else { return false }
        do {
            guard try evidenceActive() else { return false }
            exchangingEvidence = true
            evidenceDecoder = IosGroupAdmissionEvidenceDecoder()
            receiveEvidence { [weak self] evidence in
                guard let self, let offers = try self.bridge.offersForGroupAdmission() else { return }
                _ = try IosGroupAdmissionContext.companion.create(
                    offers: offers, expectedGroup: expectedGroup, expectedFounder: expectedFounder,
                    evidence: evidence, role: .member
                )
                let certificates = try GroupAdmissionEvidenceCertificates.decode(evidence)
                self.transferEvidence(evidence, certificates: certificates, role: .member,
                    expectedGroup: expectedGroup, expectedFounder: expectedFounder,
                    callbacks: callbacks, onTransferred: onTransferred)
            }
            return !closed
        } catch { adapterFailed(); return false }
    }

    /// New member path: the received root is a candidate, never an independently trusted anchor.
    /// Exact evidence reads and queue-atomic release preserve this socket and its original deadline.
    @discardableResult
    func receiveRootEvidenceAndTransfer(
        persistence: IosPersistence, callbacks: GroupRootAdoptionChannelCallbacks,
        onTransferred: @escaping (GroupRootAdoptionChannel) -> Void
    ) -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        guard canExchangeEvidence else { return false }
        do {
            guard try evidenceActive() else { return false }
            exchangingEvidence = true
            evidenceDecoder = IosGroupAdmissionEvidenceDecoder()
            receiveEvidence { [weak self] evidence in
                guard let self, !self.closed, !self.receivePending, !self.writePending,
                      let offers = try self.bridge.releaseForGroupAdmission() else { return }
                self.closed = true
                self.timer?.cancel()
                self.timer = nil
                self.evidenceDecoder?.cancel()
                self.evidenceDecoder = nil
                self.connection.stateUpdateHandler = nil
                do {
                    let next = try GroupRootAdoptionChannel(
                        connection: self.connection, identity: self.identity, transport: self.transport,
                        selectedPeerID: offers.remoteIdentity, offers: offers, evidence: evidence,
                        persistence: persistence, selectedAtMillis: self.selectedAtMillis,
                        queue: self.queue, signingQueue: self.signingQueue, nowMillis: self.nowMillis,
                        onSnapshot: callbacks.onSnapshot, onComparison: callbacks.onComparison, onClosed: callbacks.onClosed
                    )
                    onTransferred(next)
                } catch {
                    // Receiver has taken cleanup responsibility even if its initializer failed.
                    callbacks.onClosed(.adapter(error))
                }
            }
            return !closed
        } catch { adapterFailed(); return false }
    }

    private var canExchangeEvidence: Bool {
        !closed && pausedForGroup && !exchangingEvidence && !receivePending && !writePending
    }

    private func evidenceActive() throws -> Bool {
        guard !closed, try bridge.offersForGroupAdmission() != nil else { _ = try observe(); return false }
        return true
    }

    private func receiveEvidence(onEvidence: @escaping (IosGroupAdmissionEvidence) throws -> Void) {
        guard !closed, let decoder = evidenceDecoder else { return }
        do {
            guard try evidenceActive() else { return }
            let budget = Int(try decoder.nextReadBytes())
            receivePending = true
            connection.receive(minimumIncompleteLength: 1, maximumLength: budget) { [weak self] data, _, complete, error in
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    self.receivePending = false
                    do {
                        guard try self.evidenceActive() else { return }
                        if error != nil { self.transportFailed(); return }
                        var evidence: IosGroupAdmissionEvidence?
                        if let data, !data.isEmpty {
                            let read = try decoder.accept(chunk: Self.bytes(data))
                            guard Int(read.consumedBytes) == data.count else { throw AdoptionError.invalidEvidence }
                            evidence = read.evidence
                        }
                        // EOF revokes the attempt even when its last chunk completes the evidence.
                        if complete {
                            if evidence == nil { try decoder.finish() }
                            self.transportFailed()
                            return
                        }
                        if let evidence {
                            try onEvidence(evidence)
                        } else {
                            self.receiveEvidence(onEvidence: onEvidence)
                        }
                    } catch { self.adapterFailed() }
                }
            }
        } catch { adapterFailed() }
    }

    private func transferEvidence(
        _ evidence: IosGroupAdmissionEvidence, certificates: [String: SecCertificate], role: IosGroupAdmissionRole,
        expectedGroup: String, expectedFounder: String, callbacks: GroupAdmissionChannelCallbacks,
        onTransferred: (GroupAdmissionChannel) -> Void
    ) {
        guard !closed, exchangingEvidence, !receivePending, !writePending else { return }
        do {
            guard let fresh = try bridge.offersForGroupAdmission() else { _ = try observe(); return }
            _ = try IosGroupAdmissionContext.companion.create(
                offers: fresh, expectedGroup: expectedGroup, expectedFounder: expectedFounder, evidence: evidence, role: role
            )
            guard let offers = try bridge.releaseForGroupAdmission() else { _ = try observe(); return }
            // Queue-atomic ownership change: no old receive/write/sign is outstanding here.
            closed = true // Old owner is terminal and relinquishes cleanup, including deinit.
            timer?.cancel()
            timer = nil
            evidenceDecoder?.cancel()
            evidenceDecoder = nil
            connection.stateUpdateHandler = nil
            do {
                let next = try GroupAdmissionChannel(
                    connection: connection, identity: identity, peerCertificate: peerCertificate,
                    offers: offers, evidence: evidence, role: role,
                    expectedGroup: expectedGroup, expectedFounder: expectedFounder,
                    evidenceCertificates: certificates, selectedAtMillis: selectedAtMillis,
                    queue: queue, signingQueue: signingQueue, nowMillis: nowMillis,
                    onSnapshot: callbacks.onSnapshot, onComparison: callbacks.onComparison, onClosed: callbacks.onClosed
                )
                onTransferred(next) // Caller retains the new owner and invokes start().
            } catch {
                // Receiving initializer owns cleanup even on failure; old owner never cancels again.
                callbacks.onClosed(.adapter)
            }
        } catch { adapterFailed() }
    }

    private func send(_ ticket: IosHandshakeV1Write, initialHello: Bool) {
        writePending = true
        connection.send(content: Self.data(ticket.bytes), completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, !self.closed else { return }
                self.writePending = false
                do {
                    var accepted = false
                    if error != nil {
                        _ = try self.bridge.writeFailed(ticket: ticket)
                    } else {
                        accepted = try self.bridge.sent(ticket: ticket)
                    }
                    let active = try self.observe()
                    if accepted && initialHello && active { self.receiveNext() }
                } catch { self.adapterFailed() }
            }
        })
    }

    private func receiveNext() {
        guard !closed, !pausedForGroup else { return }
        let budget: Int
        do {
            guard let remaining = try bridge.nextReadBytes() else { _ = try observe(); return }
            budget = Int(remaining.int32Value)
        } catch { adapterFailed(); return }
        receivePending = true
        connection.receive(minimumIncompleteLength: 1, maximumLength: budget) { [weak self] data, _, complete, error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, !self.closed else { return }
                self.receivePending = false
                do {
                    if error != nil { self.transportFailed(); return }
                    if let data, !data.isEmpty { _ = try self.bridge.accept(chunk: Self.bytes(data)) }
                    if complete { try self.bridge.finish() }
                    if try self.observe() { self.receiveNext() }
                } catch { self.adapterFailed() }
            }
        }
    }

    @discardableResult
    private func observe() throws -> Bool {
        guard !closed else { return false }
        let snapshot = try bridge.snapshot()
        if snapshot.phase == .closed {
            terminate(.bootstrap(snapshot.failure))
            return false
        }
        onSnapshot(snapshot)
        guard !closed else { return false }
        if case .groupAdmission(let onHello) = continuation {
            if !pausedForGroup, snapshot.phase == .awaitingConfirmation, !snapshot.remoteApproved {
                pausedForGroup = true // No receive is outstanding; current exact-budget callback has completed.
                onHello()
            }
            return !closed && !pausedForGroup
        }
        if !comparisonPublished, let comparison = try bridge.comparison() {
            comparisonPublished = true
            let code = SHA256.hash(data: Self.data(comparison.bytes)).map { String(format: "%02x", $0) }.joined()
            onComparison(comparison, code)
        }
        return !closed
    }

    private func armDeadline() {
        guard !closed else { return }
        do {
            guard let remaining = try bridge.remainingMillis() else { _ = try observe(); return }
            let source = DispatchSource.makeTimerSource(queue: queue)
            source.schedule(deadline: .now() + .milliseconds(Int(remaining.int64Value)))
            source.setEventHandler { [weak self] in
                guard let self, !self.closed else { return }
                self.timer?.cancel()
                self.timer = nil
                self.armDeadline()
            }
            timer = source
            source.resume()
        } catch { adapterFailed() }
    }

    private func adapterFailed() {
        // Keep typed bootstrap failures without forwarding peer-controlled parser text to diagnostics.
        do {
            let snapshot = try bridge.snapshot()
            if snapshot.phase == .closed { terminate(.bootstrap(snapshot.failure)); return }
        } catch { /* Clock/adapter error is reported below, never converted into progress. */ }
        terminate(.adapter)
    }

    private func transportFailed() {
        do {
            let snapshot = try bridge.snapshot()
            if snapshot.phase == .closed { terminate(.bootstrap(snapshot.failure)); return }
            terminate(.transport)
        } catch { terminate(.adapter) }
    }

    private func terminate(_ failure: HandshakeV1ChannelFailure) {
        guard !closed else { return }
        closed = true
        bridge.cancel()
        timer?.cancel()
        timer = nil
        evidenceDecoder?.cancel()
        evidenceDecoder = nil
        membershipDecoder?.cancel()
        membershipDecoder = nil
        sessionDecoder?.cancel()
        sessionDecoder = nil
        textDecoder?.cancel()
        textDecoder = nil
        rosterDecoder?.cancel()
        rosterDecoder = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        onClosed(failure)
    }

    deinit {
        timer?.cancel()
        if !closed { connection.cancel() }
    }

    static func monotonicMillis() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000) }

    private static func randomNonce() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw AdoptionError.random(status) }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func bytes(_ data: Data) -> KotlinByteArray {
        let result = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() { result.set(index: Int32(index), value: Int8(bitPattern: byte)) }
        return result
    }

    private static func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }

    private enum AdoptionError: Error {
        case invalidTLS
        case invalidEvidence
        case random(OSStatus)
    }
}
