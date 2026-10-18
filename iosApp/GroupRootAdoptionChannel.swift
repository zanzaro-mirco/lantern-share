import CryptoKit
import Foundation
import Network
import Security
import LanternIdentity
import LanternUI

enum GroupRootAdoptionChannelFailure {
    case root(IosGroupRootFailure, cause: Error?)
    case adapter(Error)
}

/// Preserve both failures without logging peer-controlled parser text or losing cleanup errors.
struct GroupRootAdoptionFailureContext: Error {
    let primary: GroupRootAdoptionChannelFailure
    let secondary: Error
}

/// Exclusive owner of the selected member's ready mutual-TLS connection and its continuation.
/// Caller retires ALL previous socket readers/writers/timers before adopting on the same queue.
/// Confirmed and handover remain revocable, never membership or permission to send messages.
/// A separate successful local commit retires transport; it still does not authorize traffic.
final class GroupRootAdoptionChannel {
    private let connection: NWConnection
    private let identity: AppleIdentity
    private let persistence: IosPersistence
    private let queue: DispatchQueue
    private let signingQueue: DispatchQueue
    private let bridge: IosGroupRootAdoption
    private let boundEvidence: IosGroupAdmissionEvidence
    private let memberCertificateDer: String
    private let onSnapshot: (IosGroupRootSnapshot) -> Void
    private let onComparison: (IosGroupAdmissionComparison, String) -> Void
    private let onClosed: (GroupRootAdoptionChannelFailure) -> Void
    private var timer: DispatchSourceTimer?
    private var started = false
    private var closed = false
    private var comparisonPublished = false
    private var handedOver = false
    private var handingOver = false
    private var committing = false
    private var callbacksInProgress = 0
    private var pendingOperations = 0
    private var pendingSignaturesAndWrites = 0
    private var drainCallbacks: [() -> Void] = []

    /// Takes socket ownership even on failure, but never closes the caller's database.
    /// Offers must have been verified on THIS connection; its bootstrap owner must be retired.
    /// Persistence stays open until cancellation and all pending work has drained on the queue.
    init(
        connection: NWConnection, identity: AppleIdentity, transport: AppleTLSTransport,
        selectedPeerID: String, offers: IosHandshakeV1Offers, evidence: IosGroupAdmissionEvidence,
        persistence: IosPersistence, selectedAtMillis: Int64, queue: DispatchQueue,
        signingQueue: DispatchQueue = .global(qos: .userInitiated),
        nowMillis: @escaping () -> Int64 = HandshakeV1Channel.monotonicMillis,
        onSnapshot: @escaping (IosGroupRootSnapshot) -> Void,
        onComparison: @escaping (IosGroupAdmissionComparison, String) -> Void,
        onClosed: @escaping (GroupRootAdoptionChannelFailure) -> Void
    ) throws {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            guard case .ready = connection.state,
                  transport.localIdentityID == identity.id,
                  let peerCertificate = transport.certificate(for: connection),
                  AppleIdentity.fingerprint(peerCertificate) == selectedPeerID,
                  offers.localIdentity == identity.id, offers.remoteIdentity == selectedPeerID else {
                throw PublicCertificateError.invalid
            }
            // Bind before decoding received endpoint DER: only the actual TLS DER can win.
            let endpointEvidence = try evidence.withIssuerCertificate(
                identity: selectedPeerID,
                der: (SecCertificateCopyData(peerCertificate) as Data).base64EncodedString()
            )
            // All other issuers still require strict OS decoding and exact pin checks.
            var certificates = try GroupAdmissionEvidenceCertificates.decode(endpointEvidence)
            // Actual TLS endpoint certificates always win over received endpoint evidence.
            certificates[identity.id] = identity.certificate
            certificates[selectedPeerID] = peerCertificate
            let boundCertificates = certificates
            self.boundEvidence = endpointEvidence
            self.memberCertificateDer = (SecCertificateCopyData(identity.certificate) as Data).base64EncodedString()
            self.bridge = try IosGroupRootAdoption.companion.create(
                offers: offers, evidence: endpointEvidence, authenticatedLocalIdentity: transport.localIdentityID,
                selectedPeerIdentity: selectedPeerID, authenticatedPeerIdentity: AppleIdentity.fingerprint(peerCertificate),
                selectedAtMillis: selectedAtMillis, nowMillis: { KotlinLong(longLong: nowMillis()) },
                verifyAdmissionSignature: { issuer, bytes, signature in
                    guard let certificate = boundCertificates[issuer] else { return KotlinBoolean(bool: false) }
                    return KotlinBoolean(bool: ApplePublicCertificate.verifySignature(
                        certificate: certificate, expectedID: issuer, message: Self.data(bytes), signature: signature
                    ))
                },
                verifyRemoteSignature: { bytes, signature in
                    KotlinBoolean(bool: ApplePublicCertificate.verifySignature(
                        certificate: peerCertificate, expectedID: selectedPeerID,
                        message: Self.data(bytes), signature: signature
                    ))
                }
            )
        } catch {
            connection.cancel()
            throw error
        }
        self.connection = connection
        self.identity = identity
        self.persistence = persistence
        self.queue = queue
        self.signingQueue = signingQueue
        self.onSnapshot = onSnapshot
        self.onComparison = onComparison
        self.onClosed = onClosed
        armDeadline() // Original selection budget, including idle time before start().
    }

    /// Identity is checked at start and handover; other identity/group changes must cancel us.
    func start(currentIdentity: AppleIdentity) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !closed, !started else { return }
        started = true
        guard transportIsReady() else { return }
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, !self.closed else { return }
                switch state {
                case .failed(let cause), .waiting(let cause): self.transportFailed(cause)
                case .cancelled: self.transportFailed()
                default: break
                }
            }
        }
        do {
            let prepared = try bridge.prepare(currentIdentityId: currentIdentity.id, persistence: persistence)
            if try observe(), prepared { receiveNext() }
        } catch { adapterFailed(error) }
    }

    /// Only the exact retained comparison ticket, after explicit comparison of the full digest.
    func confirm(_ comparison: IosGroupAdmissionComparison) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !closed else { return }
        do {
            guard let signing = try bridge.confirm(ticket: comparison) else { _ = try observe(); return }
            guard try observe() else { return } // Reentrant UI cancellation must precede OS work.
            let identity = self.identity
            let message = Self.data(signing.bytes)
            pendingOperations += 1
            pendingSignaturesAndWrites += 1
            signingQueue.async { [weak self] in
                let result = Result { try identity.sign(message) }
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self else { return }
                    self.callbacksInProgress += 1
                    defer { self.completeOperation(signingOrWrite: true) }
                    guard !self.closed else { return }
                    do {
                        switch result {
                        case .success(let signature):
                            if let write = try self.bridge.signed(ticket: signing, signature: signature) {
                                self.send(write)
                            }
                        case .failure(let cause):
                            _ = try self.bridge.signingFailed(ticket: signing)
                            _ = try self.observe(cause: cause)
                        }
                        _ = try self.observe()
                    } catch { self.adapterFailed(error) }
                }
            }
        } catch { adapterFailed(error) }
    }

    func cancel() { lifecycle { try bridge.cancel() } }
    func block() { lifecycle { try bridge.block() } }
    func leaveGroup() { lifecycle { try bridge.leaveGroup() } }

    /// Call on the serial queue, outside callbacks (enqueue from onSnapshot).
    /// A pending receive is phase-neutral: the SAME owner delivers it to the current bridge,
    /// which rejects every post-handover byte and still observes EOF. No reader is replaced.
    /// Null means not ready/retired; errors close this owner and preserve their original cause.
    func handover(currentIdentity: AppleIdentity) throws -> IosGroupAdoptionJournalSnapshot? {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !closed, started, !handedOver, !handingOver,
              callbacksInProgress == 0, pendingSignaturesAndWrites == 0 else { return nil }
        handingOver = true
        defer { handingOver = false }
        do {
            guard transportIsReady() else { return nil }
            guard try bridge.snapshot().phase == .confirmed else { _ = try observe(); return nil }
            var nonce = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce) == errSecSuccess else {
                throw IdentityError.cryptography
            }
            let snapshot = try bridge.handover(
                currentIdentityId: currentIdentity.id, persistence: persistence,
                attemptId: nonce.map { String(format: "%02x", $0) }.joined(),
                boundEvidence: boundEvidence, memberCertificateDer: memberCertificateDer
            )
            if snapshot != nil { handedOver = true }
            guard try observe() else { return nil }
            return snapshot
        } catch {
            adapterFailed(error)
            throw error
        }
    }

    /// Policy A: local atomic commit, not an acknowledgement from the issuer.
    /// Invoke outside callbacks on this same non-UI queue with a fresh OS identity.
    /// Pending phase-neutral receive is cancelled only AFTER the durable commit succeeds.
    func commitLocal(currentIdentity: AppleIdentity, replacingInterrupted: IosGroupAdoptionJournalSnapshot? = nil) throws -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !closed, handedOver, !handingOver, !committing,
              callbacksInProgress == 0, pendingSignaturesAndWrites == 0 else { return false }
        committing = true
        defer { committing = false }
        do {
            guard transportIsReady() else { return false }
            let committed: Bool
            if let replacingInterrupted {
                committed = try bridge.retryLocalCommit(currentIdentityId: currentIdentity.id,
                    persistence: persistence, replacingInterrupted: replacingInterrupted)
            } else {
                committed = try bridge.commitLocal(currentIdentityId: currentIdentity.id, persistence: persistence)
            }
            if committed {
                // Retire transport without turning a durable success into a cancellation error.
                closed = true
                timer?.cancel()
                timer = nil
                connection.stateUpdateHandler = nil
                connection.cancel()
                callbacksInProgress += 1
                defer {
                    callbacksInProgress -= 1
                    notifyDrained()
                }
                onSnapshot(try bridge.snapshot())
            } else { _ = try observe() }
            return committed
        } catch {
            adapterFailed(error)
            throw error
        }
    }

    /// Caller retains this owner and the database until close AND all OS work has returned.
    /// onClosed alone is deliberately not a drain notification (a signature may still run).
    func whenClosedAndDrained(_ completion: @escaping () -> Void) {
        dispatchPrecondition(condition: .onQueue(queue))
        drainCallbacks.append(completion)
        notifyDrained()
    }

    private func lifecycle(_ event: () throws -> Void) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !closed else { return }
        do {
            try event()
            _ = try observe()
        } catch { adapterFailed(error) }
    }

    private func send(_ ticket: IosGroupRootWrite) {
        do { guard try observe() else { return } } catch { adapterFailed(error); return }
        pendingOperations += 1
        pendingSignaturesAndWrites += 1
        connection.send(content: Self.data(ticket.bytes), completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self else { return }
                self.callbacksInProgress += 1
                defer { self.completeOperation(signingOrWrite: true) }
                guard !self.closed else { return }
                do {
                    if let error {
                        _ = try self.bridge.writeFailed(ticket: ticket)
                        _ = try self.observe(cause: error)
                    } else {
                        _ = try self.bridge.sent(ticket: ticket)
                        _ = try self.observe()
                    }
                } catch { self.adapterFailed(error) }
            }
        })
    }

    private func receiveNext() {
        do { guard try observe() else { return } } catch { adapterFailed(error); return }
        pendingOperations += 1
        connection.receive(minimumIncompleteLength: 1, maximumLength: Int(bridge.maximumChunkBytes)) { [weak self] data, _, complete, error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self else { return }
                self.callbacksInProgress += 1
                defer { self.completeOperation(signingOrWrite: false) }
                guard !self.closed else { return }
                do {
                    if let error { self.transportFailed(error); return }
                    if let data, !data.isEmpty { _ = try self.bridge.accept(chunk: Self.bytes(data)) }
                    if complete { try self.bridge.finish() }
                    if try self.observe() { self.receiveNext() }
                } catch { self.adapterFailed(error) }
            }
        }
    }

    @discardableResult
    private func observe(cause: Error? = nil) throws -> Bool {
        guard !closed else { return false }
        callbacksInProgress += 1
        defer {
            callbacksInProgress -= 1
            notifyDrained()
        }
        let snapshot = try bridge.snapshot()
        if snapshot.phase == .closed { terminate(.root(snapshot.failure, cause: cause)); return false }
        onSnapshot(snapshot)
        guard !closed else { return false }
        if !comparisonPublished, let ticket = try bridge.comparison() {
            comparisonPublished = true
            let code = SHA256.hash(data: Self.data(ticket.bytes)).map { String(format: "%02x", $0) }.joined()
            onComparison(ticket, code)
        }
        guard !closed else { return false }
        // User callbacks can consume the remaining budget even without a lifecycle event.
        let current = try bridge.snapshot()
        if current.phase == .closed { terminate(.root(current.failure, cause: cause)); return false }
        return true
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
        } catch { adapterFailed(error) }
    }

    private func transportIsReady() -> Bool {
        switch connection.state {
        case .ready: return true
        case .failed(let cause), .waiting(let cause): transportFailed(cause)
        default: transportFailed()
        }
        return false
    }

    private func transportFailed(_ cause: Error? = nil) {
        do {
            // Do not overwrite an already reached timeout, clock or lifecycle failure.
            if try bridge.snapshot().phase != .closed { try bridge.transportFailed() }
            _ = try observe(cause: cause)
        } catch { adapterFailed(error) }
    }

    private func adapterFailed(_ cause: Error) {
        do {
            let snapshot = try bridge.snapshot()
            if snapshot.phase == .closed { terminate(.root(snapshot.failure, cause: cause)); return }
        } catch {
            terminate(.adapter(GroupRootAdoptionFailureContext(primary: .adapter(cause), secondary: error)))
            return
        }
        terminate(.adapter(cause))
    }

    private func terminate(_ failure: GroupRootAdoptionChannelFailure) {
        guard !closed else { return }
        closed = true
        callbacksInProgress += 1
        defer {
            callbacksInProgress -= 1
            notifyDrained()
        }
        // A failing core callback must never prevent timer/socket cleanup or disappear.
        var terminalFailure = failure
        do { try bridge.cancel() } catch {
            terminalFailure = .adapter(GroupRootAdoptionFailureContext(primary: failure, secondary: error))
        }
        timer?.cancel()
        timer = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        onClosed(terminalFailure)
    }

    private func completeOperation(signingOrWrite: Bool) {
        callbacksInProgress -= 1
        pendingOperations -= 1
        if signingOrWrite { pendingSignaturesAndWrites -= 1 }
        notifyDrained()
    }

    private func notifyDrained() {
        guard closed, pendingOperations == 0, callbacksInProgress == 0 else { return }
        let callbacks = drainCallbacks
        drainCallbacks.removeAll()
        callbacks.forEach { $0() }
    }

    deinit {
        timer?.cancel()
        if !closed { connection.cancel() }
    }

    private static func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }

    private static func bytes(_ data: Data) -> KotlinByteArray {
        let result = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() { result.set(index: Int32(index), value: Int8(bitPattern: byte)) }
        return result
    }
}
