import CryptoKit
import Foundation
import Network
import Security
import LanternIdentity
import LanternUI

enum GroupAdmissionChannelFailure {
    case confirmation(IosGroupAdmissionFailure)
    case adapter
}

struct GroupAdmissionChannelCallbacks {
    let onSnapshot: (IosGroupAdmissionSnapshot) -> Void
    let onComparison: (IosGroupAdmissionComparison, String) -> Void
    let onClosed: (GroupAdmissionChannelFailure) -> Void
}

/// Exclusive owner after bootstrap release. Same serial queue, TLS endpoints and selection clock.
/// CONFIRMED is revocable and never writes trust, adopts a root or enables application messages.
final class GroupAdmissionChannel {
    private let connection: NWConnection
    private let identity: AppleIdentity
    private let queue: DispatchQueue
    private let signingQueue: DispatchQueue
    private let bridge: IosGroupAdmissionConfirmation
    private let onSnapshot: (IosGroupAdmissionSnapshot) -> Void
    private let onComparison: (IosGroupAdmissionComparison, String) -> Void
    private let onClosed: (GroupAdmissionChannelFailure) -> Void
    private var timer: DispatchSourceTimer?
    private var started = false
    private var closed = false
    private var comparisonPublished = false

    /// Takes ownership even when construction fails. Called only by the releasing bootstrap owner.
    init(
        connection: NWConnection, identity: AppleIdentity, peerCertificate: SecCertificate,
        offers: IosHandshakeV1Offers, evidence: IosGroupAdmissionEvidence,
        role: IosGroupAdmissionRole, expectedGroup: String, expectedFounder: String,
        evidenceCertificates: [String: SecCertificate],
        selectedAtMillis: Int64, queue: DispatchQueue, signingQueue: DispatchQueue,
        nowMillis: @escaping () -> Int64,
        onSnapshot: @escaping (IosGroupAdmissionSnapshot) -> Void,
        onComparison: @escaping (IosGroupAdmissionComparison, String) -> Void,
        onClosed: @escaping (GroupAdmissionChannelFailure) -> Void
    ) throws {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            guard case .ready = connection.state else { throw PublicCertificateError.invalid }
            let context = try IosGroupAdmissionContext.companion.create(
                offers: offers, expectedGroup: expectedGroup, expectedFounder: expectedFounder,
                evidence: evidence, role: role
            )
            // Actual TLS endpoint certificates take precedence over all received entries.
            var certificates = evidenceCertificates
            certificates[identity.id] = identity.certificate
            let peerID = AppleIdentity.fingerprint(peerCertificate)
            certificates[peerID] = peerCertificate
            let boundCertificates = certificates
            guard offers.localIdentity == identity.id, offers.remoteIdentity == peerID,
                (context.issuerIdentity == identity.id && context.memberIdentity == peerID)
                || (context.memberIdentity == identity.id && context.issuerIdentity == peerID) else {
                throw PublicCertificateError.invalid
            }
            self.bridge = try IosGroupAdmissionConfirmation.companion.create(
                context: context, selectedAtMillis: selectedAtMillis,
                nowMillis: { KotlinLong(longLong: nowMillis()) },
                verifyAdmissionSignature: { issuer, bytes, signature in
                    guard let certificate = boundCertificates[issuer] else { return KotlinBoolean(bool: false) }
                    return KotlinBoolean(bool: ApplePublicCertificate.verifySignature(
                        certificate: certificate, expectedID: issuer,
                        message: Self.data(bytes), signature: signature
                    ))
                },
                verifyRemoteSignature: { bytes, signature in
                    KotlinBoolean(bool: ApplePublicCertificate.verifySignature(
                        certificate: peerCertificate, expectedID: peerID,
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
        self.queue = queue
        self.signingQueue = signingQueue
        self.onSnapshot = onSnapshot
        self.onComparison = onComparison
        self.onClosed = onClosed
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
            let prepared = try bridge.prepare()
            if try observe(), prepared { receiveNext() }
        } catch { adapterFailed() }
    }

    func confirm(_ comparison: IosGroupAdmissionComparison) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !closed else { return }
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
                                self.send(sending)
                            }
                        case .failure: _ = try self.bridge.signingFailed(ticket: signing)
                        }
                        _ = try self.observe()
                    } catch { self.adapterFailed() }
                }
            }
        } catch { adapterFailed() }
    }

    func cancel() { lifecycle { bridge.cancel() } }
    func block() { lifecycle { bridge.block() } }
    func leaveGroup() { lifecycle { bridge.leaveGroup() } }

    private func lifecycle(_ event: () -> Void) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !closed else { return }
        event()
        do { _ = try observe() } catch { adapterFailed() }
    }

    private func send(_ ticket: IosGroupAdmissionWrite) {
        connection.send(content: Self.data(ticket.bytes), completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, !self.closed else { return }
                do {
                    if error != nil { _ = try self.bridge.writeFailed(ticket: ticket) }
                    else { _ = try self.bridge.sent(ticket: ticket) }
                    _ = try self.observe()
                } catch { self.adapterFailed() }
            }
        })
    }

    private func receiveNext() {
        guard !closed else { return }
        do { guard try observe() else { return } } catch { adapterFailed(); return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: Int(bridge.maximumChunkBytes)) { [weak self] data, _, complete, error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, !self.closed else { return }
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
        if snapshot.phase == .closed { terminate(.confirmation(snapshot.failure)); return false }
        onSnapshot(snapshot)
        guard !closed else { return false }
        if !comparisonPublished, let ticket = try bridge.comparison() {
            comparisonPublished = true
            let code = SHA256.hash(data: Self.data(ticket.bytes)).map { String(format: "%02x", $0) }.joined()
            onComparison(ticket, code)
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

    private func transportFailed() {
        do {
            // Preserve an expiry/clock failure already reached before the network callback.
            if try bridge.snapshot().phase != .closed { bridge.transportFailed() }
            _ = try observe()
        } catch { adapterFailed() }
    }

    private func adapterFailed() {
        do {
            let snapshot = try bridge.snapshot()
            if snapshot.phase == .closed { terminate(.confirmation(snapshot.failure)); return }
        } catch { /* Unexpected adapter failures are reported without peer parser text. */ }
        terminate(.adapter)
    }

    private func terminate(_ failure: GroupAdmissionChannelFailure) {
        guard !closed else { return }
        closed = true
        bridge.cancel()
        timer?.cancel()
        timer = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        onClosed(failure)
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
