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

/// Owns one READY mutual-TLS connection created by the supplied AppleTLSTransport with the exact
/// explicitly selected pin. Caller must use the same serial queue for adoption and ALL methods.
/// Isolated from PairingChannel/v0; READY bootstrap progress never authorizes chat or persists trust.
final class HandshakeV1Channel {
    private let connection: NWConnection
    private let identity: AppleIdentity
    private let queue: DispatchQueue
    private let signingQueue: DispatchQueue
    private let bridge: IosHandshakeV1
    private let onSnapshot: (IosHandshakeV1Snapshot) -> Void
    private let onComparison: (IosHandshakeV1Comparison, String) -> Void
    private let onClosed: (HandshakeV1ChannelFailure) -> Void
    private var timer: DispatchSourceTimer?
    private var started = false
    private var closed = false
    private var comparisonPublished = false

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
            self.bridge = try IosHandshakeV1.companion.create(
                localIdentity: identity.id,
                localNonce: Self.randomNonce(),
                capabilitiesJson: "{\"version\":1,\"supportedFeatures\":[\"text\",\"receipts\"],\"requiredFeatures\":[\"text\"]}",
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
        self.queue = queue
        self.signingQueue = signingQueue
        self.onSnapshot = onSnapshot
        self.onComparison = onComparison
        self.onClosed = onClosed
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

    private func send(_ ticket: IosHandshakeV1Write, initialHello: Bool) {
        connection.send(content: Self.data(ticket.bytes), completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, !self.closed else { return }
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
        guard !closed else { return }
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
        if snapshot.phase == .closed {
            terminate(.bootstrap(snapshot.failure))
            return false
        }
        onSnapshot(snapshot)
        guard !closed else { return false }
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
        connection.stateUpdateHandler = nil
        connection.cancel()
        onClosed(failure)
    }

    deinit {
        timer?.cancel()
        connection.cancel()
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
        case random(OSStatus)
    }
}
