import CryptoKit
import Foundation
import Network
import Security
import LanternIdentity
import LanternUI

private struct DiscoveredPeer {
    let id: String
    let name: String
    let endpoint: NWEndpoint
}

private final class AllowedPeerStore {
    private let lock = NSLock()
    private var trusted = Set<String>()
    private var candidate: String?

    func replaceTrusted(_ values: [String]) {
        lock.lock(); trusted = Set(values); lock.unlock()
    }

    func select(_ value: String?) {
        lock.lock(); candidate = value; lock.unlock()
    }

    func contains(_ value: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return trusted.contains(value) || candidate == value
    }

    func values() -> Set<String> {
        lock.lock(); defer { lock.unlock() }
        var result = trusted
        if let candidate { result.insert(candidate) }
        return result
    }
}

private final class PairingChannel {
    private let connection: NWConnection
    private let identity: AppleIdentity
    private let transport: AppleTLSTransport
    private let wire = IosPairingProtocol()
    private let localNonce: String
    private let expectedPeerID: String?
    private let isAllowed: (String) -> Bool
    private let isTrusted: (String) -> Bool
    private let persistTrust: (String, String) throws -> Void
    private let onComparison: (String, String) -> Void
    private let onConnected: (String) -> Void
    private let onFailure: (String) -> Void
    private var remoteID: String?
    private var session = ""
    private var localApproved = false
    private var remoteApproval: IosPairingFrame?

    init(
        connection: NWConnection,
        identity: AppleIdentity,
        transport: AppleTLSTransport,
        expectedPeerID: String?,
        isAllowed: @escaping (String) -> Bool,
        isTrusted: @escaping (String) -> Bool,
        persistTrust: @escaping (String, String) throws -> Void,
        onComparison: @escaping (String, String) -> Void,
        onConnected: @escaping (String) -> Void,
        onFailure: @escaping (String) -> Void
    ) throws {
        self.connection = connection
        self.identity = identity
        self.transport = transport
        self.expectedPeerID = expectedPeerID
        self.isAllowed = isAllowed
        self.isTrusted = isTrusted
        self.persistTrust = persistTrust
        self.onComparison = onComparison
        self.onConnected = onConnected
        self.onFailure = onFailure
        self.localNonce = try Self.randomNonce()
    }

    func start(queue: DispatchQueue) {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                do {
                    self.send(try self.wire.hello(sender: self.identity.id, nonce: self.localNonce))
                    self.receiveNext()
                } catch { self.fail(error) }
            case .failed(let error): self.fail(error)
            default: break
            }
        }
        connection.start(queue: queue)
    }

    func confirm() {
        do {
            guard let remoteID, !session.isEmpty else { return }
            if localApproved { return }
            let bytes = try wire.approvalSigningBytes(sender: identity.id, peerId: remoteID, session: session)
            let signature = try identity.sign(Self.data(bytes))
            let approval = try wire.approval(sender: identity.id, peerId: remoteID, session: session, signature: signature)
            connection.send(content: Self.data(approval), completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                if let error {
                    self.fail(error)
                    return
                }
                do {
                    self.localApproved = true
                    try self.finishPairing()
                } catch { self.fail(error) }
            })
        } catch { fail(error) }
    }

    func cancel() {
        connection.stateUpdateHandler = nil
        connection.cancel()
    }

    private func receiveNext() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_540) { [weak self] data, _, complete, error in
            guard let self else { return }
            do {
                if let error { throw error }
                if let data, !data.isEmpty {
                    for frame in try self.wire.accept(chunk: Self.bytes(data)) {
                        try self.receive(frame)
                    }
                }
                if complete { throw PairingError.channelClosed }
                self.receiveNext()
            } catch { self.fail(error) }
        }
    }

    private func receive(_ frame: IosPairingFrame) throws {
        if remoteID == nil {
            guard frame.type == "HELLO", frame.sender != identity.id,
                  expectedPeerID == nil || expectedPeerID == frame.sender,
                  isAllowed(frame.sender),
                  transport.certificate(forPeerID: frame.sender) != nil else {
                throw PairingError.unexpectedPeer
            }
            remoteID = frame.sender
            let transcript = try wire.transcript(
                localId: identity.id,
                localNonce: localNonce,
                remoteId: frame.sender,
                remoteNonce: frame.nonce
            )
            session = SHA256.hash(data: Data(transcript.utf8)).map { String(format: "%02x", $0) }.joined()
            if isTrusted(frame.sender) {
                onConnected(frame.sender)
            } else {
                onComparison(frame.sender, try wire.displayCode(session: session))
            }
            return
        }

        guard frame.sender == remoteID else { throw PairingError.unexpectedPeer }
        switch frame.type {
        case "APPROVE":
            guard !isTrusted(frame.sender), frame.session == session, frame.body == identity.id,
                  let certificate = transport.certificate(forPeerID: frame.sender),
                  AppleIdentity.verify(
                    certificate: certificate,
                    message: Self.data(try wire.approvalSigningBytes(sender: frame.sender, peerId: identity.id, session: session)),
                    signature: frame.signature
                  ) else { throw PairingError.invalidApproval }
            remoteApproval = frame
            try finishPairing()
        case "HELLO": throw PairingError.duplicateHello
        default: throw PairingError.unsupportedFrame
        }
    }

    private func finishPairing() throws {
        guard localApproved, let approval = remoteApproval, let remoteID else { return }
        try persistTrust(remoteID, approval.json)
        onConnected(remoteID)
    }

    private func send(_ bytes: KotlinByteArray) {
        connection.send(content: Self.data(bytes), completion: .contentProcessed { [weak self] error in
            if let error { self?.fail(error) }
        })
    }

    private func fail(_ error: Error) {
        cancel()
        onFailure(error.localizedDescription)
    }

    private static func randomNonce() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw PairingError.random(status) }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func bytes(_ data: Data) -> KotlinByteArray {
        let result = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() {
            result.set(index: Int32(index), value: Int8(bitPattern: byte))
        }
        return result
    }

    private static func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }
}

private enum PairingError: Error, LocalizedError {
    case random(OSStatus)
    case channelClosed
    case unexpectedPeer
    case invalidApproval
    case duplicateHello
    case unsupportedFrame

    var errorDescription: String? {
        switch self {
        case .random(let status): return "Generazione nonce non riuscita (\(status))."
        case .channelClosed: return "Canale chiuso dal dispositivo remoto."
        case .unexpectedPeer: return "Identità TLS e HELLO non corrispondono."
        case .invalidApproval: return "Conferma remota non valida."
        case .duplicateHello: return "HELLO duplicato."
        case .unsupportedFrame: return "Frame non consentito prima dell'associazione."
        }
    }
}

final class BonjourProbe: ObservableObject {
    let state = IosProbeState()
    private let queue = DispatchQueue(label: "dev.lantern.poc.ios-service")
    private let allowedPeers = AllowedPeerStore()
    private var browser: NWBrowser?
    private var listener: NWListener?
    private var channel: PairingChannel?
    private var identity: AppleIdentity?
    private var transport: AppleTLSTransport?
    private var persistence: IosPersistence?
    private var peers: [String: DiscoveredPeer] = [:]
    private var trusted = Set<String>()
    private var pairingGeneration = 0
    private var deviceName = ""

    init() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in self?.openStores() }
    }

    deinit {
        stopResources()
        persistence?.close()
    }

    func rename(_ value: String) {
        queue.async { [weak self] in
            guard let self, let persistence = self.persistence else { return }
            do {
                try persistence.rename(value: value)
                self.deviceName = value
                if let identity = self.identity, self.listener != nil {
                    self.listener?.service = self.service(for: identity)
                }
                self.onMain { self.state.updateDeviceName(value: value) }
            } catch { self.reportPersistence(error) }
        }
    }

    func start() {
        queue.async { [weak self] in self?.startResources() }
    }

    func stop() {
        queue.async { [weak self] in
            self?.stopResources()
            self?.onMain {
                self?.state.updateDevices(values: [])
                self?.state.updatePairing(peerId: "", code: "")
                self?.state.updateStatus(value: "Servizio LAN arrestato")
            }
        }
    }

    func pair(_ peerID: String) {
        queue.async { [weak self] in
            guard let self, let peer = self.peers[peerID], let identity = self.identity,
                  let transport = self.transport, !self.trusted.contains(peerID) else { return }
            self.channel?.cancel()
            self.channel = nil
            self.allowedPeers.select(peerID)
            self.pairingGeneration += 1
            let generation = self.pairingGeneration
            self.onMain {
                self.state.updatePairing(peerId: peerID, code: "")
                self.state.updateStatus(value: "Seleziona questo dispositivo anche sull'altro schermo (120 s)")
            }
            if identity.id < peerID {
                do {
                    let connection = try transport.connect(endpoint: peer.endpoint, expectedPeerID: peerID)
                    try self.openChannel(connection, expectedPeerID: peerID)
                } catch { self.failChannel(error.localizedDescription) }
            }
            self.queue.asyncAfter(deadline: .now() + 120) { [weak self] in
                guard let self, self.pairingGeneration == generation, !self.trusted.contains(peerID) else { return }
                self.failChannel("Associazione scaduta")
            }
        }
    }

    func confirm() {
        queue.async { [weak self] in self?.channel?.confirm() }
    }

    func reject() {
        queue.async { [weak self] in
            self?.channel?.cancel()
            self?.channel = nil
            self?.allowedPeers.select(nil)
            self?.pairingGeneration += 1
            self?.onMain { self?.state.updatePairing(peerId: "", code: "") }
        }
    }

    private func openStores() {
        let identityResult = Result { try AppleIdentityStore().open() }
        let persistenceResult: Result<(IosPersistence, String, [String]), Error> = Result {
            let directory = try FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
            ).appendingPathComponent("Lantern", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let persistence = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
            do { return (persistence, try persistence.name(), persistence.trusted()) }
            catch { persistence.close(); throw error }
        }
        queue.async { [weak self] in
            guard let self else {
                if case .success(let (persistence, _, _)) = persistenceResult { persistence.close() }
                return
            }
            switch identityResult {
            case .success(let identity):
                self.identity = identity
                self.transport = AppleTLSTransport(identity: identity)
                self.onMain { self.state.updateIdentity(value: identity.id) }
            case .failure(let error):
                self.onMain { self.state.updateIdentityError(value: error.localizedDescription) }
            }
            switch persistenceResult {
            case .success(let (persistence, name, trusted)):
                self.persistence = persistence
                self.deviceName = name
                self.trusted = Set(trusted)
                self.allowedPeers.replaceTrusted(trusted)
                self.onMain {
                    self.state.updateDeviceName(value: name)
                    self.state.updateTrusted(values: trusted)
                }
            case .failure(let error): self.reportPersistence(error)
            }
        }
    }

    private func startResources() {
        guard browser == nil, listener == nil, let identity, let transport, persistence != nil else { return }
        do {
            let listener = try transport.listen { [allowedPeers] in allowedPeers.values() }
            listener.service = service(for: identity)
            listener.newConnectionHandler = { [weak self] connection in
                guard let self else { connection.cancel(); return }
                do { try self.openChannel(connection, expectedPeerID: nil) }
                catch { connection.cancel(); self.failChannel(error.localizedDescription) }
            }
            listener.stateUpdateHandler = { [weak self] value in self?.reportNetwork("Listener", value) }
            self.listener = listener
            listener.start(queue: queue)

            let parameters = NWParameters.tcp
            parameters.includePeerToPeer = false
            let browser = NWBrowser(for: .bonjour(type: "_lantern._tcp", domain: "local."), using: parameters)
            browser.stateUpdateHandler = { [weak self] value in self?.reportNetwork("Bonjour", value) }
            browser.browseResultsChangedHandler = { [weak self] results, _ in self?.updatePeers(results) }
            self.browser = browser
            browser.start(queue: queue)
        } catch { failChannel(error.localizedDescription) }
    }

    private func stopResources() {
        channel?.cancel(); channel = nil
        browser?.cancel(); browser = nil
        listener?.cancel(); listener = nil
        peers.removeAll()
        allowedPeers.select(nil)
        pairingGeneration += 1
    }

    private func service(for identity: AppleIdentity) -> NWListener.Service {
        NWListener.Service(
            name: "lantern-\(identity.id.prefix(16))",
            type: "_lantern._tcp",
            txtRecord: NWTXTRecord(["id": identity.id, "name": deviceName, "v": "0"])
        )
    }

    private func updatePeers(_ results: Set<NWBrowser.Result>) {
        guard let localID = identity?.id else { return }
        var current: [String: DiscoveredPeer] = [:]
        for result in results {
            guard case .bonjour(let record) = result.metadata,
                  let id = record["id"], id != localID, id.count == 64,
                  id.allSatisfy({ "0123456789abcdef".contains($0) }), record["v"] == "0" else { continue }
            current[id] = DiscoveredPeer(id: id, name: record["name"] ?? "Lantern", endpoint: result.endpoint)
        }
        peers = current
        let visible = current.values.sorted { $0.name < $1.name }.map { IosPeer(id: $0.id, name: $0.name) }
        onMain { self.state.updateDevices(values: visible) }
        reconnectTrustedPeers()
    }

    private func reconnectTrustedPeers() {
        guard channel == nil, let identity, let transport else { return }
        guard let peer = peers.values.first(where: { trusted.contains($0.id) && identity.id < $0.id }) else { return }
        do {
            let connection = try transport.connect(endpoint: peer.endpoint, expectedPeerID: peer.id)
            try openChannel(connection, expectedPeerID: peer.id)
        } catch { failChannel(error.localizedDescription) }
    }

    private func openChannel(_ connection: NWConnection, expectedPeerID: String?) throws {
        guard channel == nil, let identity, let transport, let persistence else {
            connection.cancel()
            return
        }
        let channel = try PairingChannel(
            connection: connection,
            identity: identity,
            transport: transport,
            expectedPeerID: expectedPeerID,
            isAllowed: { [allowedPeers] in allowedPeers.contains($0) },
            isTrusted: { [weak self] in self?.trusted.contains($0) == true },
            persistTrust: { [weak self] peerID, admission in
                try persistence.trust(id: peerID, admission: admission)
                self?.trusted.insert(peerID)
                self?.allowedPeers.replaceTrusted(Array(self?.trusted ?? Set<String>()))
            },
            onComparison: { [weak self] peerID, code in
                self?.onMain {
                    self?.state.updatePairing(peerId: peerID, code: code)
                    self?.state.updateStatus(value: "Confronta TUTTO il codice, poi conferma su entrambi")
                }
            },
            onConnected: { [weak self] peerID in self?.paired(peerID) },
            onFailure: { [weak self] message in self?.failChannel(message) }
        )
        self.channel = channel
        channel.start(queue: queue)
    }

    private func paired(_ peerID: String) {
        allowedPeers.select(nil)
        pairingGeneration += 1
        let values = trusted.sorted()
        onMain {
            self.state.updateTrusted(values: values)
            self.state.updatePairing(peerId: "", code: "")
            self.state.updateStatus(value: "TLS 1.3 autenticato · associazione persistita")
        }
    }

    private func failChannel(_ message: String) {
        channel?.cancel(); channel = nil
        allowedPeers.select(nil)
        pairingGeneration += 1
        onMain {
            self.state.updatePairing(peerId: "", code: "")
            self.state.updateStatus(value: "Canale chiuso: \(message)")
        }
    }

    private func reportNetwork(_ prefix: String, _ state: Any) {
        onMain { self.state.updateStatus(value: "\(prefix): \(state)") }
    }

    private func reportPersistence(_ error: Error) {
        onMain { self.state.updatePersistenceError(value: error.localizedDescription) }
    }

    private func onMain(_ operation: @escaping () -> Void) {
        DispatchQueue.main.async(execute: operation)
    }
}
