import Foundation
import Network
import Security
import LanternIdentity
import LanternUI

/// One explicit service selection, never a v0 fallback or automatic recovery of consent.
/// All methods and callbacks use the Bonjour service's serial, non-UI queue. The caller keeps
/// SQLite alive until whenClosedAndDrained, including signatures/receives after cancellation.
final class GroupAdmissionSession {
    private let identity: AppleIdentity
    private let persistence: IosPersistence
    private let transport: AppleTLSTransport
    private let selection: IosGroupAdmissionSelection
    private let presentation: IosGroupAdmissionController
    private let endpoint: NWEndpoint
    private let queue: DispatchQueue
    private let selectedAt = HandshakeV1Channel.monotonicMillis()
    private let onMembershipChanged: () -> Void
    private let onPrepared: () -> Void
    private let sessionMemory: IosGroupSessionMemory
    private var sessionOffer: IosGroupSessionOffer?
    private var anchor: IosLocalGroupAnchor?
    private var membership: IosGroupAdoptionJournalSnapshot?
    private var replacing: IosGroupAdoptionJournalSnapshot?
    private var pendingTLS: NWConnection?
    private var bootstrap: HandshakeV1Channel?
    private var issuer: GroupAdmissionChannel?
    private var root: GroupRootAdoptionChannel?
    private var comparison: IosGroupAdmissionComparison?
    private var displayed: IosGroupAdmissionDisplayTicket?
    private var timer: DispatchSourceTimer?
    private var claimed = false
    private var ended = false
    private var issuerConfirmed = false
    private var membershipVerified = false
    private var sessionSelected = false
    private var committing = false
    private var drained = false
    private var drainCallbacks: [() -> Void] = []

    init(identity: AppleIdentity, persistence: IosPersistence, transport: AppleTLSTransport,
         selection: IosGroupAdmissionSelection, presentation: IosGroupAdmissionController,
         endpoint: NWEndpoint, queue: DispatchQueue, sessionMemory: IosGroupSessionMemory = IosGroupSessionMemory(),
         onPrepared: @escaping () -> Void = {}, onMembershipChanged: @escaping () -> Void) {
        dispatchPrecondition(condition: .onQueue(queue))
        self.identity = identity
        self.persistence = persistence
        self.transport = transport
        self.selection = selection
        self.presentation = presentation
        self.endpoint = endpoint
        self.queue = queue
        self.onMembershipChanged = onMembershipChanged
        self.onPrepared = onPrepared
        self.sessionMemory = sessionMemory
    }

    func start() {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !ended, timer == nil else { return }
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + .milliseconds(Int(max(0, 120_000 - elapsed))))
        source.setEventHandler { [weak self] in self?.fail(.failed) }
        timer = source
        source.resume()
        do {
            anchor = try persistence.localGroup()
            membership = try persistence.committedGroupAdoption()
            if selection.mode != .admission {
                guard let anchor else { fail(.unavailable); return }
                _ = try GroupMembership.prepare(identity: identity, persistence: persistence)
                guard try membershipUnchanged() else { fail(.unavailable); return }
                if selection.mode == .session {
                    sessionOffer = try sessionMemory.propose(groupId: anchor.groupId, founderId: anchor.founderId,
                        marker: membership, newSessionId: Self.randomSessionID())
                }
            } else if let old = try persistence.pendingGroupAdoption() {
                guard selection.replaceInterrupted else { fail(.interrupted); return }
                guard anchor == nil, old.localIdentity == identity.id else { fail(.unavailable); return }
                replacing = old // Exact snapshot; no startup cleanup or deletion before fresh consent.
            }
            guard live else { return }
            onPrepared() // Service enables only this selection's pin after the preflight.
            connectIfInitiator()
        } catch { fail(.unavailable) }
    }

    func accept(_ connection: NWConnection) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard live, !claimed, pendingTLS == nil, selection.peerId < identity.id else { connection.cancel(); return }
        openTLS(connection)
    }

    func confirm(_ ticket: IosGroupAdmissionDisplayTicket) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard selection.mode == .admission, live, displayed === ticket, ticket.selection === selection, let comparison else { return }
        self.comparison = nil // One displayed click, never a replay to another owner.
        do {
            if anchor != nil {
                guard try membershipUnchanged() else { fail(.failed); return }
                issuer?.confirm(comparison)
            } else { root?.confirm(comparison) }
        } catch { fail(.failed) }
    }

    func cancel() {
        dispatchPrecondition(condition: .onQueue(queue))
        retire()
    }

    func whenClosedAndDrained(_ completion: @escaping () -> Void) {
        dispatchPrecondition(condition: .onQueue(queue))
        if drained { completion() } else { drainCallbacks.append(completion) }
    }

    private var elapsed: Int64 { HandshakeV1Channel.monotonicMillis() - selectedAt }
    private var live: Bool { !ended && elapsed >= 0 && elapsed < 120_000 }

    private func connectIfInitiator() {
        guard live, !claimed, pendingTLS == nil, identity.id < selection.peerId else { return }
        do { openTLS(try transport.connect(endpoint: endpoint, expectedPeerID: selection.peerId)) }
        catch { retryTLS() }
    }

    private func retryTLS() {
        // Only pre-HELLO connectivity retry, within this selection's original window.
        queue.asyncAfter(deadline: .now() + .milliseconds(500)) { [weak self] in self?.connectIfInitiator() }
    }

    private func openTLS(_ connection: NWConnection) {
        pendingTLS = connection
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection, self.pendingTLS === connection, !self.ended else { return }
            switch state {
            case .ready:
                guard self.live else { self.fail(.failed); return }
                self.claimed = true
                self.pendingTLS = nil
                connection.stateUpdateHandler = nil
                self.openBootstrap(connection)
            case .waiting, .failed, .cancelled:
                self.pendingTLS = nil
                connection.stateUpdateHandler = nil
                connection.cancel()
                self.retryTLS()
            default: break
            }
        }
        connection.start(queue: queue)
    }

    private func openBootstrap(_ connection: NWConnection) {
        do {
            let role = anchor == nil ? "group-candidate" : "group-issuer"
            let feature = IosLocalGroupMembership.shared.feature
            let capabilities: String
            switch selection.mode {
            case .membershipCheck:
                capabilities = "{\"version\":1,\"supportedFeatures\":[\"\(feature)\"],\"requiredFeatures\":[\"\(feature)\"]}"
            case .session:
                let sessionFeature = sessionMemory.feature
                capabilities = "{\"version\":1,\"supportedFeatures\":[\"\(feature)\",\"\(sessionFeature)\"],\"requiredFeatures\":[\"\(feature)\",\"\(sessionFeature)\"]}"
            default:
                capabilities = "{\"version\":1,\"supportedFeatures\":[\"group-admission\",\"\(role)\"],\"requiredFeatures\":[\"group-admission\"]}"
            }
            let owner = try HandshakeV1Channel(
                connection: connection, identity: identity, transport: transport,
                selectedPeerID: selection.peerId, selectedAtMillis: selectedAt, queue: queue,
                continuation: .groupAdmission(onHello: { [weak self] in
                    guard let self else { return }
                    if self.selection.mode != .admission { self.exchangeMembership() }
                    else { self.exchangeEvidence() }
                }),
                capabilitiesJson: capabilities,
                onSnapshot: { _ in }, onComparison: { _, _ in },
                onClosed: { [weak self] _ in self?.fail(.failed) }
            )
            bootstrap = owner
            owner.start()
        } catch { fail(.failed) }
    }

    private func exchangeMembership() {
        guard live, let bootstrap else { return }
        do {
            guard try membershipUnchanged() else { fail(.failed); return }
            let local = try GroupMembership.prepare(identity: identity, persistence: persistence)
            guard live, try membershipUnchanged() else { fail(.failed); return }
            if selection.mode == .session {
                guard let sessionOffer else { fail(.failed); return }
                guard bootstrap.negotiateSession(membership: local, offer: sessionOffer,
                    verifyRemote: { [weak self] remote in
                        guard let self, self.live, let anchor = self.anchor else { return false }
                        return try self.membershipUnchanged() &&
                            GroupMembership.verify(remote, anchor: anchor, peerID: self.selection.peerId) &&
                            self.live && self.membershipUnchanged()
                    }, onReceived: { [weak self] remote in
                        guard let self, self.live, let anchor = self.anchor else { return }
                        guard try self.membershipUnchanged(), self.live else { self.fail(.failed); return }
                        // No OS/DB/callback inside select: serialized with cancel/stop on this queue.
                        let result = try self.sessionMemory.select(local: sessionOffer, remote: remote,
                            groupId: anchor.groupId, founderId: anchor.founderId, marker: self.membership)
                        self.sessionSelected = true
                        self.presentation.sessionSelected(value: self.selection, result: result)
                        if self.identity.id < self.selection.peerId { self.retire() }
                    }) else { fail(.failed); return }
                return
            }
            guard bootstrap.exchangeMembership(local, onReceived: { [weak self] remote in
                guard let self, self.live, let anchor = self.anchor else { return }
                guard try self.membershipUnchanged(),
                      try GroupMembership.verify(remote, anchor: anchor, peerID: self.selection.peerId),
                      self.live, try self.membershipUnchanged() else { self.fail(.failed); return }
                self.membershipVerified = true
                self.presentation.membershipVerified(value: self.selection, groupId: anchor.groupId)
                if self.identity.id < self.selection.peerId { self.retire() }
            }) else { fail(.failed); return }
        } catch { fail(.failed) }
    }

    private func exchangeEvidence() {
        guard live, let bootstrap else { return }
        do {
            let features = try bootstrap.remoteSupportedFeaturesForGroup() ?? []
            let localRole = anchor == nil ? "group-candidate" : "group-issuer"
            let remoteRole = anchor == nil ? "group-issuer" : "group-candidate"
            guard features.contains("group-admission"), features.contains(remoteRole), !features.contains(localRole) else {
                fail(.failed); return
            }
            if let anchor {
                guard try membershipUnchanged() else { fail(.failed); return }
                let evidence = try LocalGroupAdmission.prepare(identity: identity, persistence: persistence, memberID: selection.peerId)
                guard live, try membershipUnchanged() else { fail(.failed); return }
                let callbacks = GroupAdmissionChannelCallbacks(
                    onSnapshot: { [weak self] snapshot in
                        guard let self, !self.ended, snapshot.phase == .confirmed else { return }
                        self.issuerConfirmed = true
                        self.presentation.completed(value: self.selection, groupId: anchor.groupId, adoptedLocally: false)
                    },
                    onComparison: { [weak self] ticket, code in self?.show(ticket, code: code, groupID: anchor.groupId) },
                    onClosed: { [weak self] _ in self?.fail(.failed) }
                )
                guard bootstrap.sendEvidenceAndTransfer(expectedGroup: anchor.groupId, expectedFounder: anchor.founderId,
                    evidence: evidence, callbacks: callbacks, onTransferred: { [weak self] owner in
                        guard let self, self.live else { owner.cancel(); return }
                        self.bootstrap = nil
                        self.issuer = owner
                        owner.start()
                    }) else { fail(.failed); return }
            } else {
                let callbacks = GroupRootAdoptionChannelCallbacks(
                    onSnapshot: { [weak self] snapshot in self?.rootSnapshot(snapshot) },
                    onComparison: { [weak self] ticket, code in
                        guard let self, let owner = self.root else { return }
                        self.show(ticket, code: code, groupID: owner.candidateGroupID)
                    },
                    onClosed: { [weak self] _ in
                        guard let self, !self.committing else { return }
                        self.fail(.failed)
                    }
                )
                guard bootstrap.receiveRootEvidenceAndTransfer(persistence: persistence, callbacks: callbacks,
                    onTransferred: { [weak self] owner in
                        guard let self, self.live else { owner.cancel(); return }
                        self.bootstrap = nil
                        self.root = owner
                        owner.start(currentIdentity: self.identity)
                    }) else { fail(.failed); return }
            }
        } catch { fail(.failed) }
    }

    private func show(_ ticket: IosGroupAdmissionComparison, code: String, groupID: String) {
        guard live else { return }
        comparison = ticket
        displayed = presentation.comparing(value: selection, issuer: anchor != nil, groupId: groupID, code: code)
    }

    private func membershipUnchanged() throws -> Bool {
        let current = try persistence.localGroup()
        guard current?.groupId == anchor?.groupId, current?.founderId == anchor?.founderId else { return false }
        let committed = try persistence.committedGroupAdoption()
        if let membership { return committed.map { membership.sameRecord(other: $0) } ?? false }
        return committed == nil
    }

    private func rootSnapshot(_ snapshot: IosGroupRootSnapshot) {
        guard !ended else { return }
        if snapshot.phase == .confirmed {
            // Handover/commit must run OUTSIDE receive/sign/write/UI callbacks, same queue/owner.
            queue.async { [weak self] in self?.commitRoot() }
        }
    }

    private func commitRoot() {
        guard live, !committing, let root else { return }
        committing = true
        defer { committing = false }
        var commitStarted = false
        do {
            guard try root.handover(currentIdentity: identity) != nil else { fail(.failed); return }
            // Crossing this queue-serialized point permits the local SQLite transaction to finish.
            defer {
                presentation.membershipChanged()
                onMembershipChanged() // Read-only, including unknown results and dismissed UI.
            }
            commitStarted = true
            if try root.commitLocal(currentIdentity: identity, replacingInterrupted: replacing) {
                presentation.completed(value: selection, groupId: root.candidateGroupID, adoptedLocally: true)
                retire()
            } else { fail(.failed) }
        } catch {
            var failure: IosGroupServiceFailure = commitStarted ? .commitOutcomeUnknown : .failed
            do {
                failure = try root.snapshot().phase == .commitOutcomeUnknown ? .commitOutcomeUnknown : .failed
            } catch {
                // If even the terminal read fails after entering commit, do not claim rollback.
                // Keep the conservative outcome above; do not attempt another write.
            }
            presentation.failed(value: selection, reason: failure)
            retire() // No replay; actual durable state is read separately.
        }
    }

    private func fail(_ failure: IosGroupServiceFailure) {
        guard !ended else { return }
        if !issuerConfirmed && !membershipVerified && !sessionSelected { presentation.failed(value: selection, reason: failure) }
        retire()
    }

    private func retire() {
        guard !ended else { return }
        ended = true
        comparison = nil
        displayed = nil
        sessionOffer = nil
        timer?.cancel()
        timer = nil
        pendingTLS?.stateUpdateHandler = nil
        pendingTLS?.cancel()
        pendingTLS = nil
        bootstrap?.cancel()
        bootstrap = nil
        issuer?.cancel()
        issuer = nil
        if let root {
            root.cancel()
            root.whenClosedAndDrained { [self] in
                self.root = nil
                finishDrain()
            }
        } else { finishDrain() }
    }

    private func finishDrain() {
        guard !drained else { return }
        drained = true
        let callbacks = drainCallbacks
        drainCallbacks.removeAll()
        callbacks.forEach { $0() }
    }

    private static func randomSessionID() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw SessionRandomError.unavailable
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private enum SessionRandomError: Error { case unavailable }
}
