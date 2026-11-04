import Foundation
import XCTest
import LanternUI
import LanternIdentity
import Security
@testable import Lantern

final class LocalGroupControllerTests: XCTestCase {
    func testConcurrentRefreshCannotHideExitFailureAndOnlyExplicitReloadRecovers() throws {
        let namespace = "dev.lantern.exit-refresh-race.\(UUID().uuidString)"
        defer { removeIdentity(namespace) }
        let identity = try AppleIdentityStore(namespace: namespace).open()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { store.close() }
        let owner = try LocalGroupFoundation(identity: identity)
        let ticket = try XCTUnwrap(owner.prepare(persistence: store))
        _ = try owner.commit(ticket: ticket, currentIdentity: identity, persistence: store)
        let queue = DispatchQueue(label: "dev.lantern.exit-refresh-race", attributes: .concurrent)

        for iteration in 0..<2_000 {
            let race = ConcurrentRefreshState()
            let controller = IosLocalGroupController(requestCreate: { XCTFail("automatic creation") },
                requestReload: { race.recordReload() })
            controller.leaveHandler = {}
            try controller.loaded(identityId: identity.id, persistence: store)
            controller.requestExit()
            let readers = DispatchGroup()
            let ready = DispatchSemaphore(value: 0)
            for _ in 0..<2 {
                readers.enter()
                queue.async {
                    defer { readers.leave() }
                    controller.refreshMembership()
                    ready.signal()
                    while !race.isStopped { controller.refreshMembership() }
                }
            }
            let firstReady = ready.wait(timeout: .now() + 5) == .success
            let secondReady = ready.wait(timeout: .now() + 5) == .success
            if firstReady && secondReady { controller.exitFailed() }
            race.stop()
            let drained = readers.wait(timeout: .now() + 5) == .success
            defer { controller.close() }
            guard firstReady && secondReady && drained else {
                XCTFail("refresh workers failed to start or drain at iteration \(iteration)")
                return
            }
            let phase = controller.snapshot().phase.name
            let reloads = race.reloadCount
            XCTAssertEqual(phase, "FAILED", "iteration \(iteration)")
            XCTAssertEqual(reloads, 0, "automatic reload at iteration \(iteration)")
            guard phase == "FAILED", reloads == 0 else { return }
            controller.refreshMembership()
            XCTAssertEqual(race.reloadCount, 0)
            controller.reload()
            XCTAssertEqual(race.reloadCount, 1)
            try controller.loaded(identityId: identity.id, persistence: store)
            XCTAssertEqual(controller.snapshot().phase.name, "FOUNDED")
            controller.close()
            controller.refreshMembership()
            XCTAssertEqual(race.reloadCount, 1)
            XCTAssertEqual(controller.snapshot().phase.name, "CLOSED")
        }
        XCTAssertNotNil(try store.localGroup())
    }

    func testRefreshReloadCallbackCanCompleteOnAnotherQueueWithoutHoldingGate() throws {
        let namespace = "dev.lantern.refresh-callback.\(UUID().uuidString)"
        defer { removeIdentity(namespace) }
        let identity = try AppleIdentityStore(namespace: namespace).open()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { store.close() }
        let owner = try LocalGroupFoundation(identity: identity)
        let ticket = try XCTUnwrap(owner.prepare(persistence: store))
        _ = try owner.commit(ticket: ticket, currentIdentity: identity, persistence: store)
        let queue = DispatchQueue(label: "dev.lantern.refresh-callback")
        let completed = DispatchSemaphore(value: 0)
        let work = DispatchGroup()
        weak var pendingController: IosLocalGroupController?
        let controller = IosLocalGroupController(requestCreate: {}, requestReload: {
            work.enter()
            queue.async {
                defer { completed.signal(); work.leave() }
                guard let controller = pendingController else { XCTFail("owner released"); return }
                do { try controller.loaded(identityId: identity.id, persistence: store) }
                catch { XCTFail("\(error)") }
            }
            // If the caller holds the gate while invoking us, the other queue cannot
            // finish loaded()/drainRefresh(). The bounded wait exposes that deadlock.
            XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
        })
        pendingController = controller
        defer {
            controller.close()
            XCTAssertEqual(work.wait(timeout: .now() + 5), .success)
        }
        try controller.loaded(identityId: identity.id, persistence: store)
        controller.refreshMembership()
        XCTAssertEqual(work.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(controller.snapshot().phase.name, "FOUNDED")
        XCTAssertNotNil(try store.localGroup())
    }

    func testExplicitExitReservesOnceRemovesFoundationAndSurvivesReopen() throws {
        let namespace = "dev.lantern.exit-tests.\(UUID().uuidString)"
        defer { removeIdentity(namespace) }
        let identity = try AppleIdentityStore(namespace: namespace).open()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { store.close() }
        let owner = try LocalGroupFoundation(identity: identity)
        let ticket = try XCTUnwrap(owner.prepare(persistence: store))
        _ = try owner.commit(ticket: ticket, currentIdentity: identity, persistence: store)
        let controller = IosLocalGroupController(requestCreate: {}, requestReload: {})
        try controller.loaded(identityId: identity.id, persistence: store)
        controller.requestExit() // No installed owner must never pretend to have left.
        XCTAssertEqual(controller.snapshot().phase.name, "FOUNDED")
        var exits = 0
        controller.leaveHandler = { exits += 1 }
        controller.requestExit()
        for _ in 0..<10 { controller.requestExit(); controller.create(); controller.reload(); controller.refreshMembership() }
        XCTAssertEqual(exits, 1)
        XCTAssertEqual(controller.snapshot().phase.name, "LEAVING")
        // The real service drains native owners before this synchronous Kotlin transaction.
        try controller.finishExit(identityId: identity.id, persistence: store)
        XCTAssertEqual(controller.snapshot().phase.name, "EMPTY")
        XCTAssertNil(try store.localGroup())
        XCTAssertNil(try store.pendingGroupAdoption())
        XCTAssertNil(try store.committedGroupAdoption())
        try controller.finishExit(identityId: identity.id, persistence: store) // No replay.
        let reopened = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { reopened.close() }
        let recovered = IosLocalGroupController(requestCreate: { XCTFail("automatic creation") }, requestReload: {})
        try recovered.loaded(identityId: identity.id, persistence: reopened)
        XCTAssertEqual(recovered.snapshot().phase.name, "EMPTY")
        controller.close(); recovered.close()
    }

    func testExitFailureRequiresExplicitReloadAndClosedControllerIgnoresCompletion() throws {
        let namespace = "dev.lantern.exit-failure-tests.\(UUID().uuidString)"
        defer { removeIdentity(namespace) }
        let identity = try AppleIdentityStore(namespace: namespace).open()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { store.close() }
        let owner = try LocalGroupFoundation(identity: identity)
        let ticket = try XCTUnwrap(owner.prepare(persistence: store))
        _ = try owner.commit(ticket: ticket, currentIdentity: identity, persistence: store)
        var reloads = 0
        let controller = IosLocalGroupController(requestCreate: {}, requestReload: { reloads += 1 })
        controller.leaveHandler = {}
        try controller.loaded(identityId: identity.id, persistence: store)
        controller.requestExit()
        controller.exitFailed()
        controller.refreshMembership()
        XCTAssertEqual(reloads, 0)
        XCTAssertEqual(controller.snapshot().phase.name, "FAILED")
        controller.reload()
        XCTAssertEqual(reloads, 1)
        try controller.loaded(identityId: identity.id, persistence: store)
        XCTAssertEqual(controller.snapshot().phase.name, "FOUNDED")
        controller.requestExit()
        controller.close()
        try controller.finishExit(identityId: identity.id, persistence: store)
        XCTAssertEqual(controller.snapshot().phase.name, "CLOSED")
        XCTAssertNotNil(try store.localGroup())
    }
    private final class ConcurrentRefreshState {
        private let lock = NSLock()
        private var stopped = false
        private var reloads = 0
        var isStopped: Bool {
            lock.lock(); defer { lock.unlock() }
            return stopped
        }
        var reloadCount: Int {
            lock.lock(); defer { lock.unlock() }
            return reloads
        }
        func stop() {
            lock.lock(); defer { lock.unlock() }
            stopped = true
        }
        func recordReload() {
            lock.lock(); defer { lock.unlock() }
            reloads += 1
        }
    }

    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("lantern-group-ui-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }

    func testOpeningIsReadOnlyAndRepeatedClicksReserveOnlyOneCreation() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { store.close() }
        var creates = 0
        var reloads = 0
        let controller = IosLocalGroupController(requestCreate: { creates += 1 }, requestReload: { reloads += 1 })
        controller.create()
        XCTAssertEqual(creates, 0)
        try controller.loaded(identityId: String(repeating: "a", count: 64), persistence: store)
        XCTAssertEqual(controller.snapshot().phase.name, "EMPTY")
        XCTAssertNil(try store.localGroup())
        for _ in 0..<20 { controller.create(); controller.reload() }
        XCTAssertEqual(creates, 1)
        XCTAssertEqual(reloads, 0)
        XCTAssertTrue(controller.hasPendingCreation())
        controller.createFailed()
        for _ in 0..<20 { controller.create() }
        XCTAssertEqual(creates, 1)
        controller.reload()
        controller.reload()
        XCTAssertEqual(reloads, 1)
        try controller.loaded(identityId: String(repeating: "a", count: 64), persistence: store)
        XCTAssertEqual(controller.snapshot().phase.name, "EMPTY")
        XCTAssertNil(try store.localGroup())
        controller.close()
    }

    func testClosePreventsQueuedCallbacksAndNoLongerReadsClosedDatabase() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        let controller = IosLocalGroupController(requestCreate: { XCTFail("closed") }, requestReload: { XCTFail("closed") })
        controller.close()
        store.close()
        try controller.loaded(identityId: String(repeating: "a", count: 64), persistence: store)
        try controller.created(identityId: String(repeating: "a", count: 64), persistence: store)
        try controller.loadedVerified(identityId: String(repeating: "a", count: 64), persistence: store,
            verifyCertificateSignature: { _, _, _ in XCTFail("closed verifier"); return nil })
        try controller.createdVerified(identityId: String(repeating: "a", count: 64), persistence: store,
            verifyCertificateSignature: { _, _, _ in XCTFail("closed verifier"); return nil })
        controller.loadFailed()
        controller.createFailed()
        controller.create()
        controller.reload()
        XCTAssertEqual(controller.snapshot().phase.name, "CLOSED")
        XCTAssertFalse(controller.hasPendingCreation())
    }

    func testMissingRootAfterHandoffFailsWithoutReturningToEmpty() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { store.close() }
        let controller = IosLocalGroupController(requestCreate: {}, requestReload: {})
        let id = String(repeating: "a", count: 64)
        try controller.loaded(identityId: id, persistence: store)
        controller.create()
        XCTAssertThrowsError(try controller.created(identityId: id, persistence: store))
        controller.createFailed()
        XCTAssertEqual(controller.snapshot().phase.name, "FAILED")
        XCTAssertEqual(controller.snapshot().failure, "STORAGE")
        controller.close()
    }

    func testInvalidIdentityCannotOfferCreationWhenStorageIsEmpty() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { store.close() }
        for id in ["", "invalid", String(repeating: "A", count: 64)] {
            let controller = IosLocalGroupController(requestCreate: { XCTFail("invalid identity") }, requestReload: {})
            try controller.loaded(identityId: id, persistence: store)
            controller.create()
            XCTAssertEqual(controller.snapshot().failure, "IDENTITY_MISMATCH")
            controller.close()
        }
    }

    func testRealQueuedFoundationAndUncertainAcknowledgementRecoverWithoutReplay() throws {
        let namespace = "dev.lantern.group-ui-tests.\(UUID().uuidString)"
        defer { removeIdentity(namespace) }
        let identity = try AppleIdentityStore(namespace: namespace).open()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { store.close() }
        let queue = DispatchQueue(label: "dev.lantern.tests.group-ui")
        let completed = expectation(description: "commit completed")
        weak var pendingController: IosLocalGroupController?
        let controller = IosLocalGroupController(requestCreate: {
            queue.async {
                guard let controller = pendingController else { XCTFail("owner released"); completed.fulfill(); return }
                do {
                    let owner = try LocalGroupFoundation(identity: identity)
                    let ticket = try XCTUnwrap(owner.prepare(persistence: store))
                    _ = try owner.commit(ticket: ticket, currentIdentity: identity, persistence: store)
                    // Simulate lost acknowledgement after real SQLite committed, never replay.
                    controller.createFailed()
                } catch { XCTFail("\(error)") }
                completed.fulfill()
            }
        }, requestReload: {})
        pendingController = controller
        try controller.loaded(identityId: identity.id, persistence: store)
        controller.create()
        wait(for: [completed], timeout: 5)
        XCTAssertEqual(controller.snapshot().phase.name, "FAILED")
        let saved = try XCTUnwrap(store.localGroup())
        controller.reload()
        try controller.loaded(identityId: identity.id, persistence: store)
        XCTAssertEqual(controller.snapshot().phase.name, "FOUNDED")
        XCTAssertEqual(controller.snapshot().groupId, saved.groupId)
        XCTAssertEqual(try store.trusted(), [])
        let reopened = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { reopened.close() }
        let recovered = IosLocalGroupController(requestCreate: { XCTFail("must not create") }, requestReload: {})
        try recovered.loaded(identityId: identity.id, persistence: reopened)
        recovered.create()
        XCTAssertEqual(recovered.snapshot().groupId, saved.groupId)
        let foreign = IosLocalGroupController(requestCreate: { XCTFail("must not overwrite") }, requestReload: {})
        try foreign.loaded(identityId: String(repeating: "c", count: 64), persistence: reopened)
        XCTAssertEqual(foreign.snapshot().failure, "IDENTITY_MISMATCH")
        controller.close(); recovered.close(); foreign.close()
    }

    func testRefreshDuringInitialLoadIsQueuedAndRereadsDurableGroup() throws {
        let namespace = "dev.lantern.tests.group-refresh.\(UUID().uuidString)"
        defer { removeIdentity(namespace) }
        let identity = try AppleIdentityStore(namespace: namespace).open()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lantern-refresh-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { store.close() }
        var reloads = 0
        let controller = IosLocalGroupController(requestCreate: { XCTFail("refresh must not create") }, requestReload: { reloads += 1 })
        controller.refreshMembership() // Initial load already in progress; do not lose the request.
        try controller.loaded(identityId: identity.id, persistence: store)
        XCTAssertEqual(reloads, 1)
        XCTAssertEqual(controller.snapshot().phase.name, "LOADING")
        let foundation = try LocalGroupFoundation(identity: identity)
        let ticket = try XCTUnwrap(foundation.prepare(persistence: store))
        _ = try foundation.commit(ticket: ticket, currentIdentity: identity, persistence: store)
        try controller.loaded(identityId: identity.id, persistence: store)
        XCTAssertEqual(controller.snapshot().phase.name, "FOUNDED")
        controller.refreshMembership() // A stable state, not only FAILED, must support a new read.
        XCTAssertEqual(reloads, 2)
        try controller.loaded(identityId: identity.id, persistence: store)
        controller.close()
        controller.refreshMembership()
        XCTAssertEqual(reloads, 2)
        XCTAssertEqual(controller.snapshot().phase.name, "CLOSED")
    }

    private func removeIdentity(_ namespace: String) {
        let queries: [[String: Any]] = [
            [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: Data("\(namespace).key".utf8)],
            [kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: "\(namespace).certificate"],
            [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: namespace, kSecAttrAccount as String: "certificate-pin"]
        ]
        for query in queries {
            let status = SecItemDelete(query as CFDictionary)
            XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
        }
    }
}
