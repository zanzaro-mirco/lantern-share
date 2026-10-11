import Foundation
import XCTest
import LanternUI
import LanternIdentity
import Security
@testable import Lantern

final class LocalGroupControllerTests: XCTestCase {
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
