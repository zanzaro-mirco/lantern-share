import Foundation
import Security
import XCTest
import LanternIdentity
import LanternUI
@testable import Lantern

/// Real Keychain identity, OS entropy and SQLite. Only deterministic callback-failure cases
/// below supply test randomness directly to the Kotlin facade; production never injects it.
final class LocalGroupFoundationTests: XCTestCase {
    private var directories: [URL] = []
    private var namespaces: [String] = []

    override func tearDown() {
        directories.forEach { try? FileManager.default.removeItem(at: $0) }
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

    func testOSFoundationSurvivesIdentityAndDatabaseReopenWithoutPeerTrust() throws {
        let (identity, namespace) = try identity()
        let directory = try directory()
        var firstClosed = false
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { if !firstClosed { store.close() } }
        try store.rename(value: "iPhone caffè ☕")
        let owner = try LocalGroupFoundation(identity: identity)
        let ticket = try XCTUnwrap(owner.prepare(persistence: store))
        XCTAssertEqual(owner.snapshot.phase.name, "AWAITING_COMMIT")
        XCTAssertNil(try store.localGroup())
        let currentIdentity = try AppleIdentityStore(namespace: namespace).open()
        XCTAssertEqual(currentIdentity.id, identity.id)
        XCTAssertEqual(try owner.commit(ticket: ticket, currentIdentity: currentIdentity, persistence: store).name, "COMMITTED")
        let saved = try XCTUnwrap(store.localGroup())
        XCTAssertEqual(saved.founderId, identity.id)
        XCTAssertEqual(saved.groupId.count, 64)
        XCTAssertTrue(saved.groupId.allSatisfy { "0123456789abcdef".contains($0) })
        XCTAssertEqual(try store.trusted(), [])
        XCTAssertEqual(try owner.commit(ticket: ticket, currentIdentity: currentIdentity, persistence: store).name, "INVALIDATED")
        XCTAssertFalse(owner.cancel())

        store.close()
        firstClosed = true
        // The original database is closed before reopening; the consumed owner is not reused.
        let reopened = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { reopened.close() }
        XCTAssertEqual(try reopened.localGroup()?.groupId, saved.groupId)
        XCTAssertEqual(try reopened.name(), "iPhone caffè ☕")
        XCTAssertEqual(try reopened.trusted(), [])
        let replacement = try LocalGroupFoundation(identity: currentIdentity)
        XCTAssertNil(try replacement.prepare(persistence: reopened))
        XCTAssertEqual(replacement.snapshot.failure.name, "ALREADY_IN_GROUP")
    }

    func testSeparateExplicitRequestsUseFreshOSRandomnessAndOnlyOneCanCommit() throws {
        let (identity, _) = try identity()
        let directory = try directory()
        let firstStore = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { firstStore.close() }
        let nextStore = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
        defer { nextStore.close() }
        let first = try LocalGroupFoundation(identity: identity)
        let next = try LocalGroupFoundation(identity: identity)
        let firstTicket = try XCTUnwrap(first.prepare(persistence: firstStore))
        let nextTicket = try XCTUnwrap(next.prepare(persistence: nextStore))
        XCTAssertEqual(try next.commit(ticket: firstTicket, currentIdentity: identity, persistence: nextStore).name, "INVALIDATED")
        XCTAssertEqual(next.snapshot.phase.name, "AWAITING_COMMIT")
        XCTAssertEqual(try first.commit(ticket: firstTicket, currentIdentity: identity, persistence: firstStore).name, "COMMITTED")
        let saved = try XCTUnwrap(firstStore.localGroup())
        XCTAssertEqual(try next.commit(ticket: nextTicket, currentIdentity: identity, persistence: nextStore).name, "ALREADY_IN_GROUP")
        XCTAssertEqual(try nextStore.localGroup()?.groupId, saved.groupId)

        let separateStore = try IosEntryKt.openIosPersistence(databaseDirectory: try self.directory().path)
        defer { separateStore.close() }
        let separate = try LocalGroupFoundation(identity: identity)
        let separateTicket = try XCTUnwrap(separate.prepare(persistence: separateStore))
        XCTAssertEqual(try separate.commit(ticket: separateTicket, currentIdentity: identity, persistence: separateStore).name, "COMMITTED")
        XCTAssertNotEqual(try separateStore.localGroup()?.groupId, saved.groupId)
    }

    func testChangedRealIdentityDoesNotPersistOrRotateTheOriginalIdentity() throws {
        let (identity, namespace) = try identity()
        let (changed, _) = try self.identity()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let owner = try LocalGroupFoundation(identity: identity)
        let ticket = try XCTUnwrap(owner.prepare(persistence: store))
        XCTAssertEqual(try owner.commit(ticket: ticket, currentIdentity: changed, persistence: store).name, "INVALIDATED")
        XCTAssertEqual(owner.snapshot.failure.name, "IDENTITY_CHANGED")
        XCTAssertNil(try store.localGroup())
        XCTAssertEqual(try AppleIdentityStore(namespace: namespace).open().id, identity.id)
    }

    func testCancelAndLeaveInvalidatePreparedRequestsWithoutPersistence() throws {
        let (identity, _) = try identity()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        for leave in [false, true] {
            let owner = try LocalGroupFoundation(identity: identity)
            let ticket = try XCTUnwrap(owner.prepare(persistence: store))
            XCTAssertTrue(leave ? owner.leaveGroup() : owner.cancel())
            XCTAssertEqual(try owner.commit(ticket: ticket, currentIdentity: identity, persistence: store).name, "INVALIDATED")
            XCTAssertEqual(owner.snapshot.failure.name, leave ? "LEFT_GROUP" : "CANCELLED")
            XCTAssertNil(try store.localGroup())
            XCTAssertNil(try owner.prepare(persistence: store))
        }
    }

    func testMissingKeyIsObservableAndDoesNotFoundAGroup() throws {
        let (identity, namespace) = try identity()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let owner = try LocalGroupFoundation(identity: identity)
        _ = try XCTUnwrap(owner.prepare(persistence: store))
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                  kSecAttrApplicationTag as String: Data("\(namespace).key".utf8)]
        XCTAssertEqual(SecItemDelete(query as CFDictionary), errSecSuccess)
        XCTAssertThrowsError(try AppleIdentityStore(namespace: namespace).open())
        XCTAssertTrue(owner.cancel())
        XCTAssertNil(try store.localGroup())
        XCTAssertEqual(try store.trusted(), [])
    }

    func testNullAndMalformedOSResultsFailTerminallyWithoutFallbackOrRetry() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let suppliedValues: [String?] = [nil, "invalid", String(repeating: "A", count: 64)]
        for supplied in suppliedValues {
            let core = try IosLocalGroupFoundation.companion.create(identityId: String(repeating: "a", count: 64))
            var calls = 0
            XCTAssertThrowsError(try core.prepare(persistence: store, generateGroupId: { calls += 1; return supplied }))
            XCTAssertEqual(core.snapshot().failure.name, "PREPARATION_FAILED")
            XCTAssertNil(try core.prepare(persistence: store, generateGroupId: { calls += 1; return supplied }))
            XCTAssertEqual(calls, 1)
            XCTAssertNil(try store.localGroup())
        }
    }

    func testReentrantOSCallbackCancellationAndLeaveCannotReviveTicket() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        for leave in [false, true] {
            let core = try IosLocalGroupFoundation.companion.create(identityId: String(repeating: "a", count: 64))
            XCTAssertNil(try core.prepare(persistence: store, generateGroupId: {
                XCTAssertEqual(core.snapshot().phase.name, "PREPARING")
                if leave { _ = core.leaveGroup() } else { _ = core.cancel() }
                return String(repeating: "b", count: 64)
            }))
            XCTAssertEqual(core.snapshot().failure.name, leave ? "LEFT_GROUP" : "CANCELLED")
            XCTAssertNil(try store.localGroup())
        }
    }

    func testExistingMembershipSkipsOSRandomness() throws {
        let (identity, _) = try identity()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let owner = try LocalGroupFoundation(identity: identity)
        let ticket = try XCTUnwrap(owner.prepare(persistence: store))
        _ = try owner.commit(ticket: ticket, currentIdentity: identity, persistence: store)
        let core = try IosLocalGroupFoundation.companion.create(identityId: identity.id)
        XCTAssertNil(try core.prepare(persistence: store, generateGroupId: {
            XCTFail("existing root must be checked before OS randomness")
            return nil
        }))
        XCTAssertEqual(core.snapshot().failure.name, "ALREADY_IN_GROUP")
    }

    func testCancelledBeforePreparationDoesNotReadClosedStorageOrGenerate() throws {
        let core = try IosLocalGroupFoundation.companion.create(identityId: String(repeating: "a", count: 64))
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        store.close()
        XCTAssertTrue(core.cancel())
        XCTAssertNil(try core.prepare(persistence: store, generateGroupId: {
            XCTFail("cancelled preparation must not touch the OS")
            return nil
        }))
        XCTAssertEqual(core.snapshot().failure.name, "CANCELLED")
        XCTAssertFalse(core.leaveGroup())
    }

    func testInvalidIdentityIsRejectedAtTheThrowingSwiftBoundary() {
        for identity in ["", "invalid", String(repeating: "A", count: 64)] {
            XCTAssertThrowsError(try IosLocalGroupFoundation.companion.create(identityId: identity))
        }
    }

    func testReentrantPreparationAndFailureCannotReplaceTheFirstTerminalReason() throws {
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let core = try IosLocalGroupFoundation.companion.create(identityId: String(repeating: "a", count: 64))
        XCTAssertThrowsError(try core.prepare(persistence: store, generateGroupId: {
            // The callback cannot throw into Kotlin. Reentry below must not invoke its OS block.
            do {
                XCTAssertNil(try core.prepare(persistence: store, generateGroupId: {
                    XCTFail("nested preparation must not generate another ID")
                    return nil
                }))
            } catch { XCTFail("unexpected nested preparation error: \(error)") }
            XCTAssertTrue(core.leaveGroup())
            return nil
        }))
        XCTAssertEqual(core.snapshot().failure.name, "LEFT_GROUP")
        XCTAssertNil(try store.localGroup())
        XCTAssertFalse(core.cancel())
    }

    func testSavedFounderPreparesEvidenceWithoutPersistingRemoteMembership() throws {
        let (founder, namespace) = try identity()
        let (member, _) = try identity()
        let path = try directory()
        let first = try IosEntryKt.openIosPersistence(databaseDirectory: path.path)
        var firstClosed = false
        defer { if !firstClosed { first.close() } }
        let owner = try LocalGroupFoundation(identity: founder)
        let ticket = try XCTUnwrap(owner.prepare(persistence: first))
        XCTAssertEqual(try owner.commit(ticket: ticket, currentIdentity: founder, persistence: first).name, "COMMITTED")
        let saved = try XCTUnwrap(first.localGroup())
        first.close()
        firstClosed = true
        let reopened = try IosEntryKt.openIosPersistence(databaseDirectory: path.path)
        defer { reopened.close() }
        let current = try AppleIdentityStore(namespace: namespace).open()
        let evidence = try FounderGroupAdmission.prepare(identity: current, persistence: reopened, memberID: member.id)
        XCTAssertTrue(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: saved.groupId, expectedFounder: saved.founderId, expectedMember: member.id
        ))
        XCTAssertFalse(try GroupAdmissionEvidenceCertificates.verifyChain(
            evidence, expectedGroup: saved.groupId, expectedFounder: member.id, expectedMember: member.id
        ))
        XCTAssertEqual(evidence.certificates.count, 1)
        XCTAssertEqual(evidence.certificates.first?.identity, founder.id)
        XCTAssertEqual(try reopened.localGroup()?.groupId, saved.groupId)
        XCTAssertEqual(try reopened.trusted(), [])
        XCTAssertEqual(try reopened.history().count, 0)
    }

    func testMissingOrForeignFoundationAndSelfAdmissionCannotPrepareEvidence() throws {
        let (founder, _) = try identity()
        let (other, _) = try identity()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        XCTAssertThrowsError(try FounderGroupAdmission.prepare(identity: founder, persistence: store, memberID: other.id))
        XCTAssertNil(try store.localGroup())
        let owner = try LocalGroupFoundation(identity: founder)
        let ticket = try XCTUnwrap(owner.prepare(persistence: store))
        XCTAssertEqual(try owner.commit(ticket: ticket, currentIdentity: founder, persistence: store).name, "COMMITTED")
        let saved = try XCTUnwrap(store.localGroup())
        XCTAssertThrowsError(try FounderGroupAdmission.prepare(identity: other, persistence: store, memberID: founder.id))
        XCTAssertThrowsError(try FounderGroupAdmission.prepare(identity: founder, persistence: store, memberID: founder.id))
        XCTAssertThrowsError(try FounderGroupAdmission.prepare(identity: founder, persistence: store, memberID: "invalid"))
        XCTAssertEqual(try store.localGroup()?.groupId, saved.groupId)
        XCTAssertEqual(try store.trusted(), [])
    }

    func testFounderEvidenceOSSigningFailureDoesNotVerifyRetryOrWrite() throws {
        let (founder, _) = try identity()
        let (member, _) = try identity()
        let store = try IosEntryKt.openIosPersistence(databaseDirectory: try directory().path)
        defer { store.close() }
        let owner = try LocalGroupFoundation(identity: founder)
        let ticket = try XCTUnwrap(owner.prepare(persistence: store))
        XCTAssertEqual(try owner.commit(ticket: ticket, currentIdentity: founder, persistence: store).name, "COMMITTED")
        let saved = try XCTUnwrap(store.localGroup())
        var signs = 0
        XCTAssertThrowsError(try IosFounderGroupAdmission.shared.prepare(
            persistence: store, identityId: founder.id, memberId: member.id,
            certificateDer: (SecCertificateCopyData(founder.certificate) as Data).base64EncodedString(),
            sign: { _ in
                signs += 1
                return nil
            },
            verifySignature: { _, _ in
                XCTFail("Failed signing must not reach verification")
                return KotlinBoolean(bool: false)
            }
        ))
        XCTAssertEqual(signs, 1)
        XCTAssertEqual(try store.localGroup()?.groupId, saved.groupId)
        XCTAssertEqual(try store.trusted(), [])
    }

    private func identity() throws -> (AppleIdentity, String) {
        let namespace = "dev.lantern.foundation-tests.\(UUID().uuidString)"
        namespaces.append(namespace)
        return (try AppleIdentityStore(namespace: namespace).open(), namespace)
    }

    private func directory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lantern-foundation-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        directories.append(directory)
        return directory
    }
}
