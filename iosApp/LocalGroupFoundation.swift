import Foundation
import Security
import LanternIdentity
import LanternUI

/// One explicit local create-group request. The future service serializes every call, identity
/// change and database lifetime on its owning queue, off the UI thread. No active service caller.
/// Kotlin owns all lifecycle/commit decisions. Neither success nor a persisted root grants peer trust.
final class LocalGroupFoundation {
    private let core: IosLocalGroupFoundation

    init(identity: AppleIdentity) throws {
        core = try IosLocalGroupFoundation.companion.create(identityId: identity.id)
    }

    var snapshot: IosGroupFoundationSnapshot { core.snapshot() }

    func prepare(persistence: IosPersistence) throws -> IosGroupFoundationTicket? {
        var randomFailure: Error?
        do {
            return try core.prepare(persistence: persistence, generateGroupId: {
                do { return try Self.randomGroupID() }
                catch { randomFailure = error; return nil }
            })
        } catch {
            // Keep the OS error observable; Kotlin has already made the failed request terminal.
            throw randomFailure ?? error
        }
    }

    func commit(
        ticket: IosGroupFoundationTicket,
        currentIdentity: AppleIdentity,
        persistence: IosPersistence
    ) throws -> IosGroupFoundationCommit {
        try core.commit(ticket: ticket, currentIdentityId: currentIdentity.id, persistence: persistence)
    }

    @discardableResult func cancel() -> Bool { core.cancel() }
    /// Invalidates only this pending request; it does not delete persisted membership.
    @discardableResult func leaveGroup() -> Bool { core.leaveGroup() }

    private static func randomGroupID() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw FoundationError.random(status) }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private enum FoundationError: Error, LocalizedError {
        case random(OSStatus)
        var errorDescription: String? {
            switch self {
            case .random(let status): return "Generazione ID gruppo non riuscita (\(status))."
            }
        }
    }
}
