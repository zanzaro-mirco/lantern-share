import Foundation
import XCTest
import LanternUI

/// Adapter memory rules only, not live membership or a permission to use the transport.
final class GroupSessionMemoryTests: XCTestCase {
    private let group = String(repeating: "a", count: 64)
    private let founder = String(repeating: "b", count: 64)

    func testTextScopeSurvivesExactB5ButNeverDifferentMarkerPeerOrReset() throws {
        let memory = IosGroupSessionMemory()
        let marker = try snapshot(attempt: "e")
        let local = try memory.propose(groupId: group, founderId: founder, marker: marker, newSessionId: id("c"))
        let remote = try IosGroupSessionMemory().propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("d"))
        XCTAssertNotNil(try memory.selectText(local: local, remote: remote, groupId: group, founderId: founder,
            marker: marker, senderId: founder, recipientId: id("d")).context)
        let held = try memory.propose(groupId: group, founderId: founder, marker: marker, newSessionId: id("f"))
        let usedHeld = try used(held)
        // Install a test observation of the same used session after scope was established.
        XCTAssertNotNil(try memory.selectText(local: usedHeld, remote: usedHeld, groupId: group, founderId: founder,
            marker: marker, senderId: id("d"), recipientId: founder).context)
        _ = try memory.select(local: usedHeld, remote: usedHeld, groupId: group, founderId: founder, marker: marker)
        XCTAssertNotNil(try memory.selectText(local: usedHeld, remote: usedHeld, groupId: group, founderId: founder,
            marker: snapshot(attempt: "e"), senderId: founder, recipientId: id("d")).context)
        for (currentMarker, peer) in [(marker, id("f")), (try snapshot(attempt: "f"), id("d"))] {
            let result = try memory.selectText(local: usedHeld, remote: usedHeld, groupId: group, founderId: founder,
                marker: currentMarker, senderId: founder, recipientId: peer)
            XCTAssertNil(result.context)
            XCTAssertEqual(result.failure, .rosterRequired)
        }
        memory.reset()
        let fresh = try memory.propose(groupId: group, founderId: founder, marker: marker, newSessionId: id("f"))
        let unknown = try memory.selectText(local: fresh, remote: usedHeld, groupId: group, founderId: founder,
            marker: marker, senderId: founder, recipientId: id("d"))
        XCTAssertNil(unknown.context)
        XCTAssertEqual(unknown.failure, .rosterRequired)
    }

    func testHeldSessionIsBoundToEntireCommittedMarkerAndRunReset() throws {
        let memory = IosGroupSessionMemory()
        let marker = try snapshot(attempt: "e")
        let local = try memory.propose(groupId: group, founderId: founder, marker: marker, newSessionId: id("c"))
        let remote = try IosGroupSessionMemory().propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("d"))
        _ = try memory.select(local: local, remote: remote, groupId: group, founderId: founder, marker: marker)
        var expected = data(try local.framedBytes())
        expected[expected.count - 1] = 2 // Same selected ID, now established rather than provisional.
        XCTAssertEqual(data(try memory.propose(groupId: group, founderId: founder,
            marker: snapshot(attempt: "e"), newSessionId: id("f")).framedBytes()), expected)
        // Equal root is insufficient. A different attempt or payload cannot revive old memory.
        for changed in [try snapshot(attempt: "f"), try snapshot(attempt: "e", payload: 2)] {
            let fresh = try memory.propose(groupId: group, founderId: founder, marker: changed, newSessionId: id("f"))
            XCTAssertNotEqual(data(try fresh.framedBytes()), expected)
            XCTAssertEqual(data(try fresh.framedBytes()).last, 0)
        }
        let founded = try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("f"))
        XCTAssertEqual(data(try founded.framedBytes()).last, 0)
        memory.reset()
        XCTAssertEqual(data(try memory.propose(groupId: group, founderId: founder,
            marker: marker, newSessionId: id("f")).framedBytes()).last, 0)
    }

    func testUsedChoiceAndDifferentRootDoNotReplaceHeldSessionButSameSessionJoinsAsUsed() throws {
        let memory = IosGroupSessionMemory()
        let local = try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("c"))
        let remote = try IosGroupSessionMemory().propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("d"))
        _ = try memory.select(local: local, remote: remote, groupId: group, founderId: founder, marker: nil)
        let expected = data(try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("f")).framedBytes())
        let usedLocal = try used(local), usedRemote = try used(remote)
        _ = try memory.select(local: usedLocal, remote: usedRemote, groupId: group, founderId: founder, marker: nil)
        let held = try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("f"))
        XCTAssertEqual(data(try held.framedBytes()), expected) // Choose is not a merge.
        // ADR 021: the same held session observed used by the peer (interrupted delivery) joins as used.
        _ = try memory.select(local: held, remote: usedLocal, groupId: group, founderId: founder, marker: nil)
        var usedExpected = expected
        usedExpected[usedExpected.count - 1] = 3
        let usedHeld = try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("f"))
        XCTAssertEqual(data(try usedHeld.framedBytes()), usedExpected)
        _ = try memory.select(local: usedHeld, remote: held, groupId: group, founderId: founder, marker: nil)
        XCTAssertEqual(data(try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("f")).framedBytes()),
            usedExpected) // Never downgraded by a later empty observation.
        let other = try IosGroupSessionMemory().propose(groupId: id("e"), founderId: founder, marker: nil, newSessionId: id("f"))
        XCTAssertThrowsError(try memory.select(local: usedHeld, remote: other, groupId: group, founderId: founder, marker: nil))
        XCTAssertEqual(data(try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("f")).framedBytes()), usedExpected)
    }

    /// ADR 022: an explicit choice is local; keeping changes nothing, adopting replaces the held session by the peer's as used.
    func testExplicitChoiceKeepsOrAdoptsTheirsAsUsedAndRefusesStaleOrReset() throws {
        func negotiate(_ memory: IosGroupSessionMemory, _ local: IosGroupSessionOffer, _ remote: IosGroupSessionOffer)
            throws -> (IosGroupAdmissionController, IosGroupSessionChoiceHandle) {
            var selected: IosGroupAdmissionSelection?
            let controller = IosGroupAdmissionController(requestSelect: { selected = $0 }, requestConfirm: { _ in }, requestCancel: {})
            controller.negotiateSession(id: id("a"), name: "member")
            let selection = try XCTUnwrap(selected)
            controller.selected(value: selection)
            controller.sessionSelected(value: selection,
                result: try memory.select(local: local, remote: remote, groupId: group, founderId: founder, marker: nil))
            XCTAssertEqual(controller.sessionSnapshot().phase, .needsChoice)
            let handle = IosGroupSessionChoiceHandle()
            controller.choiceHandler = { handle.request = $0 }
            return (controller, handle)
        }
        let memory = IosGroupSessionMemory()
        let mine = try used(try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("c")))
        let theirsEmpty = try IosGroupSessionMemory().propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("d"))
        _ = try memory.select(local: try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("c")),
                              remote: mine, groupId: group, founderId: founder, marker: nil)
        let theirs = try used(theirsEmpty)
        let held = try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("f"))
        let heldBytes = data(try held.framedBytes())
        // Keep: nothing changes and the answer idles the panel.
        var (controller, handle) = try negotiate(memory, try used(held), theirs)
        controller.chooseSession(sessionId: id("c"))
        var request = try XCTUnwrap(handle.request)
        XCTAssertTrue(memory.choose(request: request))
        controller.sessionChosen(request: request, applied: true)
        XCTAssertEqual(controller.sessionSnapshot().phase, .idle)
        XCTAssertEqual(data(try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("f")).framedBytes()), heldBytes)
        // Adopt: the held session is replaced by theirs, used, never merged.
        (controller, handle) = try negotiate(memory, try used(held), theirs)
        controller.chooseSession(sessionId: id("d"))
        request = try XCTUnwrap(handle.request)
        XCTAssertTrue(memory.choose(request: request))
        XCTAssertEqual(data(try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("f")).framedBytes()),
                       data(try theirs.framedBytes()))
        // Applying the same request again is idempotent: it now keeps the adopted session and merges nothing.
        XCTAssertTrue(memory.choose(request: request))
        XCTAssertEqual(data(try memory.propose(groupId: group, founderId: founder, marker: nil, newSessionId: id("f")).framedBytes()),
                       data(try theirs.framedBytes()))
        // A reset run refuses any choice.
        (controller, handle) = try negotiate(memory, try used(held), theirs)
        controller.chooseSession(sessionId: id("d"))
        let afterReset = try XCTUnwrap(handle.request)
        memory.reset()
        XCTAssertFalse(memory.choose(request: afterReset))
    }

    private final class IosGroupSessionChoiceHandle { var request: IosGroupSessionChoice? }

    private func used(_ offer: IosGroupSessionOffer) throws -> IosGroupSessionOffer {
        var frame = data(try offer.framedBytes())
        frame[frame.count - 1] = 3 // Untrusted test observation, parsed by the production shared codec.
        let decoder = IosGroupSessionDecoder()
        return try XCTUnwrap(decoder.accept(chunk: bytes(frame)).offer)
    }

    private func snapshot(attempt: String, payload: Int8 = 1) throws -> IosGroupAdoptionJournalSnapshot {
        let content = KotlinByteArray(size: 1)
        content.set(index: 0, value: payload)
        return try IosGroupAdoptionJournalSnapshot.companion.fromStoredRecord(attemptId: id(attempt),
            localIdentity: id("c"), peerIdentity: founder, groupId: group, founderId: founder, payload: content)
    }

    private func id(_ character: String) -> String { String(repeating: character, count: 64) }
    private func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }
    private func bytes(_ data: Data) -> KotlinByteArray {
        let result = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() { result.set(index: Int32(index), value: Int8(bitPattern: byte)) }
        return result
    }
}
