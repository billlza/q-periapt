// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import XCTest
@testable import QPeriaptContinuity

final class RosterRefreshTests: XCTestCase {
    private func proposal(selected: Bool = false) -> [UInt8] {
        var bytes = [UInt8](repeating: 1, count: 417)
        bytes.replaceSubrange(0..<8, with: "QPRWNP01".utf8)
        func counter(_ offset: Int, _ value: UInt64) {
            var value = value.bigEndian
            withUnsafeBytes(of: &value) { bytes.replaceSubrange(offset..<(offset + 8), with: $0) }
        }
        counter(168, UInt64.max - 2); counter(208, UInt64.max - 1); counter(248, 3)
        counter(321, UInt64.max - 1); counter(369, UInt64.max - 1)
        counter(329, UInt64.max - 2); counter(377, UInt64.max - 1)
        bytes[416] = 2; bytes[288] = selected ? 1 : 0
        if selected { bytes[256] = 2 } else { bytes.replaceSubrange(289..<321, with: [UInt8](repeating: 0, count: 32)) }
        return bytes
    }
    private func progress(_ parsed: RosterRefreshProposal) -> qpc_roster_refresh_progress_v1 {
        var raw = qpc_roster_refresh_progress_v1(); let scope = parsed.scope
        withUnsafeMutableBytes(of: &raw.scope.operation) { $0.copyBytes(from: scope.operation.bytes) }
        raw.scope.previous = scope.previous.native(); raw.scope.target = scope.target.native(); raw.scope.policy = scope.policy.native()
        if let authorization = scope.policyAuthorization {
            raw.scope.has_policy_authorization = 1
            withUnsafeMutableBytes(of: &raw.scope.policy_authorization) { $0.copyBytes(from: authorization.bytes) }
        }
        raw.proposal = parsed.native(); return raw
    }
    func testRetainedRosterProposalOwnsExactScopeAndRejectsOtherDomains() throws {
        for selected in [false, true] {
            var bytes = proposal(selected: selected); let saved = bytes
            let parsed = try RosterRefreshProposal(retainedBytes: bytes); bytes[416] = 3
            XCTAssertEqual(parsed.bytes, saved); XCTAssertEqual(parsed.scope.target.version, UInt64.max - 1)
            XCTAssertEqual(parsed.scope.policyAuthorization != nil, selected)
            var raw = parsed.native(); XCTAssertEqual(try rosterRefreshProposal(&raw), parsed)
        }
        let original = proposal(); var invalid = [Array(original.dropLast()), original + [0]]
        for tag in ["QPPWNP01", "QPCRNP01", "QPRWNP02"] {
            var changed = original; changed.replaceSubrange(0..<8, with: tag.utf8); invalid.append(changed)
        }
        for offset in [8, 40, 72, 104, 136, 176, 216, 256, 337, 385] {
            var changed = original; changed.replaceSubrange(offset..<(offset + 32), with: [UInt8](repeating: 0, count: 32)); invalid.append(changed)
        }
        for offset in [168, 208, 248, 321, 329, 369, 377] {
            var changed = original; changed.replaceSubrange(offset..<(offset + 8), with: [UInt8](repeating: 255, count: 8)); invalid.append(changed)
        }
        for offset in [288, 289, 256] { var changed = original; changed[offset] = 2; invalid.append(changed) }
        var sameHead = original; sameHead.replaceSubrange(385..<417, with: original[337..<369]); invalid.append(sameHead)
        var backward = original; backward.replaceSubrange(208..<216, with: original[168..<176]); invalid.append(backward)
        for bytes in invalid { XCTAssertThrowsError(try RosterRefreshProposal(retainedBytes: bytes)) }
    }
    func testRosterPreparationChecksCanonicalAbsenceAndABI() throws {
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_proposal_v1>.size, 417)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_scope_v1>.size, 192)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_preparation_v1>.size, 424)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_progress_v1>.size, 624)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_target_v1>.size, 40)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_progress_v1>.offset(of: \.proposal), 200)
        var raw = qpc_roster_refresh_preparation_v1(); XCTAssertNil(try rosterRefreshPreparation(&raw))
        raw.proposal = try RosterRefreshProposal(retainedBytes: proposal()).native()
        XCTAssertThrowsError(try rosterRefreshPreparation(&raw)); raw.present = 1
        XCTAssertEqual(try rosterRefreshPreparation(&raw)?.bytes, proposal())
        for flag: UInt32 in [2, 257, UInt32.max] { raw.present = flag; XCTAssertThrowsError(try rosterRefreshPreparation(&raw)) }
        raw.present = 1; raw.reserved.2 = 1; XCTAssertThrowsError(try rosterRefreshPreparation(&raw))
    }
    func testRosterProgressPreservesAllSixStatesAndChecksProposalScope() throws {
        var empty = qpc_roster_refresh_progress_v1(); XCTAssertEqual(try rosterRefreshProgress(&empty), .absent)
        let parsed = try RosterRefreshProposal(retainedBytes: proposal(selected: true))
        var raw = progress(parsed); XCTAssertThrowsError(try rosterRefreshProgress(&raw))
        for phase: UInt32 in [1, 5] {
            raw = progress(parsed); raw.phase = phase; XCTAssertThrowsError(try rosterRefreshProgress(&raw))
            raw.proposal = qpc_roster_refresh_proposal_v1()
            XCTAssertEqual(try rosterRefreshProgress(&raw), phase == 1 ? .staged(parsed.scope) : .abandonedBeforePreparation(parsed.scope))
            raw.retired = 1; XCTAssertThrowsError(try rosterRefreshProgress(&raw))
        }
        raw = progress(parsed); raw.phase = 2; XCTAssertEqual(try rosterRefreshProgress(&raw), .reserved(parsed))
        raw.retired = 1; XCTAssertThrowsError(try rosterRefreshProgress(&raw))
        for retired: UInt32 in [0, 1] {
            raw.retired = retired; raw.phase = 3; XCTAssertEqual(try rosterRefreshProgress(&raw), .applied(parsed, retired: retired == 1))
            raw.phase = 4; XCTAssertEqual(try rosterRefreshProgress(&raw), .closed(parsed, retired: retired == 1))
        }
        raw.scope.policy.version += 1; XCTAssertThrowsError(try rosterRefreshProgress(&raw))
        raw = progress(parsed); raw.phase = 3; raw.reserved.6 = 1; XCTAssertThrowsError(try rosterRefreshProgress(&raw))
        raw = progress(parsed); raw.phase = 3; raw.scope.reserved = 1; XCTAssertThrowsError(try rosterRefreshProgress(&raw))
        for code: UInt32 in [0, 6, 257, UInt32.max] { XCTAssertNil(RosterRefreshState(rawValue: code)) }
        XCTAssertEqual((1...5).compactMap { RosterRefreshState(rawValue: UInt32($0)) }, [.prepared, .applied, .closed, .acknowledged, .unavailable])
    }
    func testRosterCallsRespectPreparedCancelledAndClosedOwners() throws {
        let point = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        let octets = Array(point.utf8)
        let pointBytes = try stride(from: 0, to: octets.count, by: 2).map {
            try XCTUnwrap(UInt8(String(decoding: octets[$0..<($0 + 2)], as: UTF8.self), radix: 16))
        }
        let root = [UInt8](repeating: 1, count: 1952) + pointBytes
        let intent = try EnrollmentIntent(root: root, device: [UInt8](repeating: 2, count: 16),
            generation: 1, family: [UInt8](repeating: 3, count: 32), validFrom: 0, validUntil: UInt64.max - 1)
        let owner = try ContinuityEnrollment.prepareResume(path: "/unused", intent: intent)
        defer { XCTAssertNoThrow(try owner.close()) }
        let parsed = try RosterRefreshProposal(retainedBytes: proposal())
        // Canonical account digest of this fixed public-key fixture (identity.rs).
        let pin = try AccountPin(account: AccountID(bytes: [101, 231, 213, 240, 131, 125, 189, 89, 146, 154, 71, 221, 188, 46, 147, 165, 202, 206, 189, 209, 30, 254, 89, 18, 158, 119, 222, 168, 175, 213, 77, 74]), root: root,
            family: [UInt8](repeating: 3, count: 32), checkpoint: parsed.scope.target)
        let calls: [() throws -> Void] = [
            { _ = try owner.prepareWitnessedRosterRefresh(operation: parsed.scope.operation, policySource: .original, certificate: [1], roster: [1], pin: pin) },
            { _ = try owner.recoverWitnessedRosterRefreshPreparation() },
            { _ = try owner.witnessedRosterRefreshProgress() },
            { _ = try owner.abandonUnpreparedRosterRefresh(operation: parsed.scope.operation) },
            { _ = try owner.commitWitnessedRosterRefresh(parsed, policySource: .original) },
            { _ = try owner.reconcileWitnessedRosterRefresh(parsed) },
            { _ = try owner.closeWitnessedRosterRefresh(parsed) }
        ]
        for call in calls { XCTAssertThrowsError(try call()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) } }
        try owner.cancel()
        // Native take_owner checks the owner kind before cancellation. Only
        // finishOpen admits the prepared construction and consumes its request.
        for call in calls { XCTAssertThrowsError(try call()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) } }
        XCTAssertThrowsError(try owner.finishOpen()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 302) }
        for call in calls { XCTAssertThrowsError(try call()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2) } }
    }
}
