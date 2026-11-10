// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import XCTest
@testable import QPeriaptContinuity

final class PolicyRenewalTests: XCTestCase {
    private func bytes(_ value: UInt8 = 1) -> [UInt8] { [UInt8](repeating: value, count: 32) }
    private func scope(high: Bool = false) throws -> PolicyRenewalScope {
        try PolicyRenewalScope(operation: PolicyRenewalID(bytes: bytes()), journal: JournalID(bytes: bytes(2)),
            originalOwner: bytes(3), originalCredential: bytes(4), currentCredential: bytes(5),
            currentRoster: RosterCheckpoint(version: high ? UInt64.max - 1 : 2, digest: bytes(6)),
            originalPolicy: PolicyCheckpoint(version: 1, digest: bytes(7)),
            previousPolicy: PolicyCheckpoint(version: 1, digest: bytes(7)), previousAuthorization: nil)
    }
    private func request() throws -> PolicyRenewalRequest {
        try PolicyRenewalRequest(scope: scope(), account: AccountID(bytes: bytes(8)),
            originalRosterCheckpoint: RosterCheckpoint(version: 1, digest: bytes(9)),
            originalCredential: [1,2], originalRoster: [3,4], currentCredential: [5,6], currentRoster: [7,8])
    }
    func testNativeLayoutsAndOffsetsAreExact() {
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_scope_v1>.size, 320)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_scope_v1>.offset(of: \.current_roster), 160)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_scope_v1>.offset(of: \.previous_authorization), 280)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_scope_v1>.offset(of: \.reserved), 316)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_request_v1>.size, 33176)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_request_v1>.alignment, 8)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_request_v1>.offset(of: \.original_roster_checkpoint), 352)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_request_v1>.offset(of: \.original_credential), 392)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_status_v1>.size, 160)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_status_v1>.offset(of: \.target), 72)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_status_v1>.offset(of: \.observed_at), 152)
    }
    func testRetainedRequestRoundTripOwnsAllBytesAndPreservesUnsignedCounters() throws {
        let request = try request(); var raw = try request.native()
        XCTAssertEqual(try decodePolicyRenewalRequest(&raw), request)
        withUnsafeMutableBytes(of: &raw.original_credential) { $0[4] = 99 }
        XCTAssertEqual(request.originalCredential, [1,2])
        var high = try scope(high: true).native()
        XCTAssertEqual(try decodePolicyRenewalScope(&high).currentRoster.version, UInt64.max - 1)
        var maximum = try publicPolicyRecord([UInt8](repeating: 9, count: 8192))
        XCTAssertEqual(try policyRecordBytes(&maximum).count, 8192)
    }
    func testScopeRejectsContradictoryPredecessorAndNoncanonicalNativeOption() throws {
        let good = try scope()
        XCTAssertThrowsError(try PolicyRenewalScope(operation: good.operation, journal: good.journal,
            originalOwner: good.originalOwner, originalCredential: good.originalCredential, currentCredential: good.currentCredential,
            currentRoster: good.currentRoster, originalPolicy: good.originalPolicy,
            previousPolicy: PolicyCheckpoint(version: 2, digest: bytes()), previousAuthorization: nil))
        for flag in [UInt32(1), 2] {
            var raw = good.native(); raw.has_previous_authorization = flag
            XCTAssertThrowsError(try decodePolicyRenewalScope(&raw))
        }
        var reserved = good.native(); reserved.reserved = 1
        XCTAssertThrowsError(try decodePolicyRenewalScope(&reserved))
        var zero = good.native(); withUnsafeMutableBytes(of: &zero.journal) { $0.copyBytes(from: bytes(0)) }
        XCTAssertThrowsError(try decodePolicyRenewalScope(&zero))
        XCTAssertThrowsError(try PolicyRenewalID(bytes: bytes(0)))
        XCTAssertThrowsError(try PolicyRenewalStatementID(bytes: [1]))
    }
    func testRequestRejectsDirtyTailEmptyFieldsAndImpossibleOriginalHead() throws {
        var raw = try request().native()
        withUnsafeMutableBytes(of: &raw.original_credential) { $0[8195] = 1 }
        XCTAssertThrowsError(try decodePolicyRenewalRequest(&raw))
        raw = try request().native(); raw.current_roster.length = 0
        XCTAssertThrowsError(try decodePolicyRenewalRequest(&raw))
        raw = try request().native(); raw.original_roster_checkpoint.version = 3
        XCTAssertThrowsError(try decodePolicyRenewalRequest(&raw))
    }
    private func status(_ phase: UInt32) throws -> qpc_policy_renewal_status_v1 {
        var raw = qpc_policy_renewal_status_v1(); raw.phase = phase
        withUnsafeMutableBytes(of: &raw.operation) { $0.copyBytes(from: bytes(1)) }
        withUnsafeMutableBytes(of: &raw.statement) { $0.copyBytes(from: bytes(2)) }
        raw.target = try PolicyCheckpoint(version: UInt64.max - 1, digest: bytes(3)).native()
        return raw
    }
    func testAllStatusStatesRemainDistinctIncludingBothAbandonmentReasons() throws {
        var absent = qpc_policy_renewal_status_v1()
        XCTAssertEqual(try decodePolicyRenewalStatus(&absent), .absent)
        var pending = try status(1), committed = try status(2)
        guard case .pending = try decodePolicyRenewalStatus(&pending), case .committed = try decodePolicyRenewalStatus(&committed) else {
            return XCTFail("native progress became another state")
        }
        for reason in [PolicyRenewalAbandonment.expired, .rosterAdvanced] {
            var raw = try status(3); raw.reason = reason.rawValue; raw.observed_at = UInt64.max - 1
            raw.observed_roster = try RosterCheckpoint(version: 3, digest: bytes(4)).native()
            guard case let .abandonedUncommitted(_, _, _, decoded, roster, at) = try decodePolicyRenewalStatus(&raw) else {
                return XCTFail("abandonment was lost")
            }
            XCTAssertEqual(decoded, reason); XCTAssertEqual(roster.version, 3); XCTAssertEqual(at, UInt64.max - 1)
        }
    }
    func testMalformedStatusesCannotBecomeCommittedOrNoCommit() throws {
        for phase in [UInt32(0), 3, 4, UInt32.max] {
            var raw = try status(phase); XCTAssertThrowsError(try decodePolicyRenewalStatus(&raw))
        }
        var pending = try status(1); pending.observed_at = 1
        XCTAssertThrowsError(try decodePolicyRenewalStatus(&pending))
        var committed = try status(2); committed.reason = 1
        XCTAssertThrowsError(try decodePolicyRenewalStatus(&committed))
        var zero = try status(2); zero.target.version = 0
        XCTAssertThrowsError(try decodePolicyRenewalStatus(&zero))
    }
}
