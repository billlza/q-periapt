// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner

public struct RosterRefreshID: Sendable, Equatable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) throws {
        guard bytes.count == 32 else { throw ContinuityBoundaryError.inputLength }
        guard bytes.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.bytes = bytes
    }
}
/// Explicit current policy selection. Selected requires selectContinuedPolicy;
/// neither case retries using a different authority when admission fails.
public enum RosterPolicySource: UInt32, Sendable { case original = 0, selected = 1 }
public struct RosterRefreshScope: Sendable, Equatable {
    public let operation: RosterRefreshID
    public let previous: RosterCheckpoint
    public let target: RosterCheckpoint
    public let policy: PolicyCheckpoint
    public let policyAuthorization: PolicyAuthorizationID?
    public init(operation: RosterRefreshID, previous: RosterCheckpoint, target: RosterCheckpoint,
                policy: PolicyCheckpoint, policyAuthorization: PolicyAuthorizationID?) throws {
        guard target.version > previous.version else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.operation = operation; self.previous = previous; self.target = target
        self.policy = policy; self.policyAuthorization = policyAuthorization
    }
}
/// Complete original R expectation. Restoring public bytes is not an approval.
/// Retain these exact bytes independently of incoming witness replies.
public struct RosterRefreshProposal: Sendable, Equatable {
    public let bytes: [UInt8]
    public let scope: RosterRefreshScope
    public init(retainedBytes bytes: [UInt8]) throws {
        guard bytes.count == 417 else { throw ContinuityBoundaryError.inputLength }
        guard Array(bytes[0..<8]) == Array("QPRWNP01".utf8) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        func field(_ offset: Int) -> [UInt8] { Array(bytes[offset..<(offset + 32)]) }
        func counter(_ offset: Int) -> UInt64 {
            bytes[offset..<(offset + 8)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }
        for offset in [8, 40, 72, 104, 337, 385] {
            guard field(offset).contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        }
        let authorization: PolicyAuthorizationID?
        switch bytes[288] {
        case 0:
            guard field(289).allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
            authorization = nil
        case 1: authorization = try PolicyAuthorizationID(bytes: field(289))
        default: throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        let scope = try RosterRefreshScope(operation: RosterRefreshID(bytes: field(136)),
            previous: RosterCheckpoint(version: counter(168), digest: field(176)),
            target: RosterCheckpoint(version: counter(208), digest: field(216)),
            policy: PolicyCheckpoint(version: counter(248), digest: field(256)), policyAuthorization: authorization)
        let fence = counter(321), revision = counter(329)
        guard (authorization == nil) == (field(256) == field(104)),
              fence > 0, fence < UInt64.max, counter(369) == fence,
              revision > 0, revision < UInt64.max - 1, counter(377) == revision + 1,
              field(337) != field(385) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.bytes = bytes; self.scope = scope
    }
    func native() -> qpc_roster_refresh_proposal_v1 {
        var raw = qpc_roster_refresh_proposal_v1()
        withUnsafeMutableBytes(of: &raw.bytes) { $0.copyBytes(from: bytes) }
        return raw
    }
}
/// Witness history, never an operational lease or a replacement for local history.
public enum RosterRefreshState: UInt32, Sendable {
    case prepared = 1, applied = 2, closed = 3, acknowledged = 4, unavailable = 5
}
public enum RosterRefreshProgress: Sendable, Equatable {
    case absent
    case staged(RosterRefreshScope)
    case reserved(RosterRefreshProposal)
    case applied(RosterRefreshProposal, retired: Bool)
    case closed(RosterRefreshProposal, retired: Bool)
    /// Explicit local abandonment before releasing any proposal; never witness Closed.
    case abandonedBeforePreparation(RosterRefreshScope)
}
func rosterRefreshProposal(_ raw: inout qpc_roster_refresh_proposal_v1) throws -> RosterRefreshProposal {
    do { return try RosterRefreshProposal(retainedBytes: withUnsafeBytes(of: &raw.bytes) { Array($0) }) }
    catch is ContinuityBoundaryError { throw ContinuityBoundaryError.malformedOutput }
}
func rosterRefreshPreparation(_ raw: inout qpc_roster_refresh_preparation_v1) throws -> RosterRefreshProposal? {
    guard raw.present <= 1, withUnsafeBytes(of: &raw.reserved, { $0.allSatisfy { $0 == 0 } }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    if raw.present == 0 {
        guard withUnsafeBytes(of: &raw.proposal, { $0.allSatisfy { $0 == 0 } }) else { throw ContinuityBoundaryError.malformedOutput }
        return nil
    }
    return try rosterRefreshProposal(&raw.proposal)
}
func rosterRefreshProgress(_ raw: inout qpc_roster_refresh_progress_v1) throws -> RosterRefreshProgress {
    guard raw.phase <= 5, raw.retired <= 1, [3, 4].contains(raw.phase) || raw.retired == 0,
          withUnsafeBytes(of: &raw.reserved, { $0.allSatisfy { $0 == 0 } }) else { throw ContinuityBoundaryError.malformedOutput }
    if raw.phase == 0 {
        guard withUnsafeBytes(of: &raw, { $0.allSatisfy { $0 == 0 } }) else { throw ContinuityBoundaryError.malformedOutput }
        return .absent
    }
    do {
        guard raw.scope.reserved == 0, raw.scope.has_policy_authorization <= 1 else { throw ContinuityBoundaryError.malformedOutput }
        let bytes = withUnsafeBytes(of: &raw.scope.policy_authorization) { Array($0) }
        let authorization: PolicyAuthorizationID?
        if raw.scope.has_policy_authorization == 1 { authorization = try PolicyAuthorizationID(bytes: bytes) }
        else {
            guard bytes.allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
            authorization = nil
        }
        let scope = try RosterRefreshScope(operation: RosterRefreshID(bytes: withUnsafeBytes(of: &raw.scope.operation) { Array($0) }),
            previous: RosterCheckpoint(version: raw.scope.previous.version, digest: withUnsafeBytes(of: &raw.scope.previous.digest) { Array($0) }),
            target: RosterCheckpoint(version: raw.scope.target.version, digest: withUnsafeBytes(of: &raw.scope.target.digest) { Array($0) }),
            policy: PolicyCheckpoint(version: raw.scope.policy.version, digest: withUnsafeBytes(of: &raw.scope.policy.digest) { Array($0) }),
            policyAuthorization: authorization)
        if raw.phase == 1 || raw.phase == 5 {
            guard withUnsafeBytes(of: &raw.proposal, { $0.allSatisfy { $0 == 0 } }) else { throw ContinuityBoundaryError.malformedOutput }
            return raw.phase == 1 ? .staged(scope) : .abandonedBeforePreparation(scope)
        }
        let proposal = try rosterRefreshProposal(&raw.proposal)
        guard scope == proposal.scope else { throw ContinuityBoundaryError.malformedOutput }
        switch raw.phase {
        case 2: return .reserved(proposal)
        case 3: return .applied(proposal, retired: raw.retired == 1)
        case 4: return .closed(proposal, retired: raw.retired == 1)
        default: throw ContinuityBoundaryError.malformedOutput
        }
    } catch is ContinuityBoundaryError { throw ContinuityBoundaryError.malformedOutput }
}
