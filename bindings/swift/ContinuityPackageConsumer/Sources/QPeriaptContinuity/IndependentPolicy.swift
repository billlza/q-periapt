// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner

/// Complete original policy-only expectation. Parsing these public bytes grants
/// no witness approval or current permission. Persist the complete descriptor;
/// never substitute a descriptor received from an untrusted participant.
public struct IndependentPolicyProposal: Sendable, Equatable {
    public let bytes: [UInt8]
    public let operation: PolicyRenewalID
    public let statement: PolicyRenewalStatementID

    public init(retainedBytes bytes: [UInt8]) throws {
        guard bytes.count == 296 else { throw ContinuityBoundaryError.inputLength }
        guard Array(bytes.prefix(8)) == Array("QPPWNP01".utf8) else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        for offset in [8, 40, 72, 104, 136, 168, 216, 264] {
            guard bytes[offset..<(offset + 32)].contains(where: { $0 != 0 }) else {
                throw ContinuityBoundaryError.invalidEnrollmentInput
            }
        }
        func counter(_ offset: Int) -> UInt64 {
            bytes[offset..<(offset + 8)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }
        let fence = counter(200), revision = counter(208)
        guard fence > 0, fence < UInt64.max, counter(248) == fence,
              revision > 0, revision < UInt64.max - 1, counter(256) == revision + 1,
              bytes[216..<248] != bytes[264..<296] else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        self.bytes = bytes
        operation = try PolicyRenewalID(bytes: Array(bytes[136..<168]))
        statement = try PolicyRenewalStatementID(bytes: Array(bytes[168..<200]))
    }

    func native() -> qpc_independent_policy_proposal_v1 {
        var raw = qpc_independent_policy_proposal_v1()
        withUnsafeMutableBytes(of: &raw.bytes) { $0.copyBytes(from: bytes) }
        return raw
    }
}

/// Exact witness transaction history; no case grants a device or traffic lease.
public enum IndependentPolicyState: UInt32, Sendable {
    case prepared = 1, applied = 2, closed = 3, acknowledged = 4, unavailable = 5
}

/// Local original-operation history. Absence and unavailable witness history do
/// not prove non-commit. Retirement records durable terminal cleanup, not new authority.
public enum IndependentPolicyProgress: Sendable, Equatable {
    case absent
    case reserved(proposal: IndependentPolicyProposal, target: PolicyCheckpoint)
    case applied(proposal: IndependentPolicyProposal, target: PolicyCheckpoint, retired: Bool)
    case closed(proposal: IndependentPolicyProposal, target: PolicyCheckpoint, retired: Bool)
}

func independentPolicyProposal(_ raw: inout qpc_independent_policy_proposal_v1) throws -> IndependentPolicyProposal {
    do {
        return try IndependentPolicyProposal(retainedBytes: withUnsafeBytes(of: &raw.bytes) { Array($0) })
    } catch is ContinuityBoundaryError { throw ContinuityBoundaryError.malformedOutput }
}

func independentPolicyPreparation(_ raw: inout qpc_independent_policy_preparation_v1) throws -> IndependentPolicyProposal? {
    guard raw.reserved == 0, raw.present <= 1 else { throw ContinuityBoundaryError.malformedOutput }
    if raw.present == 0 {
        guard withUnsafeBytes(of: &raw.proposal.bytes, { $0.allSatisfy { $0 == 0 } }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        return nil
    }
    return try independentPolicyProposal(&raw.proposal)
}

func independentPolicyProgress(_ raw: inout qpc_independent_policy_progress_v1) throws -> IndependentPolicyProgress {
    guard raw.phase <= 3, raw.retired <= 1, raw.phase >= 2 || raw.retired == 0 else {
        throw ContinuityBoundaryError.malformedOutput
    }
    if raw.phase == 0 {
        guard withUnsafeBytes(of: &raw, { $0.allSatisfy { $0 == 0 } }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        return .absent
    }
    let proposal = try independentPolicyProposal(&raw.proposal)
    do {
        let target = try PolicyCheckpoint(version: raw.target.version,
            digest: withUnsafeBytes(of: &raw.target.digest) { Array($0) })
        switch raw.phase {
        case 1: return .reserved(proposal: proposal, target: target)
        case 2: return .applied(proposal: proposal, target: target, retired: raw.retired == 1)
        case 3: return .closed(proposal: proposal, target: target, retired: raw.retired == 1)
        default: throw ContinuityBoundaryError.malformedOutput
        }
    } catch is ContinuityBoundaryError { throw ContinuityBoundaryError.malformedOutput }
}
