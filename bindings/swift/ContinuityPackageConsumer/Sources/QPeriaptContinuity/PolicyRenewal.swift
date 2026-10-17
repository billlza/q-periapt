// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

/// Independent policy-only operation, never a credential-renewal operation.
public struct PolicyRenewalID: Sendable, Equatable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) throws { self.bytes = try policyIdentity(bytes) }
}
/// Exact independent policy statement, distinct from a joint G/T statement.
public struct PolicyRenewalStatementID: Sendable, Equatable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) throws { self.bytes = try policyIdentity(bytes) }
}
/// Previous adopted authorization, either an independent policy statement or joint T.
public struct PolicyAuthorizationID: Sendable, Equatable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) throws { self.bytes = try policyIdentity(bytes) }
}
private func policyIdentity(_ bytes: [UInt8]) throws -> [UInt8] {
    guard bytes.count == 32 else { throw ContinuityBoundaryError.inputLength }
    guard bytes.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
    return bytes
}

/// Retained expected scope. Incoming approvals cannot select these values.
public struct PolicyRenewalScope: Sendable, Equatable {
    public let operation: PolicyRenewalID
    public let journal: JournalID
    public let originalOwner: [UInt8]
    public let originalCredential: [UInt8]
    public let currentCredential: [UInt8]
    public let currentRoster: RosterCheckpoint
    public let originalPolicy: PolicyCheckpoint
    public let previousPolicy: PolicyCheckpoint
    public let previousAuthorization: PolicyAuthorizationID?
    public init(operation: PolicyRenewalID, journal: JournalID, originalOwner: [UInt8],
                originalCredential: [UInt8], currentCredential: [UInt8], currentRoster: RosterCheckpoint,
                originalPolicy: PolicyCheckpoint, previousPolicy: PolicyCheckpoint,
                previousAuthorization: PolicyAuthorizationID?) throws {
        _ = try policyIdentity(journal.bytes)
        self.originalOwner = try policyIdentity(originalOwner)
        self.originalCredential = try policyIdentity(originalCredential)
        self.currentCredential = try policyIdentity(currentCredential)
        guard previousAuthorization == nil ? previousPolicy == originalPolicy : previousPolicy.version > originalPolicy.version else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        self.operation = operation; self.journal = journal; self.currentRoster = currentRoster
        self.originalPolicy = originalPolicy; self.previousPolicy = previousPolicy
        self.previousAuthorization = previousAuthorization
    }
    func native() -> qpc_policy_renewal_scope_v1 {
        var raw = qpc_policy_renewal_scope_v1()
        withUnsafeMutableBytes(of: &raw.operation) { $0.copyBytes(from: operation.bytes) }
        withUnsafeMutableBytes(of: &raw.journal) { $0.copyBytes(from: journal.bytes) }
        withUnsafeMutableBytes(of: &raw.original_owner) { $0.copyBytes(from: originalOwner) }
        withUnsafeMutableBytes(of: &raw.original_credential) { $0.copyBytes(from: originalCredential) }
        withUnsafeMutableBytes(of: &raw.current_credential) { $0.copyBytes(from: currentCredential) }
        raw.current_roster = currentRoster.native()
        raw.original_policy = originalPolicy.native(); raw.previous_policy = previousPolicy.native()
        if let previousAuthorization {
            raw.has_previous_authorization = 1
            withUnsafeMutableBytes(of: &raw.previous_authorization) { $0.copyBytes(from: previousAuthorization.bytes) }
        }
        return raw
    }
}
extension PolicyCheckpoint {
    func native() -> qpc_policy_checkpoint_v1 {
        var raw = qpc_policy_checkpoint_v1(); raw.version = version
        withUnsafeMutableBytes(of: &raw.digest) { $0.copyBytes(from: digest) }; return raw
    }
}
/// Owned signed material and original scope. Construction checks shape only;
/// native staging re-verifies every signature, pin and actual predecessor.
/// Retain these fields and the exact approvals across process restart. No native
/// memory layout is a portable request format or an authorization proof.
public struct PolicyRenewalRequest: Sendable, Equatable {
    public let scope: PolicyRenewalScope
    public let account: AccountID
    public let originalRosterCheckpoint: RosterCheckpoint
    public let originalCredential: [UInt8]
    public let originalRoster: [UInt8]
    public let currentCredential: [UInt8]
    public let currentRoster: [UInt8]
    public init(scope: PolicyRenewalScope, account: AccountID, originalRosterCheckpoint: RosterCheckpoint,
                originalCredential: [UInt8], originalRoster: [UInt8], currentCredential: [UInt8], currentRoster: [UInt8]) throws {
        _ = try policyIdentity(account.bytes)
        guard [originalCredential, originalRoster, currentCredential, currentRoster].allSatisfy({ (1...8192).contains($0.count) }) else {
            throw ContinuityBoundaryError.inputLength
        }
        guard originalRosterCheckpoint.version < scope.currentRoster.version || originalRosterCheckpoint == scope.currentRoster else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        self.scope = scope; self.account = account; self.originalRosterCheckpoint = originalRosterCheckpoint
        self.originalCredential = originalCredential; self.originalRoster = originalRoster
        self.currentCredential = currentCredential; self.currentRoster = currentRoster
    }
    func native() throws -> qpc_policy_renewal_request_v1 {
        var raw = qpc_policy_renewal_request_v1(); raw.scope = scope.native()
        withUnsafeMutableBytes(of: &raw.account) { $0.copyBytes(from: account.bytes) }
        raw.original_roster_checkpoint = originalRosterCheckpoint.native()
        raw.original_credential = try publicPolicyRecord(originalCredential)
        raw.original_roster = try publicPolicyRecord(originalRoster)
        raw.current_credential = try publicPolicyRecord(currentCredential)
        raw.current_roster = try publicPolicyRecord(currentRoster)
        return raw
    }
}
func publicPolicyRecord(_ bytes: [UInt8]) throws -> qpc_public_record_v1 {
    guard (1...8192).contains(bytes.count), MemoryLayout<qpc_public_record_v1>.size == 8196 else {
        throw ContinuityBoundaryError.inputLength
    }
    var raw = qpc_public_record_v1(); raw.length = UInt32(bytes.count)
    // Clang omits the large array member; borrow the exact checked C record.
    withUnsafeMutableBytes(of: &raw) { $0[4..<(4 + bytes.count)].copyBytes(from: bytes) }
    return raw
}
func policyRecordBytes(_ raw: inout qpc_public_record_v1) throws -> [UInt8] {
    guard (1...8192).contains(raw.length) else { throw ContinuityBoundaryError.malformedOutput }
    let length = Int(raw.length)
    return try withUnsafeBytes(of: &raw) { record in
        guard record.count == 8196 else { throw ContinuityBoundaryError.malformedOutput }
        let bytes = record.dropFirst(4)
        guard bytes.dropFirst(length).allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        return Array(bytes.prefix(length))
    }
}
func decodePolicyRenewalScope(_ raw: inout qpc_policy_renewal_scope_v1) throws -> PolicyRenewalScope {
    guard raw.reserved == 0 else { throw ContinuityBoundaryError.malformedOutput }
    func bytes<T>(_ v: inout T) -> [UInt8] { withUnsafeBytes(of: &v) { Array($0) } }
    do {
        let authorization = bytes(&raw.previous_authorization)
        let previous: PolicyAuthorizationID?
        switch raw.has_previous_authorization {
        case 0:
            guard authorization.allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
            previous = nil
        case 1: previous = try PolicyAuthorizationID(bytes: authorization)
        default: throw ContinuityBoundaryError.malformedOutput
        }
        return try PolicyRenewalScope(operation: PolicyRenewalID(bytes: bytes(&raw.operation)),
            journal: JournalID(bytes: bytes(&raw.journal)), originalOwner: bytes(&raw.original_owner),
            originalCredential: bytes(&raw.original_credential), currentCredential: bytes(&raw.current_credential),
            currentRoster: RosterCheckpoint(version: raw.current_roster.version, digest: bytes(&raw.current_roster.digest)),
            originalPolicy: PolicyCheckpoint(version: raw.original_policy.version, digest: bytes(&raw.original_policy.digest)),
            previousPolicy: PolicyCheckpoint(version: raw.previous_policy.version, digest: bytes(&raw.previous_policy.digest)),
            previousAuthorization: previous)
    } catch is ContinuityBoundaryError { throw ContinuityBoundaryError.malformedOutput }
}
func decodePolicyRenewalRequest(_ raw: inout qpc_policy_renewal_request_v1) throws -> PolicyRenewalRequest {
    do {
        return try PolicyRenewalRequest(scope: decodePolicyRenewalScope(&raw.scope),
            account: AccountID(bytes: withUnsafeBytes(of: &raw.account) { Array($0) }),
            originalRosterCheckpoint: RosterCheckpoint(version: raw.original_roster_checkpoint.version,
                digest: withUnsafeBytes(of: &raw.original_roster_checkpoint.digest) { Array($0) }),
            originalCredential: policyRecordBytes(&raw.original_credential), originalRoster: policyRecordBytes(&raw.original_roster),
            currentCredential: policyRecordBytes(&raw.current_credential), currentRoster: policyRecordBytes(&raw.current_roster))
    } catch is ContinuityBoundaryError { throw ContinuityBoundaryError.malformedOutput }
}
public enum PolicyRenewalAbandonment: UInt32, Sendable { case expired = 1, rosterAdvanced = 2 }
/// Authenticated independent policy progress. Pending is not proof of no commit.
public enum PolicyRenewalStatus: Sendable, Equatable {
    case absent
    case pending(operation: PolicyRenewalID, statement: PolicyRenewalStatementID, target: PolicyCheckpoint)
    case committed(operation: PolicyRenewalID, statement: PolicyRenewalStatementID, target: PolicyCheckpoint)
    case abandonedUncommitted(operation: PolicyRenewalID, statement: PolicyRenewalStatementID, target: PolicyCheckpoint,
        reason: PolicyRenewalAbandonment, observedRoster: RosterCheckpoint, observedAt: UInt64)
}
func decodePolicyRenewalStatus(_ raw: inout qpc_policy_renewal_status_v1) throws -> PolicyRenewalStatus {
    let operation = withUnsafeBytes(of: &raw.operation) { Array($0) }, statement = withUnsafeBytes(of: &raw.statement) { Array($0) }
    let target = withUnsafeBytes(of: &raw.target.digest) { Array($0) }, roster = withUnsafeBytes(of: &raw.observed_roster.digest) { Array($0) }
    let noObservation = raw.observed_at == 0 && raw.observed_roster.version == 0 && roster.allSatisfy({ $0 == 0 })
    if raw.phase == 0 {
        guard raw.reason == 0, noObservation, raw.target.version == 0,
              [operation, statement, target].allSatisfy({ $0.allSatisfy({ $0 == 0 }) }) else { throw ContinuityBoundaryError.malformedOutput }
        return .absent
    }
    do {
        let operation = try PolicyRenewalID(bytes: operation), statement = try PolicyRenewalStatementID(bytes: statement)
        let target = try PolicyCheckpoint(version: raw.target.version, digest: target)
        switch raw.phase {
        case 1, 2:
            guard raw.reason == 0, noObservation else { throw ContinuityBoundaryError.malformedOutput }
            return raw.phase == 1 ? .pending(operation: operation, statement: statement, target: target)
                : .committed(operation: operation, statement: statement, target: target)
        case 3:
            guard let reason = PolicyRenewalAbandonment(rawValue: raw.reason), raw.observed_at > 0 else { throw ContinuityBoundaryError.malformedOutput }
            let roster = try RosterCheckpoint(version: raw.observed_roster.version, digest: roster)
            return .abandonedUncommitted(operation: operation, statement: statement, target: target,
                reason: reason, observedRoster: roster, observedAt: raw.observed_at)
        default: throw ContinuityBoundaryError.malformedOutput
        }
    } catch is ContinuityBoundaryError { throw ContinuityBoundaryError.malformedOutput }
}
