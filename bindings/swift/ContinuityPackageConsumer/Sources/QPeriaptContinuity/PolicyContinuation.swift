// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

/// Independently retained policy checkpoint, distinct from an account roster.
public struct PolicyCheckpoint: Sendable, Equatable {
    public let version: UInt64
    public let digest: [UInt8]
    public init(version: UInt64, digest: [UInt8]) throws {
        guard digest.count == 32 else { throw ContinuityBoundaryError.inputLength }
        guard version > 0, version < UInt64.max, digest.contains(where: { $0 != 0 }) else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        self.version = version; self.digest = digest
    }
}

/// Signed public policy plus a root/checkpoint supplied through an independent
/// trusted channel. Construction is shape validation; native admission verifies
/// the signature and exact original G/T relationship. No runtime is created here.
public struct PolicyDocument: Sendable, Equatable {
    public let root: [UInt8]
    public let family: [UInt8]
    public let checkpoint: PolicyCheckpoint
    public let wire: [UInt8]
    public init(root: [UInt8], family: [UInt8], checkpoint: PolicyCheckpoint, wire: [UInt8]) throws {
        guard root.count == 1985, family.count == 32, (1...8192).contains(wire.count) else {
            throw ContinuityBoundaryError.inputLength
        }
        guard family.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.root = root; self.family = family; self.checkpoint = checkpoint; self.wire = wire
    }
    func withNative<T>(_ body: (UnsafePointer<qpc_policy_document_v1>) throws -> T) rethrows -> T {
        try root.withUnsafeBufferPointer { root in
            try wire.withUnsafeBufferPointer { wire in
                var value = qpc_policy_document_v1()
                value.root = root.baseAddress; value.root_length = root.count
                value.wire = wire.baseAddress; value.wire_length = wire.count
                value.version = checkpoint.version
                withUnsafeMutableBytes(of: &value.family) { $0.copyBytes(from: family) }
                withUnsafeMutableBytes(of: &value.digest) { $0.copyBytes(from: checkpoint.digest) }
                return try withUnsafePointer(to: &value, body)
            }
        }
    }
}

/// Exact last-adopted policy authorization T, not a version-floor observation.
public struct PolicyContinuationStatementID: Sendable, Equatable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) throws {
        guard bytes.count == 32 else { throw ContinuityBoundaryError.inputLength }
        guard bytes.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.bytes = bytes
    }
}

private func policyMetadata(_ bytes: [UInt8], kind: RenewalMetadataKind) throws
    -> (CredentialRenewalID, CredentialRenewalStatementID, PolicyContinuationStatementID?, Bool) {
    let base = kind == .proposal ? 296 : 248
    let extended = bytes.count == base + 33
    let identity = try renewalMetadataIdentity(bytes, kind: kind, policy: extended)
    if !extended { return (identity.operation, identity.statement, nil, false) }
    guard bytes[base] <= 1, bytes[(base + 1)..<(base + 33)].contains(where: { $0 != 0 }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    return (identity.operation, identity.statement,
        try PolicyContinuationStatementID(bytes: Array(bytes[(base + 1)..<(base + 33)])), bytes[base] == 1)
}

/// Original coordination bytes, not an independent witness approval. An adopting
/// transaction uses T as its statement; a credential-only carry continues to use G.
public struct PolicyRenewalProposal: Sendable, Equatable {
    public let bytes: [UInt8]
    public let operation: CredentialRenewalID
    public let credentialStatement: CredentialRenewalStatementID
    public let policyStatement: PolicyContinuationStatementID?
    public let adoptsPolicy: Bool
    public let statement: CredentialRenewalStatementID
    init(nativeBytes bytes: [UInt8]) throws {
        let (operation, credential, policy, adopts) = try policyMetadata(bytes, kind: .proposal)
        self.bytes = bytes; self.operation = operation; credentialStatement = credential
        policyStatement = policy; adoptsPolicy = adopts
        if adopts {
            guard let policy else { throw ContinuityBoundaryError.malformedOutput }
            statement = try CredentialRenewalStatementID(bytes: policy.bytes)
        } else { statement = credential }
    }
}
/// Exact target-free expectation. Historical cancellation never claims Closed
/// or permission to discard the original transaction before its independent ACK.
public struct PolicyRenewalCancellation: Sendable, Equatable {
    public let bytes: [UInt8]
    public let operation: CredentialRenewalID
    public let credentialStatement: CredentialRenewalStatementID
    public let policyStatement: PolicyContinuationStatementID?
    public let adoptsPolicy: Bool
    public let statement: CredentialRenewalStatementID
    init(nativeBytes bytes: [UInt8]) throws {
        let (operation, credential, policy, adopts) = try policyMetadata(bytes, kind: .cancellation)
        self.bytes = bytes; self.operation = operation; credentialStatement = credential
        policyStatement = policy; adoptsPolicy = adopts
        if adopts {
            guard let policy else { throw ContinuityBoundaryError.malformedOutput }
            statement = try CredentialRenewalStatementID(bytes: policy.bytes)
        } else { statement = credential }
    }
}

// The records contain u32 length and a byte array, followed by ABI padding.
// Padding is not protocol data. Only the array's unused tail must be zero.
func policyProposalBytes(_ raw: inout qpc_policy_renewal_proposal_v1) throws -> [UInt8] {
    let length = Int(raw.length)
    guard length == 296 || length == 329 else { throw ContinuityBoundaryError.malformedOutput }
    return try withUnsafeBytes(of: &raw) { record in
        guard record.count == 336 else { throw ContinuityBoundaryError.malformedOutput }
        let bytes = record.dropFirst(4).prefix(329)
        guard bytes.dropFirst(length).allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        return Array(bytes.prefix(length))
    }
}
func policyCancellationBytes(_ raw: inout qpc_policy_renewal_cancellation_v1) throws -> [UInt8] {
    let length = Int(raw.length)
    guard length == 248 || length == 281 else { throw ContinuityBoundaryError.malformedOutput }
    return try withUnsafeBytes(of: &raw) { record in
        guard record.count == 288 else { throw ContinuityBoundaryError.malformedOutput }
        let bytes = record.dropFirst(4).prefix(281)
        guard bytes.dropFirst(length).allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        return Array(bytes.prefix(length))
    }
}
