// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

/// Original host/root-authority operation, retained across unknown outcomes.
public struct CredentialRenewalID: Sendable, Equatable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) throws {
        guard bytes.count == 32 else { throw ContinuityBoundaryError.inputLength }
        guard bytes.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.bytes = bytes
    }
}
/// Exact authenticated statement identity; randomized signature bytes are excluded.
public struct CredentialRenewalStatementID: Sendable, Equatable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) throws {
        guard bytes.count == 32 else { throw ContinuityBoundaryError.inputLength }
        guard bytes.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.bytes = bytes
    }
}

/// Exact persisted public proposal for independent witness approval. These bytes
/// are metadata, not a capability or current operational permission.
public struct CredentialRenewalProposal: Sendable, Equatable {
    public let bytes: [UInt8]
    public let operation: CredentialRenewalID
    public let statement: CredentialRenewalStatementID

    init(nativeBytes bytes: [UInt8]) throws {
        guard bytes.count == 296, Array(bytes[0..<8]) == Array("QPCRNP01".utf8) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        for offset in [8, 40, 72, 104, 136, 168, 216, 264] {
            guard bytes[offset..<(offset + 32)].contains(where: { $0 != 0 }) else {
                throw ContinuityBoundaryError.malformedOutput
            }
        }
        func counter(_ offset: Int) -> UInt64 {
            bytes[offset..<(offset + 8)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }
        let fence = counter(200), revision = counter(208), target = counter(256)
        guard fence > 0, fence < UInt64.max, counter(248) == fence,
              revision > 0, revision < UInt64.max - 1, target == revision + 1,
              bytes[216..<248] != bytes[264..<296] else {
            throw ContinuityBoundaryError.malformedOutput
        }
        self.bytes = bytes
        operation = try CredentialRenewalID(bytes: Array(bytes[136..<168]))
        statement = try CredentialRenewalStatementID(bytes: Array(bytes[168..<200]))
    }
}

/// Immutable target-free cancellation expectation for independent approval.
/// It neither proves Closed nor grants permission to erase state or use a device.
public struct CredentialRenewalCancellation: Sendable, Equatable {
    public let bytes: [UInt8]
    public let operation: CredentialRenewalID
    public let statement: CredentialRenewalStatementID

    init(nativeBytes bytes: [UInt8]) throws {
        guard bytes.count == 248, Array(bytes[0..<8]) == Array("QPCRNC01".utf8) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        for offset in [8, 40, 72, 104, 136, 168, 216] {
            guard bytes[offset..<(offset + 32)].contains(where: { $0 != 0 }) else {
                throw ContinuityBoundaryError.malformedOutput
            }
        }
        for offset in [200, 208] {
            let value = bytes[offset..<(offset + 8)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            guard value > 0, value < UInt64.max else { throw ContinuityBoundaryError.malformedOutput }
        }
        self.bytes = bytes
        operation = try CredentialRenewalID(bytes: Array(bytes[136..<168]))
        statement = try CredentialRenewalStatementID(bytes: Array(bytes[168..<200]))
    }
}

/// Historical progress only. No case supplies current operational permission.
public enum CredentialRenewalStatus: Sendable, Equatable {
    case absent
    case pending(operation: CredentialRenewalID, statement: CredentialRenewalStatementID)
    case committed(operation: CredentialRenewalID, statement: CredentialRenewalStatementID, target: RosterCheckpoint)
    case closed(operation: CredentialRenewalID, statement: CredentialRenewalStatementID, target: RosterCheckpoint)
    case expiredUncommitted(operation: CredentialRenewalID, statement: CredentialRenewalStatementID,
                            observedHead: RosterCheckpoint, observedAt: UInt64)
}

func renewalCheckpoint(_ raw: inout qpc_roster_checkpoint_v1) throws -> RosterCheckpoint {
    let digest = withUnsafeBytes(of: &raw.digest) { Array($0) }
    guard raw.version > 0, raw.version < UInt64.max, digest.contains(where: { $0 != 0 }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    return try RosterCheckpoint(version: raw.version, digest: digest)
}

func decodeCredentialRenewalStatus(_ raw: inout qpc_credential_renewal_status_v1) throws -> CredentialRenewalStatus {
    let operation = withUnsafeBytes(of: &raw.operation) { Array($0) }
    let statement = withUnsafeBytes(of: &raw.statement) { Array($0) }
    let digest = withUnsafeBytes(of: &raw.checkpoint.digest) { Array($0) }
    guard raw.phase <= 4 else { throw ContinuityBoundaryError.malformedOutput }
    if raw.phase < 2 {
        guard raw.checkpoint.version == 0, digest.allSatisfy({ $0 == 0 }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
    }
    guard raw.phase == 3 ? raw.observed_at != 0 : raw.observed_at == 0 else {
        throw ContinuityBoundaryError.malformedOutput
    }
    if raw.phase == 0 {
        guard operation.allSatisfy({ $0 == 0 }), statement.allSatisfy({ $0 == 0 }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        return .absent
    }
    guard operation.contains(where: { $0 != 0 }), statement.contains(where: { $0 != 0 }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    let id = try CredentialRenewalID(bytes: operation), identity = try CredentialRenewalStatementID(bytes: statement)
    switch raw.phase {
    case 1: return .pending(operation: id, statement: identity)
    case 2: return .committed(operation: id, statement: identity, target: try renewalCheckpoint(&raw.checkpoint))
    case 3:
        return .expiredUncommitted(operation: id, statement: identity,
            observedHead: try renewalCheckpoint(&raw.checkpoint), observedAt: raw.observed_at)
    case 4: return .closed(operation: id, statement: identity, target: try renewalCheckpoint(&raw.checkpoint))
    default: throw ContinuityBoundaryError.malformedOutput
    }
}

public extension ContinuityDevice {
    /// Admit one peer's root grant on the original service. Supply its target pin
    /// independently, retain the exact operation after errors, then explicitly reopen
    /// existing peer children. This cannot renew the local device or replace policy.
    func admitPeerCredentialRenewal(grant: [UInt8], pin: AccountPin,
                                    operation: CredentialRenewalID) throws -> RosterCheckpoint {
        guard (1...65536).contains(grant.count) else { throw ContinuityBoundaryError.inputLength }
        return try call { handle in
            var raw = qpc_roster_checkpoint_v1(), error = qpc_error_v1()
            let code = pin.withNative { pin in
                grant.withUnsafeBufferPointer { grant in
                    operation.bytes.withUnsafeBufferPointer { operation in
                        qpc_device_v1_admit_peer_credential_renewal(handle, grant.baseAddress, grant.count,
                            pin, operation.baseAddress, &raw, &error)
                    }
                }
            }
            try checked(code, &error)
            return try renewalCheckpoint(&raw)
        }
    }
}
