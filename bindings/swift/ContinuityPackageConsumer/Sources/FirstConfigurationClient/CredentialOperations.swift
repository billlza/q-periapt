// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity

let credentialModes = [
    "credential-identity", "credential-expired-request", "credential-expired",
    "credential-activation-unmanaged", "credential-activate", "credential-prepare",
    "credential-stage", "credential-stage-refused", "credential-commit",
    "credential-commit-closed", "credential-commit-unmanaged", "credential-commit-unknown",
    "credential-reconcile",
]

func credentialIdentity(_ owner: ContinuityEnrollment) throws -> [UInt8] {
    let status = try owner.status()
    guard let journal = status.journal else { throw ClientError("credential renewal requires the original journal") }
    return status.signingID.bytes + journal.bytes
}

// Same-host public test readback shared with C. Serialize named fields, including
// explicit zero padding; Swift enum layout and native struct padding are private.
func credentialStatusBytes(_ status: CredentialRenewalStatus) -> [UInt8] {
    func row(_ phase: UInt32, _ operation: CredentialRenewalID, _ statement: CredentialRenewalStatementID,
             _ checkpoint: RosterCheckpoint? = nil, _ observed: UInt64 = 0) -> [UInt8] {
        var bytes = hostNumber(phase) + operation.bytes + statement.bytes + [UInt8](repeating: 0, count: 4)
        bytes += hostNumber(checkpoint?.version ?? UInt64(0))
        bytes += checkpoint?.digest ?? [UInt8](repeating: 0, count: 32)
        bytes += hostNumber(observed)
        return bytes
    }
    switch status {
    case .absent: return [UInt8](repeating: 0, count: 120)
    case let .pending(operation, statement): return row(1, operation, statement)
    case let .committed(operation, statement, target): return row(2, operation, statement, target)
    case let .expiredUncommitted(operation, statement, head, at): return row(3, operation, statement, head, at)
    case let .closed(operation, statement, target): return row(4, operation, statement, target)
    }
}

private func stageCredential(_ owner: ContinuityEnrollment, source: URL, refused: Bool) throws -> [UInt8] {
    let operation = try CredentialRenewalID(bytes: exact(source, "credential-operation", 32))
    let pin = try AccountPin(account: AccountID(bytes: exact(source, "trusted-account", 32)),
        root: exact(source, "enrollment-root", 1985), family: exact(source, "family", 32),
        checkpoint: RosterCheckpoint(version: counter(exact(source, "renewal-version", 8)[...]),
                                     digest: exact(source, "renewal-digest", 32)))
    var grant = try load(source, "credential-renewal", 65536)
    if refused {
        grant[grant.count - 1] ^= 1
        try expect(102) { _ = try owner.stageCredentialRenewal(grant: grant, pin: pin, operation: operation) }
        try expect(2) { _ = try owner.status() }
        return hostNumber(UInt32(102))
    }
    return try credentialStatusBytes(owner.stageCredentialRenewal(grant: grant, pin: pin, operation: operation))
}

private func commitCredential(_ owner: ContinuityEnrollment, registry: inout ContinuityAccountAuthority?,
                              source: URL, mode: String) throws -> [UInt8] {
    let operation = try CredentialRenewalID(bytes: exact(source, "credential-operation", 32))
    let statement = try CredentialRenewalStatementID(bytes: exact(source, "credential-statement", 32))
    if mode == "credential-reconcile" {
        return try credentialStatusBytes(owner.reconcileWitnessedCredentialRenewal(operation: operation, statement: statement))
    }
    if mode == "credential-commit-closed" {
        guard let selected = registry else { throw ClientError("credential commit requires the original registry") }
        try selected.close()
        registry = nil
    }
    let expected: Int32?
    switch mode {
    case "credential-commit-closed": expected = 202
    case "credential-commit-unmanaged": expected = 211
    case "credential-commit-unknown": expected = 218
    case "credential-commit": expected = nil
    default: throw ClientError("credential commit mode")
    }
    if let expected {
        try expect(expected) { _ = try owner.commitWitnessedCredentialRenewal(operation: operation, statement: statement) }
        try expect(2) { _ = try owner.status() }
        return hostNumber(UInt32(expected))
    }
    return try credentialStatusBytes(owner.commitWitnessedCredentialRenewal(operation: operation, statement: statement))
}

func credentialOperation(_ owner: ContinuityEnrollment, registry: inout ContinuityAccountAuthority?,
                         device: inout ContinuityDevice?, source: URL, mode: String) throws -> [UInt8] {
    switch mode {
    case "credential-identity": return try credentialIdentity(owner)
    case "credential-expired-request":
        try expect(104) { _ = try owner.request() }
        return hostNumber(UInt32(104))
    case "credential-expired", "credential-activation-unmanaged":
        let expected: Int32 = mode == "credential-expired" ? 104 : 211
        try expect(expected) { _ = try owner.activate() }
        return hostNumber(UInt32(expected))
    case "credential-activate":
        let identity = try credentialIdentity(owner)
        device = try owner.activate()
        try owner.close()
        return identity
    case "credential-prepare": return try owner.prepareWitnessedCredentialRenewal().bytes
    case "credential-stage", "credential-stage-refused":
        return try stageCredential(owner, source: source, refused: mode == "credential-stage-refused")
    default: return try commitCredential(owner, registry: &registry, source: source, mode: mode)
    }
}
