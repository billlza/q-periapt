// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity
import ContinuityConsumerFixtures

let policyCredentialModes = [
    "policy-credential-request", "policy-credential-next-request", "policy-credential-status",
    "policy-credential-stage", "policy-credential-stage-refused", "policy-credential-prepare",
    "policy-credential-commit-unknown", "policy-credential-commit", "policy-credential-reconcile",
    "policy-credential-close", "policy-credential-activate",
]

func policyCredentialOperation(_ owner: ContinuityEnrollment, device: inout ContinuityDevice?,
    source: URL, path: String, recoverable: Bool, carrier: String?, mode: String) throws -> [UInt8] {
    if mode == "policy-credential-status" { return try credentialStatusBytes(owner.credentialRenewalStatus()) }
    let operation = try CredentialRenewalID(bytes: exact(source,
        mode == "policy-credential-next-request" ? "credential-next-operation" : "credential-operation", 32))
    if mode == "policy-credential-request" || mode == "policy-credential-next-request" {
        let request = carrier == nil ? try owner.credentialRenewalRequest(operation: operation)
            : try owner.witnessedCredentialRenewalRequest(operation: operation)
        return CredentialRequestFixture.write(request)
    }
    if mode != "policy-credential-reconcile" && mode != "policy-credential-close" {
        try selectPolicyTarget(owner, source: source, path: path, recoverable: recoverable)
    }
    if mode == "policy-credential-activate" {
        let identity = try credentialIdentity(owner)
        device = try owner.activatePolicyRenewal()
        return identity
    }
    if mode == "policy-credential-stage" || mode == "policy-credential-stage-refused" {
        let pin = try AccountPin(account: AccountID(bytes: exact(source, "trusted-account", 32)),
            root: exact(source, "enrollment-root", 1985), family: exact(source, "family", 32),
            checkpoint: RosterCheckpoint(version: counter(exact(source, "renewal-version", 8)[...]),
                                         digest: exact(source, "renewal-digest", 32)))
        var grant = try load(source, "credential-renewal", 65536)
        if mode == "policy-credential-stage-refused" {
            grant[grant.count - 1] ^= 1
            try expect(102) { _ = try owner.stageContinuedCredentialRenewal(grant: grant, pin: pin, operation: operation) }
            try expect(2) { _ = try owner.status() }
            return hostNumber(UInt32(102))
        }
        return try credentialStatusBytes(owner.stageContinuedCredentialRenewal(grant: grant, pin: pin, operation: operation))
    }
    let statement = try CredentialRenewalStatementID(bytes: exact(source, "credential-statement", 32))
    switch mode {
    case "policy-credential-prepare":
        let proposal = try owner.prepareWitnessedPolicyContinuation()
        guard proposal.operation == operation, proposal.credentialStatement == statement,
              proposal.policyStatement == nil, !proposal.adoptsPolicy,
              proposal.independentPolicyStatement == (try PolicyRenewalStatementID(bytes: exact(source, "renewal-statement", 32))) else {
            throw ClientError("G must retain the independently approved P")
        }
        return proposal.bytes
    case "policy-credential-commit-unknown":
        try expect(218) { _ = try owner.commitWitnessedPolicyContinuation(operation: operation, statement: statement) }
        try expect(2) { _ = try owner.status() }
        return hostNumber(UInt32(218))
    case "policy-credential-commit": return try credentialStatusBytes(owner.commitWitnessedPolicyContinuation(operation: operation, statement: statement))
    case "policy-credential-reconcile": return try credentialStatusBytes(owner.reconcileWitnessedCredentialRenewal(operation: operation, statement: statement))
    case "policy-credential-close": return try credentialStatusBytes(owner.closeWitnessedCredentialRenewal(operation: operation, statement: statement))
    default: throw ClientError("policy credential operation")
    }
}
