// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

/// Original public issuer inputs. Retain the complete request and operation before
/// submitting; retry unknown submissions with those same inputs. This snapshot
/// neither reserves a journal nor authenticates or authorizes an issuer decision.
public struct CredentialRenewalRequest: Sendable, Equatable {
    public let operation: CredentialRenewalID
    public let journal: JournalID
    public let account: AccountID
    public let originalOwner: [UInt8]
    public let originalPolicyDigest: [UInt8]
    public let currentPolicy: PolicyCheckpoint
    public let currentPolicyAuthorization: PolicyAuthorizationID?
    public let previousRosterCheckpoint: RosterCheckpoint
    public let originalRosterCheckpoint: RosterCheckpoint
    public let previousValidFrom: UInt64
    public let previousValidUntil: UInt64
    public let originalCredential: [UInt8]
    public let originalRoster: [UInt8]
    public let previousCredential: [UInt8]
    public let previousRoster: [UInt8]

    init(native raw: inout qpc_credential_renewal_request_v1) throws {
        func bytes<T>(_ value: inout T) -> [UInt8] { withUnsafeBytes(of: &value) { Array($0) } }
        do {
            guard raw.reserved == 0, raw.previous_valid_from < raw.previous_valid_until,
                  raw.previous_valid_until != UInt64.max else { throw ContinuityBoundaryError.malformedOutput }
            operation = try CredentialRenewalID(bytes: bytes(&raw.operation))
            journal = try JournalID(bytes: bytes(&raw.journal)); account = try AccountID(bytes: bytes(&raw.account))
            originalOwner = bytes(&raw.original_owner); originalPolicyDigest = bytes(&raw.original_policy_digest)
            guard [journal.bytes, account.bytes, originalOwner, originalPolicyDigest].allSatisfy({ $0.contains(where: { $0 != 0 }) }) else {
                throw ContinuityBoundaryError.malformedOutput
            }
            currentPolicy = try PolicyCheckpoint(version: raw.current_policy.version, digest: bytes(&raw.current_policy.digest))
            let authorization = bytes(&raw.current_policy_authorization)
            switch raw.has_current_policy_authorization {
            case 0:
                guard authorization.allSatisfy({ $0 == 0 }), currentPolicy.digest == originalPolicyDigest else {
                    throw ContinuityBoundaryError.malformedOutput
                }
                currentPolicyAuthorization = nil
            case 1: currentPolicyAuthorization = try PolicyAuthorizationID(bytes: authorization)
            default: throw ContinuityBoundaryError.malformedOutput
            }
            previousRosterCheckpoint = try renewalCheckpoint(&raw.previous_roster_checkpoint)
            originalRosterCheckpoint = try renewalCheckpoint(&raw.original_roster_checkpoint)
            guard originalRosterCheckpoint.version < previousRosterCheckpoint.version
                    || originalRosterCheckpoint == previousRosterCheckpoint else { throw ContinuityBoundaryError.malformedOutput }
            previousValidFrom = raw.previous_valid_from; previousValidUntil = raw.previous_valid_until
            originalCredential = try policyRecordBytes(&raw.original_credential)
            originalRoster = try policyRecordBytes(&raw.original_roster)
            previousCredential = try policyRecordBytes(&raw.previous_credential)
            previousRoster = try policyRecordBytes(&raw.previous_roster)
        } catch is ContinuityBoundaryError { throw ContinuityBoundaryError.malformedOutput }
    }
}
