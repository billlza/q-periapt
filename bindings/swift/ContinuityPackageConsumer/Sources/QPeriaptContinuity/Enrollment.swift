// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

public enum SigningKeyTag: Sendable {}
/// Public identity of the original protected signing owner, never key bytes.
public typealias SigningKeyID = ContinuityID<SigningKeyTag>

/// Independently approved account root and exact device grant. The host must
/// authenticate this approval separately from the returned proof-of-possession request.
public struct EnrollmentIntent: Sendable, Equatable {
    public let root: [UInt8]
    public let device: [UInt8]
    public let generation: UInt64
    public let family: [UInt8]
    public let validFrom: UInt64
    public let validUntil: UInt64

    public init(root: [UInt8], device: [UInt8], generation: UInt64, family: [UInt8],
                validFrom: UInt64, validUntil: UInt64) throws {
        guard root.count == 1985, device.count == 16, family.count == 32 else {
            throw ContinuityBoundaryError.inputLength
        }
        guard device.contains(where: { $0 != 0 }), family.contains(where: { $0 != 0 }),
              generation > 0, generation < UInt64.max, validFrom < validUntil,
              validUntil < UInt64.max else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.root = root; self.device = device; self.generation = generation
        self.family = family; self.validFrom = validFrom; self.validUntil = validUntil
    }

    // Each pointer is scoped to one synchronous C call. The C preparation copies
    // this complete intent; no borrowed pointer becomes part of the Swift owner.
    func withNative<T>(_ body: (UnsafePointer<qpc_enrollment_intent_v1>) throws -> T) rethrows -> T {
        try root.withUnsafeBufferPointer { root in
            var value = qpc_enrollment_intent_v1()
            value.root = root.baseAddress; value.root_length = root.count
            value.generation = generation; value.valid_from = validFrom; value.valid_until = validUntil
            withUnsafeMutableBytes(of: &value.device) { $0.copyBytes(from: device) }
            withUnsafeMutableBytes(of: &value.family) { $0.copyBytes(from: family) }
            return try withUnsafePointer(to: &value, body)
        }
    }
}

/// Exact independently retained roster expectation. A checkpoint is not permission.
public struct RosterCheckpoint: Sendable, Equatable {
    public let version: UInt64
    public let digest: [UInt8]
    public init(version: UInt64, digest: [UInt8]) throws {
        guard digest.count == 32 else { throw ContinuityBoundaryError.inputLength }
        guard version > 0, version < UInt64.max, digest.contains(where: { $0 != 0 }) else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        self.version = version; self.digest = digest
    }
    func native() -> qpc_roster_checkpoint_v1 {
        var value = qpc_roster_checkpoint_v1()
        value.version = version
        withUnsafeMutableBytes(of: &value.digest) { $0.copyBytes(from: digest) }
        return value
    }
}

/// Current account/root/roster expectation from an independent trusted channel.
/// Never select these values from the untrusted response being admitted.
public struct AccountPin: Sendable, Equatable {
    public let account: AccountID
    public let root: [UInt8]
    public let family: [UInt8]
    public let checkpoint: RosterCheckpoint
    public init(account: AccountID, root: [UInt8], family: [UInt8], checkpoint: RosterCheckpoint) throws {
        guard root.count == 1985, family.count == 32 else { throw ContinuityBoundaryError.inputLength }
        guard account.bytes.contains(where: { $0 != 0 }), family.contains(where: { $0 != 0 }) else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        self.account = account; self.root = root; self.family = family; self.checkpoint = checkpoint
    }
    func withNative<T>(_ body: (UnsafePointer<qpc_account_pin_v1>) throws -> T) rethrows -> T {
        try root.withUnsafeBufferPointer { root in
            var value = qpc_account_pin_v1()
            value.root = root.baseAddress; value.root_length = root.count
            value.checkpoint = checkpoint.native()
            withUnsafeMutableBytes(of: &value.account) { $0.copyBytes(from: account.bytes) }
            withUnsafeMutableBytes(of: &value.family) { $0.copyBytes(from: family) }
            return try withUnsafePointer(to: &value, body)
        }
    }
}

public enum EnrollmentPhase: UInt32, Sendable {
    case preparing = 1, requested = 2, accepted = 3, activating = 4, active = 5, refreshing = 6, rosterResolved = 7
}
/// Authenticated durable progress, not a live authorization or successful activation receipt.
public struct EnrollmentStatus: Sendable, Equatable {
    public let phase: EnrollmentPhase
    public let signingID: SigningKeyID
    /// Absent only in Preparing and Requested.
    public let journal: JournalID?
    /// Original checkpoint pair exists in Refreshing and RosterResolved.
    public let previous: RosterCheckpoint?
    public let next: RosterCheckpoint?
}

func enrollmentStatus(_ raw: inout qpc_enrollment_status_v1) throws -> EnrollmentStatus {
    let signing = withUnsafeBytes(of: &raw.signing_id) { Array($0) }
    let journal = withUnsafeBytes(of: &raw.journal) { Array($0) }
    guard let phase = EnrollmentPhase(rawValue: raw.phase), signing.contains(where: { $0 != 0 }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    let hasJournal = phase != .preparing && phase != .requested
    guard hasJournal ? journal.contains(where: { $0 != 0 }) : journal.allSatisfy({ $0 == 0 }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    func checkpoint(_ raw: inout qpc_roster_checkpoint_v1) throws -> RosterCheckpoint? {
        let bytes = withUnsafeBytes(of: &raw.digest) { Array($0) }
        if phase != .refreshing && phase != .rosterResolved {
            guard raw.version == 0, bytes.allSatisfy({ $0 == 0 }) else {
                throw ContinuityBoundaryError.malformedOutput
            }
            return nil
        }
        guard raw.version > 0, raw.version < UInt64.max, bytes.contains(where: { $0 != 0 }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        return try RosterCheckpoint(version: raw.version, digest: bytes)
    }
    let previous = try checkpoint(&raw.previous), next = try checkpoint(&raw.next)
    if phase == .refreshing || phase == .rosterResolved {
        guard let previous, let next, next.version > previous.version else {
            throw ContinuityBoundaryError.malformedOutput
        }
    }
    return EnrollmentStatus(phase: phase, signingID: try SigningKeyID(bytes: signing),
        journal: hasJournal ? try JournalID(bytes: journal) : nil, previous: previous, next: next)
}

func enrollmentRequest(_ raw: inout qpc_enrollment_request_v1) throws -> [UInt8] {
    guard (1...8192).contains(raw.length) else { throw ContinuityBoundaryError.malformedOutput }
    let length = Int(raw.length)
    // Clang's Swift importer omits this 8192-byte C array member. Borrow the
    // complete imported record, whose checked ABI is u32 length + u8[8192].
    // No pointer escapes and no raw memory is rebound to another type.
    return try withUnsafeBytes(of: &raw) { record in
        let header = MemoryLayout<UInt32>.size
        guard record.count == header + 8192 else { throw ContinuityBoundaryError.malformedOutput }
        let bytes = record.dropFirst(header)
        guard bytes.dropFirst(length).allSatisfy({ $0 == 0 }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        return Array(bytes.prefix(length))
    }
}

/// Original registration, retaining the native transaction until explicit close
/// or successful transfer to a device. No method recreates missing active state.
public final class ContinuityEnrollment: Sendable {
    private let reference: OwnerTransferReference
    private init(_ native: NativeOwner) { reference = OwnerTransferReference(native, label: "enrollment") }

    /// Explicit first-use key creation. An unknown result may have published the
    /// original key; never delete/recreate it or use this to repair a missing active key.
    public static func provisionWrappingKey(path: String) throws {
        let bytes = try textBytes(path, maximum: 4096)
        var error = qpc_error_v1()
        let code = bytes.withUnsafeBufferPointer {
            qpc_enrollment_v1_provision_wrapping_key($0.baseAddress, $0.count, &error)
        }
        try checked(code, &error)
    }
    private static func prepare(path: String, intent: EnrollmentIntent, witness: WitnessCarrier,
                                selection: SetupIntent) throws -> ContinuityEnrollment {
        try ContinuityEnrollment(NativeOwner.prepare(path: path, kind: 3, quality: 0,
            witness: witness, enrollment: (selection, intent)))
    }
    /// Copy the complete approved intent without I/O. finishOpen commits its original identity.
    public static func prepareCreate(path: String, intent: EnrollmentIntent,
                                     witness: WitnessCarrier = .local) throws -> ContinuityEnrollment {
        try prepare(path: path, intent: intent, witness: witness, selection: .create)
    }
    /// Copy original restart inputs. finishOpen refuses absent or mismatched state.
    public static func prepareResume(path: String, intent: EnrollmentIntent,
                                     witness: WitnessCarrier = .local) throws -> ContinuityEnrollment {
        try prepare(path: path, intent: intent, witness: witness, selection: .resume)
    }
    public static func create(path: String, intent: EnrollmentIntent,
                              witness: WitnessCarrier = .local) throws -> ContinuityEnrollment {
        let owner = try prepareCreate(path: path, intent: intent, witness: witness)
        try owner.finishOpen()
        return owner
    }
    public static func resume(path: String, intent: EnrollmentIntent,
                              witness: WitnessCarrier = .local) throws -> ContinuityEnrollment {
        let owner = try prepareResume(path: path, intent: intent, witness: witness)
        try owner.finishOpen()
        return owner
    }
    public func finishOpen() throws { try reference.call { try $0.finishOpen() } }
    public func cancel() throws { try reference.call(cancellation: true) { try $0.cancel() } }
    /// Successful transfer makes this harmless to the returned device. Before
    /// transfer, Busy preserves the owner; join active work before closing it.
    public func close() throws { try reference.close() }
    public func status() throws -> EnrollmentStatus {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_enrollment_status_v1(), error = qpc_error_v1()
                try checked(qpc_enrollment_v1_status(handle, &raw, &error), &error)
                return try enrollmentStatus(&raw)
            }
        }
    }
    /// Resolve the original pair without granting a device or requiring a live
    /// runtime/private signer. A higher actual head preserves unknown past adoption.
    /// After an admitted failure, close/resume and retry this same pair.
    public func resolveRosterRefresh(previous: RosterCheckpoint, target: RosterCheckpoint) throws -> RosterRefreshResolution {
        try reference.call { native in
            try native.call { handle in
                var before = previous.native(), next = target.native()
                var raw = qpc_roster_refresh_resolution_v1(), error = qpc_error_v1()
                try checked(qpc_enrollment_v1_resolve_roster_refresh(handle, &before, &next, &raw, &error), &error)
                return try decodeRosterRefreshResolution(&raw)
            }
        }
    }
    /// Prepare the original same-credential roster target under an explicit current policy.
    /// Independent witness approval is still required. Retain the complete returned proposal.
    public func prepareWitnessedRosterRefresh(operation: RosterRefreshID, policySource: RosterPolicySource,
        certificate: [UInt8], roster: [UInt8], pin: AccountPin) throws -> RosterRefreshProposal {
        guard (1...8192).contains(certificate.count), (1...8192).contains(roster.count) else {
            throw ContinuityBoundaryError.inputLength
        }
        return try reference.call { native in try native.call { handle in
            var raw = qpc_roster_refresh_proposal_v1(), error = qpc_error_v1()
            let code = operation.bytes.withUnsafeBufferPointer { operation in
                certificate.withUnsafeBufferPointer { certificate in
                    roster.withUnsafeBufferPointer { roster in
                        pin.withNative { pin in
                            var target = qpc_roster_refresh_target_v1(certificate: certificate.baseAddress,
                                certificate_length: certificate.count, roster: roster.baseAddress,
                                roster_length: roster.count, pin: pin)
                            return qpc_enrollment_v1_prepare_witnessed_roster_refresh(handle, operation.baseAddress,
                                policySource.rawValue, &target, &raw, &error)
                        }
                    }
                }
            }
            try checked(code, &error); return try rosterRefreshProposal(&raw)
        } }
    }
    /// Nil is local absence only; it is not witness Closed or proof of no commit.
    public func recoverWitnessedRosterRefreshPreparation() throws -> RosterRefreshProposal? {
        try reference.call { native in try native.call { handle in
            var raw = qpc_roster_refresh_preparation_v1(), error = qpc_error_v1()
            try checked(qpc_enrollment_v1_recover_witnessed_roster_refresh_preparation(handle, &raw, &error), &error)
            return try rosterRefreshPreparation(&raw)
        } }
    }
    /// Historical original-operation metadata, without current runtime or private signer.
    public func witnessedRosterRefreshProgress() throws -> RosterRefreshProgress {
        try reference.call { native in try native.call { handle in
            var raw = qpc_roster_refresh_progress_v1(), error = qpc_error_v1()
            try checked(qpc_enrollment_v1_witnessed_roster_refresh_progress(handle, &raw, &error), &error)
            return try rosterRefreshProgress(&raw)
        } }
    }
    /// Allowed only before a proposal was released and when original pending state is absent.
    public func abandonUnpreparedRosterRefresh(operation: RosterRefreshID) throws -> RosterRefreshProgress {
        try reference.call { native in try native.call { handle in
            var raw = qpc_roster_refresh_progress_v1(), error = qpc_error_v1()
            let code = operation.bytes.withUnsafeBufferPointer {
                qpc_enrollment_v1_abandon_unprepared_roster_refresh(handle, $0.baseAddress, &raw, &error)
            }
            try checked(code, &error); return try rosterRefreshProgress(&raw)
        } }
    }
    public func commitWitnessedRosterRefresh(_ proposal: RosterRefreshProposal,
        policySource: RosterPolicySource) throws -> RosterRefreshState {
        try rosterRefreshCommand(proposal) { qpc_enrollment_v1_commit_witnessed_roster_refresh($0, $1, policySource.rawValue, $2, $3) }
    }
    /// Original terminal history is retained durably before witness ACK and cleanup.
    public func reconcileWitnessedRosterRefresh(_ proposal: RosterRefreshProposal) throws -> RosterRefreshState {
        try rosterRefreshCommand(proposal) { qpc_enrollment_v1_reconcile_witnessed_roster_refresh($0, $1, $2, $3) }
    }
    public func closeWitnessedRosterRefresh(_ proposal: RosterRefreshProposal) throws -> RosterRefreshState {
        try rosterRefreshCommand(proposal) { qpc_enrollment_v1_close_witnessed_roster_refresh($0, $1, $2, $3) }
    }
    private func rosterRefreshCommand(_ proposal: RosterRefreshProposal,
        _ invoke: (UInt64, UnsafePointer<qpc_roster_refresh_proposal_v1>, UnsafeMutablePointer<UInt32>, UnsafeMutablePointer<qpc_error_v1>) -> Int32) throws -> RosterRefreshState {
        try reference.call { native in try native.call { handle in
            var raw = proposal.native(), observed: UInt32 = 0, error = qpc_error_v1()
            try checked(invoke(handle, &raw, &observed, &error), &error)
            guard let state = RosterRefreshState(rawValue: observed) else { throw ContinuityBoundaryError.malformedOutput }
            return state
        } }
    }
    /// Actual independent-policy scope and signed identities; this reserves nothing.
    public func policyRenewalRequest(operation: PolicyRenewalID) throws -> PolicyRenewalRequest {
        try independentPolicyRequest(operation) { qpc_enrollment_v1_policy_renewal_request($0, $1, $2, $3) }
    }
    /// Required-witness request from the original installation. No local fallback.
    public func witnessedPolicyRenewalRequest(operation: PolicyRenewalID) throws -> PolicyRenewalRequest {
        try independentPolicyRequest(operation) { qpc_enrollment_v1_witnessed_policy_renewal_request($0, $1, $2, $3) }
    }
    private func independentPolicyRequest(_ operation: PolicyRenewalID,
        _ invoke: (UInt64, UnsafePointer<UInt8>?, UnsafeMutablePointer<qpc_policy_renewal_request_v1>,
                   UnsafeMutablePointer<qpc_error_v1>) -> Int32) throws -> PolicyRenewalRequest {
        try reference.call { native in try native.call { handle in
            // The C contract initializes the complete 33-KiB record only on
            // success. Keep it off cooperative worker stacks and never read or
            // deinitialize the untouched allocation after a failed native call.
            let raw = UnsafeMutablePointer<qpc_policy_renewal_request_v1>.allocate(capacity: 1)
            defer { raw.deallocate() }
            var error = qpc_error_v1()
            let code = operation.bytes.withUnsafeBufferPointer {
                invoke(handle, $0.baseAddress, raw, &error)
            }
            defer { if code == QPC_OK { raw.deinitialize(count: 1) } }
            try checked(code, &error); return try decodePolicyRenewalRequest(&raw.pointee)
        } }
    }
    /// Select the current target first; repeated preparation retains the same
    /// sealed target. The returned proposal still needs independent witness approval.
    public func prepareWitnessedPolicyRenewal(previous: PolicyDocument) throws -> IndependentPolicyProposal {
        try reference.call { native in try native.call { handle in
            var raw = qpc_independent_policy_proposal_v1(), error = qpc_error_v1()
            let code = previous.withNative { qpc_enrollment_v1_prepare_witnessed_policy_renewal(handle, $0, &raw, &error) }
            try checked(code, &error); return try independentPolicyProposal(&raw)
        } }
    }
    /// Local original descriptor only; nil is local absence, never proof of no commit.
    public func recoverWitnessedPolicyRenewalPreparation() throws -> IndependentPolicyProposal? {
        try reference.call { native in try native.call { handle in
            var raw = qpc_independent_policy_preparation_v1(), error = qpc_error_v1()
            try checked(qpc_enrollment_v1_recover_witnessed_policy_renewal_preparation(handle, &raw, &error), &error)
            return try independentPolicyPreparation(&raw)
        } }
    }
    /// Historical metadata without current runtime, private signer or application TLS.
    public func witnessedPolicyRenewalProgress() throws -> IndependentPolicyProgress {
        try reference.call { native in try native.call { handle in
            var raw = qpc_independent_policy_progress_v1(), error = qpc_error_v1()
            try checked(qpc_enrollment_v1_witnessed_policy_renewal_progress(handle, &raw, &error), &error)
            return try independentPolicyProgress(&raw)
        } }
    }
    private func independentPolicyCommand(_ proposal: IndependentPolicyProposal,
        _ invoke: (UInt64, UnsafePointer<qpc_independent_policy_proposal_v1>, UnsafeMutablePointer<UInt32>,
                   UnsafeMutablePointer<qpc_error_v1>) -> Int32) throws -> IndependentPolicyState {
        try reference.call { native in try native.call { handle in
            var raw = proposal.native(), observed: UInt32 = 0, error = qpc_error_v1()
            try checked(invoke(handle, &raw, &observed, &error), &error)
            guard let state = IndependentPolicyState(rawValue: observed) else { throw ContinuityBoundaryError.malformedOutput }
            return state
        } }
    }
    /// Commit exactly the independently approved target under current authorization.
    public func commitWitnessedPolicyRenewal(_ proposal: IndependentPolicyProposal) throws -> IndependentPolicyState {
        try independentPolicyCommand(proposal) { qpc_enrollment_v1_commit_witnessed_policy_renewal($0, $1, $2, $3) }
    }
    /// Recover the original disposition; persist its terminal before ACK/cleanup.
    public func reconcileWitnessedPolicyRenewal(_ proposal: IndependentPolicyProposal) throws -> IndependentPolicyState {
        try independentPolicyCommand(proposal) { qpc_enrollment_v1_reconcile_witnessed_policy_renewal($0, $1, $2, $3) }
    }
    /// Close only this original proposal; historical outcome grants no new authority.
    public func closeWitnessedPolicyRenewal(_ proposal: IndependentPolicyProposal) throws -> IndependentPolicyState {
        try independentPolicyCommand(proposal) { qpc_enrollment_v1_close_witnessed_policy_renewal($0, $1, $2, $3) }
    }
    private func independentPolicyStatus(_ invoke: (UInt64, UnsafeMutablePointer<qpc_policy_renewal_status_v1>,
        UnsafeMutablePointer<qpc_error_v1>) throws -> Int32) throws -> PolicyRenewalStatus {
        try reference.call { native in try native.call { handle in
            var raw = qpc_policy_renewal_status_v1(), error = qpc_error_v1()
            try checked(invoke(handle, &raw, &error), &error)
            return try decodePolicyRenewalStatus(&raw)
        } }
    }
    public func policyRenewalStatus() throws -> PolicyRenewalStatus {
        try independentPolicyStatus { qpc_enrollment_v1_policy_renewal_status($0, $1, $2) }
    }
    /// Reuses a retained request after Pending or unknown result; never recreates it.
    /// Select the independently pinned current target before staging or activation.
    public func stagePolicyRenewal(request: PolicyRenewalRequest, originalPin: AccountPin, currentPin: AccountPin,
        approvals: [UInt8], previous: PolicyDocument) throws -> PolicyRenewalStatus {
        guard approvals.count == 7618 else { throw ContinuityBoundaryError.inputLength }
        return try independentPolicyStatus { handle, status, error in
            var raw = try request.native()
            return originalPin.withNative { originalPin in currentPin.withNative { currentPin in
                previous.withNative { previous in approvals.withUnsafeBufferPointer { approvals in
                    qpc_enrollment_v1_stage_policy_renewal(handle, &raw, originalPin, currentPin,
                        approvals.baseAddress, approvals.count, previous, status, error)
                } }
            } }
        }
    }
    /// Exact first saved signatures of Pending, for the original operation only.
    public func pendingPolicyRenewalApproval(operation: PolicyRenewalID) throws -> [UInt8] {
        try reference.call { native in try native.call { handle in
            var raw = qpc_public_record_v1(), error = qpc_error_v1()
            let code = operation.bytes.withUnsafeBufferPointer {
                qpc_enrollment_v1_pending_policy_renewal_approval(handle, $0.baseAddress, &raw, &error)
            }
            try checked(code, &error)
            let bytes = try policyRecordBytes(&raw)
            guard bytes.count == 7618 else { throw ContinuityBoundaryError.malformedOutput }
            return bytes
        } }
    }
    public func reconcilePolicyRenewal() throws -> PolicyRenewalStatus {
        try independentPolicyStatus { qpc_enrollment_v1_reconcile_policy_renewal($0, $1, $2) }
    }
    /// Historical result only; no runtime selection, private signer, TLS or Device.
    public func resolvePolicyRenewal(operation: PolicyRenewalID, statement: PolicyRenewalStatementID,
        target: PolicyDocument) throws -> PolicyRenewalStatus {
        try independentPolicyStatus { handle, status, error in
            operation.bytes.withUnsafeBufferPointer { operation in statement.bytes.withUnsafeBufferPointer { statement in
                target.withNative { target in
                    qpc_enrollment_v1_resolve_policy_renewal(handle, operation.baseAddress, statement.baseAddress,
                        target, status, error)
                }
            } }
        }
    }
    /// Transfers the same controlled native owner only after current native checks.
    /// Failed activation retains this wrapper for close and original-state resume.
    public func activatePolicyRenewal() throws -> ContinuityDevice {
        try reference.transfer { native in
            let device = ContinuityDevice.activated(native)
            try native.call { handle in
                var error = qpc_error_v1()
                try checked(qpc_enrollment_v1_activate_policy_renewal(handle, &error), &error)
            }
            return device
        }
    }
    /// Passive original-operation history; does not load SDK policy or TLS inputs.
    public func credentialRenewalStatus() throws -> CredentialRenewalStatus {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_credential_renewal_status_v1(), error = qpc_error_v1()
                try checked(qpc_enrollment_v1_credential_renewal_status(handle, &raw, &error), &error)
                return try decodeCredentialRenewalStatus(&raw)
            }
        }
    }
    /// Retain the exact grant and original operation before activation. An admitted
    /// native failure consumes this registration owner; close and resume its record.
    public func stageCredentialRenewal(grant: [UInt8], pin: AccountPin,
                                       operation: CredentialRenewalID) throws -> CredentialRenewalStatus {
        guard (1...65536).contains(grant.count) else { throw ContinuityBoundaryError.inputLength }
        return try reference.call { native in
            try native.call { handle in
                var raw = qpc_credential_renewal_status_v1(), error = qpc_error_v1()
                let code = pin.withNative { pin in
                    grant.withUnsafeBufferPointer { grant in
                        operation.bytes.withUnsafeBufferPointer { operation in
                            qpc_enrollment_v1_stage_credential_renewal(handle, grant.baseAddress, grant.count,
                                pin, operation.baseAddress, &raw, &error)
                        }
                    }
                }
                try checked(code, &error)
                return try decodeCredentialRenewalStatus(&raw)
            }
        }
    }
    /// Reconcile an exact expired target under the original policy. A retained
    /// commit remains Committed. This returns no device and never restages an intent.
    public func reconcileExpiredCredentialRenewal(operation: CredentialRenewalID,
        statement: CredentialRenewalStatementID) throws -> CredentialRenewalStatus {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_credential_renewal_status_v1(), error = qpc_error_v1()
                let code = operation.bytes.withUnsafeBufferPointer { operation in
                    statement.bytes.withUnsafeBufferPointer { statement in
                        qpc_enrollment_v1_reconcile_expired_credential_renewal(handle, operation.baseAddress,
                            statement.baseAddress, &raw, &error)
                    }
                }
                try checked(code, &error)
                return try decodeCredentialRenewalStatus(&raw)
            }
        }
    }
    /// Recover or prepare the exact original target for independent witness approval.
    public func prepareWitnessedCredentialRenewal() throws -> CredentialRenewalProposal {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_credential_renewal_proposal_v1(), error = qpc_error_v1()
                try checked(qpc_enrollment_v1_prepare_witnessed_credential_renewal(handle, &raw, &error), &error)
                return try CredentialRenewalProposal(nativeBytes: withUnsafeBytes(of: &raw.bytes) { Array($0) })
            }
        }
    }
    /// Reserve the staged grant without a target or witness dispatch. Independent
    /// approval and historical reconciliation must finish before journal work resumes.
    public func prepareWitnessedCredentialCancellation() throws -> CredentialRenewalCancellation {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_credential_renewal_cancellation_v1(), error = qpc_error_v1()
                try checked(qpc_enrollment_v1_prepare_witnessed_credential_cancellation(handle, &raw, &error), &error)
                return try CredentialRenewalCancellation(nativeBytes: withUnsafeBytes(of: &raw.bytes) { Array($0) })
            }
        }
    }
    /// A new Commit requires current authority. A retained terminal is history only.
    public func commitWitnessedCredentialRenewal(operation: CredentialRenewalID,
        statement: CredentialRenewalStatementID) throws -> CredentialRenewalStatus {
        try witnessedCredentialRenewal(operation: operation, statement: statement,
            invoke: qpc_enrollment_v1_commit_witnessed_credential_renewal)
    }
    /// Close the exact target. A competing Applied outcome remains Committed.
    public func closeWitnessedCredentialRenewal(operation: CredentialRenewalID,
        statement: CredentialRenewalStatementID) throws -> CredentialRenewalStatus {
        try witnessedCredentialRenewal(operation: operation, statement: statement,
            invoke: qpc_enrollment_v1_close_witnessed_credential_renewal)
    }
    /// Historical recovery sends neither Commit nor Close and releases no device.
    public func reconcileWitnessedCredentialRenewal(operation: CredentialRenewalID,
        statement: CredentialRenewalStatementID) throws -> CredentialRenewalStatus {
        try witnessedCredentialRenewal(operation: operation, statement: statement,
            invoke: qpc_enrollment_v1_reconcile_witnessed_credential_renewal)
    }
    private func witnessedCredentialRenewal(operation: CredentialRenewalID,
        statement: CredentialRenewalStatementID,
        invoke: (UInt64, UnsafePointer<UInt8>?, UnsafePointer<UInt8>?,
                 UnsafeMutablePointer<qpc_credential_renewal_status_v1>?, UnsafeMutablePointer<qpc_error_v1>?) -> Int32
    ) throws -> CredentialRenewalStatus {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_credential_renewal_status_v1(), error = qpc_error_v1()
                let code = operation.bytes.withUnsafeBufferPointer { operation in
                    statement.bytes.withUnsafeBufferPointer { statement in
                        invoke(handle, operation.baseAddress, statement.baseAddress, &raw, &error)
                    }
                }
                try checked(code, &error)
                return try decodeCredentialRenewalStatus(&raw)
            }
        }
    }
    /// Select once per resumed registration. Native retains the complete SDK
    /// runtime owner; the explicit policy pin is independent of approval bytes.
    /// Selection writes no renewal and grants no operating service.
    public func selectContinuedPolicy(path: String, target: PolicyDocument) throws {
        let path = try textBytes(path, maximum: 4096)
        try reference.call { native in
            try native.call { handle in
                var error = qpc_error_v1()
                let code = target.withNative { target in
                    path.withUnsafeBufferPointer { path in
                        qpc_enrollment_v1_select_continued_policy(handle, path.baseAddress, path.count, target, &error)
                    }
                }
                try checked(code, &error)
            }
        }
    }
    /// Stage the exact G and both signed approvals. Previous policy and T come
    /// from retained independent state; nil previous T means original P0 only.
    public func stagePolicyContinuation(grant: [UInt8], pin: AccountPin, operation: CredentialRenewalID,
        approvals: [UInt8], previous: PolicyDocument, previousAuthorization: PolicyContinuationStatementID?
    ) throws -> CredentialRenewalStatus {
        guard (1...65536).contains(grant.count), (1...7746).contains(approvals.count) else {
            throw ContinuityBoundaryError.inputLength
        }
        return try reference.call { native in
            try native.call { handle in
                var raw = qpc_credential_renewal_status_v1(), error = qpc_error_v1()
                let invoke: (UnsafePointer<UInt8>?) -> Int32 = { previousT in
                    pin.withNative { pin in
                        previous.withNative { previous in
                            grant.withUnsafeBufferPointer { grant in
                                operation.bytes.withUnsafeBufferPointer { operation in
                                    approvals.withUnsafeBufferPointer { approvals in
                                        qpc_enrollment_v1_stage_policy_continuation(handle, grant.baseAddress, grant.count,
                                            pin, operation.baseAddress, approvals.baseAddress, approvals.count,
                                            previous, previousT, &raw, &error)
                                    }
                                }
                            }
                        }
                    }
                }
                let code = previousAuthorization.map { value in
                    value.bytes.withUnsafeBufferPointer { invoke($0.baseAddress) }
                } ?? invoke(nil)
                try checked(code, &error)
                return try decodeCredentialRenewalStatus(&raw)
            }
        }
    }
    /// Stage a credential-only successor under the actual adopted T and selected P1.
    public func stageContinuedCredentialRenewal(grant: [UInt8], pin: AccountPin,
        operation: CredentialRenewalID) throws -> CredentialRenewalStatus {
        guard (1...65536).contains(grant.count) else { throw ContinuityBoundaryError.inputLength }
        return try reference.call { native in
            try native.call { handle in
                var raw = qpc_credential_renewal_status_v1(), error = qpc_error_v1()
                let code = pin.withNative { pin in
                    grant.withUnsafeBufferPointer { grant in
                        operation.bytes.withUnsafeBufferPointer { operation in
                            qpc_enrollment_v1_stage_continued_credential_renewal(handle, grant.baseAddress, grant.count,
                                pin, operation.baseAddress, &raw, &error)
                        }
                    }
                }
                try checked(code, &error)
                return try decodeCredentialRenewalStatus(&raw)
            }
        }
    }
    /// Original G/T coordination metadata for independent witness approval.
    public func prepareWitnessedPolicyContinuation() throws -> PolicyRenewalProposal {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_policy_renewal_proposal_v1(), error = qpc_error_v1()
                try checked(qpc_enrollment_v1_prepare_witnessed_policy_continuation(handle, &raw, &error), &error)
                return try PolicyRenewalProposal(nativeBytes: policyProposalBytes(&raw))
            }
        }
    }
    /// Historical target-free reservation. This sends no witness command and
    /// needs no selected current runtime; its result is not a terminal fact.
    public func prepareWitnessedPolicyCancellation() throws -> PolicyRenewalCancellation {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_policy_renewal_cancellation_v1(), error = qpc_error_v1()
                try checked(qpc_enrollment_v1_prepare_witnessed_policy_cancellation(handle, &raw, &error), &error)
                return try PolicyRenewalCancellation(nativeBytes: policyCancellationBytes(&raw))
            }
        }
    }
    /// Reconcile the original local transaction; a new commit requires selected P1.
    public func reconcilePolicyContinuation() throws -> CredentialRenewalStatus {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_credential_renewal_status_v1(), error = qpc_error_v1()
                try checked(qpc_enrollment_v1_reconcile_policy_continuation(handle, &raw, &error), &error)
                return try decodeCredentialRenewalStatus(&raw)
            }
        }
    }
    /// Reconcile history first, then commit only a still-Pending exact proposal
    /// with independently selected current P1. Terminal cleanup needs no selection.
    public func commitWitnessedPolicyContinuation(operation: CredentialRenewalID,
        statement: CredentialRenewalStatementID) throws -> CredentialRenewalStatus {
        try witnessedCredentialRenewal(operation: operation, statement: statement,
            invoke: qpc_enrollment_v1_commit_witnessed_policy_continuation)
    }
    /// Complete only an existing local journal commit using independently pinned
    /// P1 history. Needs no current SDK/TLS files, creates no target or Device,
    /// and leaves an uncommitted Pending suspended for explicit later resolution.
    public func recoverHistoricalPolicyContinuation(operation: CredentialRenewalID,
        statement: CredentialRenewalStatementID, target: PolicyDocument) throws -> CredentialRenewalStatus {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_credential_renewal_status_v1(), error = qpc_error_v1()
                let code = target.withNative { target in
                    operation.bytes.withUnsafeBufferPointer { operation in
                        statement.bytes.withUnsafeBufferPointer { statement in
                            qpc_enrollment_v1_recover_historical_policy_continuation(handle,
                                operation.baseAddress, statement.baseAddress, target, &raw, &error)
                        }
                    }
                }
                try checked(code, &error)
                return try decodeCredentialRenewalStatus(&raw)
            }
        }
    }
    /// Return owned public request bytes only after native persistence/readback.
    /// Retrying returns the original bytes; possession is not account approval.
    public func request() throws -> [UInt8] {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_enrollment_request_v1(), error = qpc_error_v1()
                try checked(qpc_enrollment_v1_request(handle, &raw, &error), &error)
                return try enrollmentRequest(&raw)
            }
        }
    }
    /// Admit an untrusted signed response under a separately approved current pin.
    /// This persists the original journal identity; it does not release a device.
    public func accept(certificate: [UInt8], roster: [UInt8], pin: AccountPin) throws -> JournalID {
        guard (1...8192).contains(certificate.count), (1...8192).contains(roster.count) else {
            throw ContinuityBoundaryError.inputLength
        }
        return try reference.call { native in
            try native.call { handle in
                var journal = [UInt8](repeating: 0, count: 32), error = qpc_error_v1()
                let code = pin.withNative { pin in
                    certificate.withUnsafeBufferPointer { certificate in
                        roster.withUnsafeBufferPointer { roster in
                            qpc_enrollment_v1_accept(handle, certificate.baseAddress, certificate.count,
                                roster.baseAddress, roster.count, pin, &journal, &error)
                        }
                    }
                }
                try checked(code, &error)
                guard journal.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.malformedOutput }
                return try JournalID(bytes: journal)
            }
        }
    }
    public func prepareStorage() throws -> InstallationPreparation {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_setup_preparation_v1(), error = qpc_error_v1()
                try checked(qpc_enrollment_v1_prepare_storage(handle, &raw, &error), &error)
                return try installationPreparation(&raw)
            }
        }
    }
    /// Persist one same-credential roster target. It cannot replace the root,
    /// credential, key or policy, and cannot renew an expired credential.
    public func refreshRoster(previous: RosterCheckpoint, roster: [UInt8], pin: AccountPin) throws -> EnrollmentStatus {
        guard (1...8192).contains(roster.count) else { throw ContinuityBoundaryError.inputLength }
        return try reference.call { native in
            try native.call { handle in
                var previous = previous.native(), raw = qpc_enrollment_status_v1(), error = qpc_error_v1()
                let code = pin.withNative { pin in
                    roster.withUnsafeBufferPointer { roster in
                        qpc_enrollment_v1_refresh_roster(handle, &previous, roster.baseAddress,
                            roster.count, pin, &raw, &error)
                    }
                }
                try checked(code, &error)
                return try enrollmentStatus(&raw)
            }
        }
    }
    /// Allocate the successor first, then transfer this exact native owning
    /// reference. Failure retains it for close; resume the original state afterward.
    /// Concurrent cancellation may also affect a successful successor; join it first.
    public func activate() throws -> ContinuityDevice {
        try reference.transfer { native in
            let device = ContinuityDevice.activated(native)
            try native.call { handle in
                var error = qpc_error_v1()
                try checked(qpc_enrollment_v1_activate(handle, &error), &error)
            }
            return device
        }
    }
    /// Transfer the original native enrollment and complete selected target
    /// runtime to the same owning device. Required mode needs completed ACK;
    /// historical recovery alone never authorizes activation.
    public func activatePolicyContinuation() throws -> ContinuityDevice {
        try reference.transfer { native in
            let device = ContinuityDevice.activated(native)
            try native.call { handle in
                var error = qpc_error_v1()
                try checked(qpc_enrollment_v1_activate_policy_continuation(handle, &error), &error)
            }
            return device
        }
    }
}
