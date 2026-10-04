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
    case preparing = 1, requested = 2, accepted = 3, activating = 4, active = 5, refreshing = 6
}
/// Authenticated durable progress, not a live authorization or successful activation receipt.
public struct EnrollmentStatus: Sendable, Equatable {
    public let phase: EnrollmentPhase
    public let signingID: SigningKeyID
    /// Absent only in Preparing and Requested.
    public let journal: JournalID?
    /// Both checkpoints exist only in Refreshing.
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
        if phase != .refreshing {
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
    if phase == .refreshing {
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
}
