// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

enum SetupIntent { case create, resume }
public enum JournalTag: Sendable {}
public typealias JournalID = ContinuityID<JournalTag>
public enum InstallationPhase: UInt32, Sendable { case creating = 1, active = 2 }
public struct InstallationStatus: Sendable, Equatable {
    public let phase: InstallationPhase
    public let journal: JournalID
}
/// Public original enrollment inputs, not a signed receipt or enrollment permission.
public struct WitnessGenesis: Sendable, Equatable {
    public let journal: JournalID
    public let subject: [UInt8]
    public let imageDigest: [UInt8]
}
public enum InstallationPreparation: Sendable, Equatable {
    case local(JournalID)
    case requiresEnrollment(WitnessGenesis)
}

func installationStatus(_ raw: inout qpc_setup_status_v1) throws -> InstallationStatus {
    let journal = withUnsafeBytes(of: &raw.journal) { Array($0) }
    guard let phase = InstallationPhase(rawValue: raw.phase), journal.contains(where: { $0 != 0 }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    return InstallationStatus(phase: phase, journal: try JournalID(bytes: journal))
}
func installationPreparation(_ raw: inout qpc_setup_preparation_v1) throws -> InstallationPreparation {
    let journal = withUnsafeBytes(of: &raw.journal) { Array($0) }
    let subject = withUnsafeBytes(of: &raw.subject) { Array($0) }
    let digest = withUnsafeBytes(of: &raw.image_digest) { Array($0) }
    guard journal.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.malformedOutput }
    let id = try JournalID(bytes: journal)
    switch raw.protection {
    case 1:
        guard subject.allSatisfy({ $0 == 0 }), digest.allSatisfy({ $0 == 0 }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        return .local(id)
    case 2:
        guard Array(subject.prefix(32)) == journal,
              subject.dropFirst(32).prefix(32).contains(where: { $0 != 0 }),
              subject.suffix(32).contains(where: { $0 != 0 }), digest.contains(where: { $0 != 0 }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        return .requiresEnrollment(WitnessGenesis(journal: id, subject: subject, imageDigest: digest))
    default: throw ContinuityBoundaryError.malformedOutput
    }
}

/// Explicit original installation setup over independently prepared key,
/// credential, policy and TLS inputs. It grants no peer/message authority.
public final class ContinuitySetup: Sendable {
    private let reference: OwnerTransferReference
    private init(_ native: NativeOwner) { reference = OwnerTransferReference(native, label: "setup") }
    private static func prepare(path: String, witness: WitnessCarrier, intent: SetupIntent) throws -> ContinuitySetup {
        try ContinuitySetup(NativeOwner.prepare(path: path, kind: 3, quality: 0, witness: witness, setup: intent))
    }
    public static func prepareCreate(path: String, witness: WitnessCarrier = .local) throws -> ContinuitySetup {
        try prepare(path: path, witness: witness, intent: .create)
    }
    public static func prepareResume(path: String, witness: WitnessCarrier = .local) throws -> ContinuitySetup {
        try prepare(path: path, witness: witness, intent: .resume)
    }
    public static func create(path: String, witness: WitnessCarrier = .local) throws -> ContinuitySetup {
        let setup = try prepareCreate(path: path, witness: witness)
        try setup.finishOpen()
        return setup
    }
    public static func resume(path: String, witness: WitnessCarrier = .local) throws -> ContinuitySetup {
        let setup = try prepareResume(path: path, witness: witness)
        try setup.finishOpen()
        return setup
    }
    public func finishOpen() throws { try reference.call { try $0.finishOpen() } }
    /// Cancellation admitted before/during transfer can also affect the returned
    /// device. Join cancellation before treating a racing activation as usable.
    public func cancel() throws { try reference.call(cancellation: true) { try $0.cancel() } }
    /// Successful transfer makes subsequent setup close harmless to its successor.
    public func close() throws { try reference.close() }
    public func status() throws -> InstallationStatus {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_setup_status_v1(), error = qpc_error_v1()
                try checked(qpc_setup_v1_status(handle, &raw, &error), &error)
                return try installationStatus(&raw)
            }
        }
    }
    public func prepareStorage() throws -> InstallationPreparation {
        try reference.call { native in
            try native.call { handle in
                var raw = qpc_setup_preparation_v1(), error = qpc_error_v1()
                try checked(qpc_setup_v1_prepare_storage(handle, &raw, &error), &error)
                return try installationPreparation(&raw)
            }
        }
    }
    /// Allocate the successor before native mutation, then transfer the same
    /// owning reference. Failed activation leaves setup available for cancel/close;
    /// reconcile through a new resume of the original configuration.
    public func activate() throws -> ContinuityDevice {
        try reference.transfer { native in
            let device = ContinuityDevice.activated(native)
            try native.call { handle in
                var error = qpc_error_v1()
                try checked(qpc_setup_v1_activate(handle, &error), &error)
            }
            return device
        }
    }
}
