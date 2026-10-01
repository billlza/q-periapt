// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner

public enum ClosureReportTag: Sendable {}
public enum ResolutionReportTag: Sendable {}
public typealias ClosureReportID = ContinuityID<ClosureReportTag>
public typealias ResolutionReportID = ContinuityID<ResolutionReportTag>

public enum ClosureStatus: Sendable, Equatable {
    case open, pending(ClosureReportID), closed(ClosureReportID)
}
public enum ClosureRole: UInt32, Sendable { case initiator = 1, responder = 2 }
public enum ClosureResolution: Sendable, Equatable {
    case unrequested, pending(ResolutionReportID), acknowledged(ResolutionReportID)
}

/// Complete scalar header; read every counted entry before durably acknowledging.
/// These values describe an immutable loss snapshot, never permission to send.
public struct ClosureHeader: Sendable {
    public let session: SessionID
    public let report: ClosureReportID
    public let context: [UInt8]
    public let peerAccount: [UInt8]
    public let peerDevice: [UInt8]
    public let role: ClosureRole
    public let peerGeneration: UInt64
    public let confirmedEpoch: UInt64
    public let sendingEpoch: UInt64
    public let receivingEpoch: UInt64
    public let pendingEpoch: UInt64?
    public let reservedCount: UInt32
    public let epochCount: UInt32
}
public struct ClosureEpoch: Sendable {
    public let epoch: UInt64
    public let acknowledgedBefore: UInt64
    public let sent: UInt64
    public let consumedBefore: UInt64
    public let received: UInt64
    public let peerSent: UInt64?
    public let resolution: ClosureResolution
    public let unconfirmedCount: UInt32
    public let deliveryCount: UInt32
    public let skippedCount: UInt32
}
public struct ClosureReservation: Sendable {
    public let message: MessageID
    public let plaintextBytes: UInt64
    public let associatedDataBytes: UInt64
}
public struct ClosureUnconfirmed: Sendable {
    public let message: MessageID
    /// Native domain-separated ciphertext commitment, never a plaintext hash.
    public let ciphertextDigest: [UInt8]
}
public struct ClosureDelivery: Sendable {
    public let message: MessageID
    public let index: UInt64
    public let plaintextBytes: UInt64
}

// Called only with imported fixed uint8_t arrays, not padded native records.
private func octets<T>(_ value: T) -> [UInt8] {
    withUnsafeBytes(of: value) { Array($0) }
}
private func optionalCounter(_ present: UInt32, _ value: UInt64) throws -> UInt64? {
    guard present <= 1, present == 1 || value == 0 else {
        throw ContinuityBoundaryError.malformedOutput
    }
    return present == 1 ? value : nil
}
func closureHeader(_ value: qpc_closure_header_v1) throws -> ClosureHeader {
    guard let role = ClosureRole(rawValue: value.role) else { throw ContinuityBoundaryError.malformedOutput }
    return try ClosureHeader(session: SessionID(bytes: octets(value.session)),
        report: ClosureReportID(bytes: octets(value.report)), context: octets(value.context),
        peerAccount: octets(value.peer_account), peerDevice: octets(value.peer_device), role: role,
        peerGeneration: value.peer_generation, confirmedEpoch: value.confirmed_epoch,
        sendingEpoch: value.sending_epoch, receivingEpoch: value.receiving_epoch,
        pendingEpoch: optionalCounter(value.has_pending_epoch, value.pending_epoch),
        reservedCount: value.reserved_count, epochCount: value.epoch_count)
}
func closureEpoch(_ value: qpc_closure_epoch_v1) throws -> ClosureEpoch {
    guard value.reserved_zero == 0 else { throw ContinuityBoundaryError.malformedOutput }
    let resolution: ClosureResolution
    let report = try ResolutionReportID(bytes: octets(value.resolution_report))
    switch value.resolution {
    case 0:
        guard report.bytes.allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        resolution = .unrequested
    case 1: resolution = .pending(report)
    case 2: resolution = .acknowledged(report)
    default: throw ContinuityBoundaryError.malformedOutput
    }
    return try ClosureEpoch(epoch: value.epoch, acknowledgedBefore: value.acknowledged_before,
        sent: value.sent, consumedBefore: value.consumed_before, received: value.received,
        peerSent: optionalCounter(value.has_peer_sent, value.peer_sent), resolution: resolution,
        unconfirmedCount: value.unconfirmed_count, deliveryCount: value.delivery_count,
        skippedCount: value.skipped_count)
}
func closureStatus(_ value: qpc_closure_status_v1) throws -> ClosureStatus {
    let report = try ClosureReportID(bytes: octets(value.report))
    switch value.phase {
    case 0:
        guard report.bytes.allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        return .open
    case 1: return .pending(report)
    case 2: return .closed(report)
    default: throw ContinuityBoundaryError.malformedOutput
    }
}

/// Cleanup-only original-installation authority. This distinct type exposes no
/// operational methods, raw handle, key export or conversion to ContinuityOwner.
/// Discovery IDs are hints; selection authenticates the original durable state.
public final class ContinuityRecoveryOwner: Sendable {
    private let native: NativeOwner
    private init(native: NativeOwner) { self.native = native }

    public static func prepare(path: String, witness: WitnessCarrier = .local) throws -> ContinuityRecoveryOwner {
        try ContinuityRecoveryOwner(native: NativeOwner.prepare(path: path, kind: 2, quality: 0, witness: witness))
    }
    /// Never provisions or repairs. Required witness protection cannot fall back.
    public static func open(path: String, witness: WitnessCarrier = .local) throws -> ContinuityRecoveryOwner {
        let owner = try prepare(path: path, witness: witness)
        try owner.finishOpen()
        return owner
    }
    public func finishOpen() throws { try native.finishOpen() }
    public func cancel() throws { try native.cancel() }
    public func close() throws { try native.close() }

    private func read<T>(_ initial: T,
        _ body: (UInt64, UnsafeMutablePointer<T>, UnsafeMutablePointer<qpc_error_v1>) -> Int32) throws -> T {
        try withExtendedLifetime(self) {
            try native.call { handle in
                var error = qpc_error_v1(), value = initial
                try checked(body(handle, &value, &error), &error)
                return value
            }
        }
    }
    private func change(_ body: (UInt64, UnsafeMutablePointer<qpc_error_v1>) -> Int32) throws {
        try withExtendedLifetime(self) {
            try native.call { handle in
                var error = qpc_error_v1()
                try checked(body(handle, &error), &error)
            }
        }
    }
    public func sessionCount() throws -> UInt32 { try read(0, qpc_recovery_v1_session_count) }
    public func session(at index: UInt32) throws -> SessionID {
        var bytes = [UInt8](repeating: 0, count: 32)
        try change { handle, error in
            bytes.withUnsafeMutableBufferPointer { qpc_recovery_v1_session_at(handle, index, $0.baseAddress, error) }
        }
        return try SessionID(bytes: bytes)
    }
    /// Failed native selection consumes discovery; close and reopen original state.
    public func select(session: SessionID) throws {
        try change { handle, error in
            session.bytes.withUnsafeBufferPointer { qpc_recovery_v1_select(handle, $0.baseAddress, error) }
        }
    }
    public func select(archive: [UInt8]) throws {
        try change { handle, error in
            archive.withUnsafeBufferPointer { qpc_recovery_v1_select_archive(handle, $0.baseAddress, $0.count, error) }
        }
    }
    /// Authenticated original metadata only; retain before retiring its index row.
    public func archive() throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: Int(QPC_CLOSURE_ARCHIVE_BYTES))
        try change { handle, error in
            bytes.withUnsafeMutableBufferPointer { qpc_recovery_v1_archive(handle, $0.baseAddress, error) }
        }
        return bytes
    }
    /// Permanently freezes the session and retains its immutable loss snapshot.
    /// Read all reserved/epoch/nested entries; each call can fail independently.
    /// A partial read must never be treated as a complete durable report.
    public func begin() throws -> ClosureHeader { try closureHeader(read(qpc_closure_header_v1(), qpc_recovery_v1_begin)) }
    public func status() throws -> ClosureStatus { try closureStatus(read(qpc_closure_status_v1(), qpc_recovery_v1_status)) }
    public func reservation(at index: UInt32) throws -> ClosureReservation {
        let value = try read(qpc_closure_reserved_v1()) { qpc_recovery_v1_reserved($0, index, $1, $2) }
        return try ClosureReservation(message: MessageID(bytes: octets(value.message)),
            plaintextBytes: value.plaintext_bytes, associatedDataBytes: value.associated_data_bytes)
    }
    public func epoch(at index: UInt32) throws -> ClosureEpoch {
        try closureEpoch(read(qpc_closure_epoch_v1()) { qpc_recovery_v1_epoch($0, index, $1, $2) })
    }
    public func unconfirmed(epoch: UInt32, at index: UInt32) throws -> ClosureUnconfirmed {
        let value = try read(qpc_closure_unconfirmed_v1()) { qpc_recovery_v1_unconfirmed($0, epoch, index, $1, $2) }
        return try ClosureUnconfirmed(message: MessageID(bytes: octets(value.message)), ciphertextDigest: octets(value.ciphertext_digest))
    }
    public func delivery(epoch: UInt32, at index: UInt32) throws -> ClosureDelivery {
        let value = try read(qpc_closure_delivery_v1()) { qpc_recovery_v1_delivery($0, epoch, index, $1, $2) }
        return try ClosureDelivery(message: MessageID(bytes: octets(value.message)), index: value.index, plaintextBytes: value.plaintext_bytes)
    }
    /// An observed skipped position does not prove that a peer message existed.
    public func skippedPosition(epoch: UInt32, at index: UInt32) throws -> UInt64 {
        try read(0) { qpc_recovery_v1_skipped($0, epoch, index, $1, $2) }
    }
    /// Call only after the complete report and its ID are durable in one host
    /// transaction. Unknown results require same-ID status reconciliation.
    public func acknowledge(report: ClosureReportID) throws {
        try change { handle, error in
            report.bytes.withUnsafeBufferPointer { qpc_recovery_v1_acknowledge(handle, $0.baseAddress, error) }
        }
    }
    /// Removes catalogue metadata only after exact closed-state admission.
    public func retire(report: ClosureReportID) throws -> Bool {
        let removed: UInt8 = try read(0) { handle, result, error in
            report.bytes.withUnsafeBufferPointer { qpc_recovery_v1_retire(handle, $0.baseAddress, result, error) }
        }
        guard removed <= 1 else { throw ContinuityBoundaryError.malformedOutput }
        return removed == 1
    }
    /// Restores metadata only, never operational authority or key material.
    public func restoreIndex() throws { try change(qpc_recovery_v1_restore_index) }
}
