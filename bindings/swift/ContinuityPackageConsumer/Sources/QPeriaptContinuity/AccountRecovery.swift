// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner

/// Identity of one immutable complete-account loss snapshot, never delivery proof.
public struct AccountCleanupHeader: Sendable {
    public let operation: AccountOperationID
    public let report: AccountAbandonmentID
    public let memberCount: UInt32
}

/// Original canonical member, including all retained rekey and epoch metadata.
public struct AccountCleanupMember: Sendable {
    public let device: [UInt8]
    public let context: [UInt8]
    public let session: SessionID
    public let generation: UInt64
    public let role: ClosureRole
    public let confirmedEpoch: UInt64
    public let sendingEpoch: UInt64
    public let receivingEpoch: UInt64
    public let pendingEpoch: UInt64?
    public let epochCount: UInt32
}

func accountCleanupHeader(_ value: qpc_account_cleanup_header_v1) throws -> AccountCleanupHeader {
    let operation = octets(value.batch), report = octets(value.report)
    guard value.reserved_zero == 0, (1...32).contains(value.member_count),
          operation.contains(where: { $0 != 0 }), report.contains(where: { $0 != 0 }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    return try AccountCleanupHeader(operation: AccountOperationID(bytes: operation),
        report: AccountAbandonmentID(bytes: report), memberCount: value.member_count)
}
func accountCleanupMember(_ value: qpc_account_cleanup_member_v1) throws -> AccountCleanupMember {
    let device = octets(value.device), session = octets(value.session)
    guard let role = ClosureRole(rawValue: value.role), value.reserved_zero == 0,
          value.generation != 0, (1...4).contains(value.epoch_count),
          device.contains(where: { $0 != 0 }), session.contains(where: { $0 != 0 }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    return try AccountCleanupMember(device: device, context: octets(value.context),
        session: SessionID(bytes: session), generation: value.generation, role: role,
        confirmedEpoch: value.confirmed_epoch, sendingEpoch: value.sending_epoch,
        receivingEpoch: value.receiving_epoch,
        pendingEpoch: optionalCounter(value.has_pending_epoch, value.pending_epoch),
        epochCount: value.epoch_count)
}
func decodeAccountCleanupStatus(_ value: qpc_account_cleanup_status_v1) throws -> AccountStatus {
    guard let state = UInt8(exactly: value.phase) else { throw ContinuityBoundaryError.malformedOutput }
    return try accountStatus(state, report: octets(value.report))
}

extension ContinuityRecoveryOwner {
    /// Consumes discovery and authenticates every original account member before
    /// recovery writes. No recipient subset or operational authority is accepted.
    /// Failed native selection requires closing and reopening original state.
    public func select(account operation: AccountOperationID) throws {
        try change { handle, error in
            operation.bytes.withUnsafeBufferPointer { qpc_recovery_v1_select_account(handle, $0.baseAddress, error) }
        }
    }
    /// Permanently freezes all members and retains one complete immutable snapshot.
    /// Read every member, reservation, epoch and nested entry before host accounting.
    /// A partial read is never a complete report.
    public func beginAccountCleanup() throws -> AccountCleanupHeader {
        try accountCleanupHeader(read(qpc_account_cleanup_header_v1(), qpc_recovery_v1_account_begin))
    }
    /// Fresh native aggregate status, not inferred delivery or cached permission.
    public func accountCleanupStatus() throws -> AccountStatus {
        try decodeAccountCleanupStatus(read(qpc_account_cleanup_status_v1(), qpc_recovery_v1_account_status))
    }
    public func accountMember(at member: UInt32) throws -> AccountCleanupMember {
        try accountCleanupMember(read(qpc_account_cleanup_member_v1()) {
            qpc_recovery_v1_account_member($0, member, $1, $2)
        })
    }
    /// Each original member has exactly one reserved input.
    public func accountReservation(member: UInt32) throws -> ClosureReservation {
        let value = try read(qpc_closure_reserved_v1()) { qpc_recovery_v1_account_reserved($0, member, $1, $2) }
        return try ClosureReservation(message: MessageID(bytes: octets(value.message)),
            plaintextBytes: value.plaintext_bytes, associatedDataBytes: value.associated_data_bytes)
    }
    public func accountEpoch(member: UInt32, at epoch: UInt32) throws -> ClosureEpoch {
        try closureEpoch(read(qpc_closure_epoch_v1()) { qpc_recovery_v1_account_epoch($0, member, epoch, $1, $2) })
    }
    public func accountUnconfirmed(member: UInt32, epoch: UInt32, at index: UInt32) throws -> ClosureUnconfirmed {
        let value = try read(qpc_closure_unconfirmed_v1()) {
            qpc_recovery_v1_account_unconfirmed($0, member, epoch, index, $1, $2)
        }
        return try ClosureUnconfirmed(message: MessageID(bytes: octets(value.message)),
            ciphertextDigest: octets(value.ciphertext_digest))
    }
    public func accountDelivery(member: UInt32, epoch: UInt32, at index: UInt32) throws -> ClosureDelivery {
        let value = try read(qpc_closure_delivery_v1()) {
            qpc_recovery_v1_account_delivery($0, member, epoch, index, $1, $2)
        }
        return try ClosureDelivery(message: MessageID(bytes: octets(value.message)),
            index: value.index, plaintextBytes: value.plaintext_bytes)
    }
    /// An observed skipped position does not prove the peer sent that message.
    public func accountSkippedPosition(member: UInt32, epoch: UInt32, at index: UInt32) throws -> UInt64 {
        try read(0) { qpc_recovery_v1_account_skipped($0, member, epoch, index, $1, $2) }
    }
    /// Only after the complete report and its IDs are durable in a deduplicated
    /// host transaction. Unknown outcomes require exact original-ID reconciliation.
    public func acknowledgeAccount(report: AccountAbandonmentID) throws {
        try change { handle, error in
            report.bytes.withUnsafeBufferPointer { qpc_recovery_v1_account_acknowledge(handle, $0.baseAddress, error) }
        }
    }
    /// Retires only acknowledged batch metadata. Session/bootstrap tombstones and
    /// counters remain; this never refunds capacity or reactivates member keys.
    public func retireAccount() throws { try change(qpc_recovery_v1_account_retire) }
}
