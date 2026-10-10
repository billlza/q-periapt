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

/// Historical state of one original outgoing member. Only acknowledged proves
/// authenticated consumption. HistoryRetired no longer distinguishes an earlier
/// acknowledgement from accounted unknown delivery. None grants send permission.
public enum AccountMemberState: UInt32, Sendable, Equatable {
    case committed = 1, acknowledged = 2, resolutionPending = 3
    case deliveryUnknown = 4, historyRetired = 5, reservationAbandoned = 6
}
public struct AccountReconciledMember: Sendable, Equatable {
    public let device: [UInt8]
    public let session: SessionID
    public let message: MessageID
    public let state: AccountMemberState
}
/// Complete original member set in canonical device order. Retain the needed
/// results durably before retiring metadata; this is not a delivery acknowledgement.
public struct AccountReconciliation: Sendable, Equatable {
    public let operation: AccountOperationID
    public let members: [AccountReconciledMember]
}

func accountReconciliation(_ value: qpc_account_reconciliation_v1) throws -> AccountReconciliation {
    let operation = octets(value.batch), bytes = octets(value.members)
    guard value.reserved_zero == 0, (1...32).contains(value.member_count),
          operation.contains(where: { $0 != 0 }), bytes.count == 32 * 88 else {
        throw ContinuityBoundaryError.malformedOutput
    }
    var members: [AccountReconciledMember] = []
    for index in 0..<32 {
        let offset = index * 88
        let member = Array(bytes[offset..<(offset + 88)])
        if index >= Int(value.member_count) {
            guard member.allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
            continue
        }
        let device = Array(member[0..<16]), session = Array(member[16..<48]), message = Array(member[48..<80])
        let (state, reserved) = member.withUnsafeBytes {
            ($0.loadUnaligned(fromByteOffset: 80, as: UInt32.self),
             $0.loadUnaligned(fromByteOffset: 84, as: UInt32.self))
        }
        guard let state = AccountMemberState(rawValue: state), reserved == 0,
              device.contains(where: { $0 != 0 }), session.contains(where: { $0 != 0 }),
              message.contains(where: { $0 != 0 }),
              members.last.map({ $0.device.lexicographicallyPrecedes(device) }) ?? true else {
            throw ContinuityBoundaryError.malformedOutput
        }
        members.append(try AccountReconciledMember(device: device, session: SessionID(bytes: session),
            message: MessageID(bytes: message), state: state))
    }
    return try AccountReconciliation(operation: AccountOperationID(bytes: operation), members: members)
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
    /// Authenticate and reconcile ALL original members in one native observation.
    /// Reserved or unresolved abandonment is refused; unknown outcomes and witness
    /// failures throw their exact native error and never become an empty result.
    public func reconcileAccount() throws -> AccountReconciliation {
        try accountReconciliation(read(qpc_account_reconciliation_v1(), qpc_recovery_v1_account_reconciliation))
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
    /// Retires acknowledged abandonment metadata or a committed batch whose EVERY
    /// original member is settled. Persist needed complete results first. Original
    /// session/bootstrap records and counters remain; no member keys reactivate.
    public func retireAccount() throws { try change(qpc_recovery_v1_account_retire) }
}
