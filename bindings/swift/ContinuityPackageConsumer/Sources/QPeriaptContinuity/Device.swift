// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

public enum BootstrapRole: UInt32, Sendable { case initiator = 1, responder = 2 }
public enum AccountTag: Sendable {}
public enum AccountOperationTag: Sendable {}
public enum AccountAbandonmentTag: Sendable {}
public typealias AccountID = ContinuityID<AccountTag>
public typealias AccountOperationID = ContinuityID<AccountOperationTag>
public typealias AccountAbandonmentID = ContinuityID<AccountAbandonmentTag>

/// Local aggregate state. Committed does not assert any peer's consumption.
public enum AccountStatus: Sendable, Equatable {
    case absent, reserved, committed, retired
    case abandoning(AccountAbandonmentID), abandoned(AccountAbandonmentID)
}
public enum AccountDeliveryOutcome: Sendable, Equatable {
    case consumption(Consumption)
    case resolutionPending, deliveryUnknown, historyRetired, reservationAbandoned
}
/// Retains the peer wrapper. A live peer retains its original native parent;
/// closed peers grant no authority. Native admission verifies that every target
/// is a distinct live child of the selected device.
public struct AccountTarget: Sendable {
    public let peer: ContinuityOwner
    public let session: SessionID
    public init(peer: ContinuityOwner, session: SessionID) {
        self.peer = peer
        self.session = session
    }
}
public struct AccountDelivery: Sendable {
    public let device: [UInt8]
    public let session: SessionID
    public let message: MessageID
    public let outcome: AccountDeliveryOutcome
    /// Zero means an already retained outcome, which need not be consumption.
    public let exchanges: UInt16
}

func accountStatus(_ state: UInt8, report: [UInt8]) throws -> AccountStatus {
    guard report.count == 32 else { throw ContinuityBoundaryError.malformedOutput }
    switch state {
    case 0, 1, 2, 5:
        guard report.allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        switch state {
        case 0: return .absent
        case 1: return .reserved
        case 2: return .committed
        default: return .retired
        }
    case 3, 4:
        guard report.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        let id = try AccountAbandonmentID(bytes: report)
        return state == 3 ? .abandoning(id) : .abandoned(id)
    default: throw ContinuityBoundaryError.malformedOutput
    }
}
func accountDelivery(_ result: inout qpc_account_delivered_v1, session: SessionID) throws -> AccountDelivery {
    let device = withUnsafeBytes(of: &result.device) { Array($0) }
    let observed = withUnsafeBytes(of: &result.session) { Array($0) }
    let message = withUnsafeBytes(of: &result.message) { Array($0) }
    guard device.count == 16, device.contains(where: { $0 != 0 }), observed == session.bytes,
          message.count == 32, message.contains(where: { $0 != 0 }), result.exchanges <= 8 else {
        throw ContinuityBoundaryError.malformedOutput
    }
    let outcome: AccountDeliveryOutcome
    switch result.outcome {
    case 1: outcome = .consumption(.confirmed)
    case 2:
        guard result.exchanges != 0 else { throw ContinuityBoundaryError.malformedOutput }
        outcome = .consumption(.prefixPending)
    case 3: outcome = .resolutionPending
    case 4: outcome = .deliveryUnknown
    case 5: outcome = .historyRetired
    case 6: outcome = .reservationAbandoned
    default: throw ContinuityBoundaryError.malformedOutput
    }
    return AccountDelivery(device: device, session: session, message: try MessageID(bytes: message),
                           outcome: outcome, exchanges: UInt16(result.exchanges))
}

/// One already Active original installation. Provisioning and renewal are explicit
/// separate operations. Live peers retain native parent ownership; closing one
/// preserves a separately owned device. Successful device close releases its stores and
/// invalidates children even if their Swift objects remain alive.
public final class ContinuityDevice: Sendable {
    private let native: NativeOwner
    private init(native: NativeOwner) { self.native = native }
    static func activated(_ native: NativeOwner) -> ContinuityDevice { ContinuityDevice(native: native) }
    public static func prepare(path: String, witness: WitnessCarrier = .local) throws -> ContinuityDevice {
        try ContinuityDevice(native: NativeOwner.prepare(path: path, kind: 3, quality: 0, witness: witness))
    }
    public static func open(path: String, witness: WitnessCarrier = .local) throws -> ContinuityDevice {
        let device = try prepare(path: path, witness: witness)
        try device.finishOpen()
        return device
    }
    func call<T>(_ body: (UInt64) throws -> T) rethrows -> T {
        try withExtendedLifetime(self) { try native.call(body) }
    }
    public func finishOpen() throws { try native.finishOpen() }
    public func cancel() throws { try native.cancel() }
    public func close() throws { try native.close() }

    public func preparePeer(path: String, quality: PrekeyQuality, role: BootstrapRole) throws -> ContinuityOwner {
        try withExtendedLifetime(self) {
            try ContinuityOwner.preparePeer(parent: native, path: path, quality: quality, role: role, session: nil)
        }
    }
    public func openPeer(path: String, quality: PrekeyQuality, role: BootstrapRole) throws -> ContinuityOwner {
        let peer = try preparePeer(path: path, quality: quality, role: role)
        try peer.finishOpen()
        return peer
    }
    public func preparePeerReopen(path: String, quality: PrekeyQuality, role: BootstrapRole,
                                  session: SessionID) throws -> ContinuityOwner {
        try withExtendedLifetime(self) {
            try ContinuityOwner.preparePeer(parent: native, path: path, quality: quality, role: role, session: session)
        }
    }
    public func reopenPeer(path: String, quality: PrekeyQuality, role: BootstrapRole,
                           session: SessionID) throws -> ContinuityOwner {
        let peer = try preparePeerReopen(path: path, quality: quality, role: role, session: session)
        try peer.finishOpen()
        return peer
    }
    /// Copies explicit peer inputs without a peer directory; finishOpen performs current admission.
    public func preparePeer(configuration: PeerConfiguration, quality: PrekeyQuality, role: BootstrapRole) throws -> ContinuityOwner {
        try withExtendedLifetime(self) {
            try ContinuityOwner.preparePeer(parent: native, configuration: configuration, quality: quality, role: role, session: nil)
        }
    }
    public func openPeer(configuration: PeerConfiguration, quality: PrekeyQuality, role: BootstrapRole) throws -> ContinuityOwner {
        let peer = try preparePeer(configuration: configuration, quality: quality, role: role)
        try peer.finishOpen()
        return peer
    }
    /// Exact original-session restoration; never substitutes fresh bootstrap after failure.
    public func preparePeerReopen(configuration: PeerConfiguration, quality: PrekeyQuality, role: BootstrapRole,
                                  session: SessionID) throws -> ContinuityOwner {
        try withExtendedLifetime(self) {
            try ContinuityOwner.preparePeer(parent: native, configuration: configuration, quality: quality, role: role, session: session)
        }
    }
    public func reopenPeer(configuration: PeerConfiguration, quality: PrekeyQuality, role: BootstrapRole,
                           session: SessionID) throws -> ContinuityOwner {
        let peer = try preparePeerReopen(configuration: configuration, quality: quality, role: role, session: session)
        try peer.finishOpen()
        return peer
    }
    /// Read and retain before sending. This does not reserve or dispatch work.
    public func nextAccountOperation() throws -> AccountOperationID {
        try call { handle in
            var result = [UInt8](repeating: 0, count: 32), error = qpc_error_v1()
            let code = result.withUnsafeMutableBufferPointer {
                qpc_device_v1_next_account(handle, $0.baseAddress, &error)
            }
            try checked(code, &error)
            guard result.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.malformedOutput }
            return try AccountOperationID(bytes: result)
        }
    }
    public func status(operation: AccountOperationID) throws -> AccountStatus {
        try call { handle in
            var status: UInt8 = 255, report = [UInt8](repeating: 0, count: 32), error = qpc_error_v1()
            let code = operation.bytes.withUnsafeBufferPointer { operation in
                report.withUnsafeMutableBufferPointer {
                    qpc_device_v1_account_status(handle, operation.baseAddress, &status, $0.baseAddress, &error)
                }
            }
            try checked(code, &error)
            return try accountStatus(status, report: report)
        }
    }
    /// Reconcile the exact complete input, then deliver one member. All target
    /// owners are pinned through return. Retain the original operation after any
    /// error/cancellation; no automatic fallback, omission or new ID is used.
    public func sendAccountMember(operation: AccountOperationID, account: AccountID,
                                  targets: [AccountTarget], selected: Int, address: String,
                                  plaintext: [UInt8], associatedData: [UInt8]) throws -> AccountDelivery {
        guard (1...32).contains(targets.count), targets.indices.contains(selected) else {
            throw ContinuityBoundaryError.inputLength
        }
        let address = try textBytes(address, maximum: 128)
        return try withExtendedLifetime(targets) {
            let records = targets.map { target in
                target.peer.call { handle in
                    var record = qpc_account_target_v1()
                    record.peer = handle
                    withUnsafeMutableBytes(of: &record.session) { $0.copyBytes(from: target.session.bytes) }
                    return record
                }
            }
            return try call { handle in
                var result = qpc_account_delivered_v1(), error = qpc_error_v1()
                let code = records.withUnsafeBufferPointer { records in
                    operation.bytes.withUnsafeBufferPointer { operation in
                        account.bytes.withUnsafeBufferPointer { account in
                            address.withUnsafeBufferPointer { address in
                                plaintext.withUnsafeBufferPointer { plaintext in
                                    associatedData.withUnsafeBufferPointer { ad in
                                        qpc_device_v1_send_account_member(handle, records.baseAddress, records.count,
                                            selected, operation.baseAddress, account.baseAddress,
                                            address.baseAddress, address.count, plaintext.baseAddress,
                                            plaintext.count, ad.baseAddress, ad.count, &result, &error)
                                    }
                                }
                            }
                        }
                    }
                }
                try checked(code, &error)
                return try accountDelivery(&result, session: targets[selected].session)
            }
        }
    }
}
