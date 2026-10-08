// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner

/// Independently retained witness pin and exact old-subject replacement proof.
/// Construction checks widths only; native preparation authenticates the proof.
/// Never learn the pin from the response whose authority is being checked.
public struct RetiredEnrollmentAuthority: Sendable, Equatable {
    public let witness: [UInt8]
    public let publicKey: [UInt8]
    public let replacement: [UInt8]
    public let subject: [UInt8]
    public let receipt: [UInt8]

    public init(witness: [UInt8], publicKey: [UInt8], replacement: [UInt8],
                subject: [UInt8], receipt: [UInt8]) throws {
        guard witness.count == 32, publicKey.count == 1985, subject.count == 96,
              receipt.count == 3754, (1...57794).contains(replacement.count) else {
            throw ContinuityBoundaryError.inputLength
        }
        self.witness = witness; self.publicKey = publicKey; self.replacement = replacement
        self.subject = subject; self.receipt = receipt
    }

    func withNative<T>(_ body: (UnsafePointer<qpc_retired_authority_v1>) throws -> T) rethrows -> T {
        try publicKey.withUnsafeBufferPointer { key in
            try replacement.withUnsafeBufferPointer { replacement in
                try receipt.withUnsafeBufferPointer { receipt in
                    var value = qpc_retired_authority_v1()
                    value.public_key = key.baseAddress; value.public_key_length = key.count
                    value.replacement = replacement.baseAddress; value.replacement_length = replacement.count
                    value.receipt = receipt.baseAddress; value.receipt_length = receipt.count
                    withUnsafeMutableBytes(of: &value.witness) { $0.copyBytes(from: witness) }
                    withUnsafeMutableBytes(of: &value.subject) { $0.copyBytes(from: subject) }
                    return try withUnsafePointer(to: &value, body)
                }
            }
        }
    }
}

public enum RetiredReportTag: Sendable {}
public typealias RetiredReportID = ContinuityID<RetiredReportTag>

/// Original public expectation; these bytes alone grant no witness authority.
public struct RetiredInventory: Sendable, Equatable {
    public let bytes: [UInt8]
    init(bytes: [UInt8]) throws {
        guard bytes.count == 313, bytes.starts(with: Array("QPRCLP01".utf8)) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        self.bytes = bytes
    }
}

/// Original inventory plus its keyed report ID, separately authenticated by the witness.
public struct RetiredReportProposal: Sendable, Equatable {
    public let bytes: [UInt8]
    public let inventory: RetiredInventory
    public let report: RetiredReportID
    init(bytes: [UInt8]) throws {
        guard bytes.count == 353, bytes.starts(with: Array("QPRRPT01".utf8)),
              bytes.suffix(32).contains(where: { $0 != 0 }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        inventory = try RetiredInventory(bytes: Array(bytes[8..<321]))
        report = try RetiredReportID(bytes: Array(bytes.suffix(32)))
        self.bytes = bytes
    }
}

func retiredProposal(_ value: qpc_retired_proposal_v1) throws -> RetiredReportProposal? {
    let bytes = octets(value.bytes)
    guard value.present <= 1, octets(value.reserved_zero).allSatisfy({ $0 == 0 }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    if value.present == 0 {
        guard bytes.allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        return nil
    }
    return try RetiredReportProposal(bytes: bytes)
}

/// Complete immutable private host metadata, with its separately returned keyed ID.
/// Persist every byte and the original proposal before accounting/acknowledgement.
/// Loading this value is neither a durable host transaction nor an erasure permit.
public struct RetiredDeviceReport: Sendable, Equatable {
    public let report: RetiredReportID
    public let viewCount: UInt32
    public let canonicalBytes: [UInt8]
    init(info: qpc_retired_report_info_v1, bytes: [UInt8]) throws {
        guard (323...8388608).contains(info.length), bytes.count == info.length,
              (1...2).contains(info.views), info.reserved_zero == 0,
              octets(info.report).contains(where: { $0 != 0 }),
              bytes.starts(with: Array("QPRDMD01".utf8)) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        report = try RetiredReportID(bytes: octets(info.report))
        viewCount = info.views; canonicalBytes = bytes
    }
}

/// Authenticated logical state only; retained pages, backups and wrapping keys are separate.
public enum RetiredErasureState: UInt32, Sendable { case retained = 0, erased = 1 }

/// Cleanup-only original enrollment. No operational owner, key getter or raw handle is exposed.
/// Native failures after admission consume the resource. Close and reopen the exact
/// original inputs after unknown outcomes; never provision, reset or choose another backup.
public final class ContinuityRetiredEnrollment: Sendable {
    private let native: NativeOwner
    private init(_ native: NativeOwner) { self.native = native }

    public static func prepareOpen(path: String, intent: EnrollmentIntent,
                                   authority: RetiredEnrollmentAuthority) throws -> ContinuityRetiredEnrollment {
        try ContinuityRetiredEnrollment(NativeOwner.prepareRetired(path: path, intent: intent, authority: authority))
    }
    public static func open(path: String, intent: EnrollmentIntent,
                            authority: RetiredEnrollmentAuthority) throws -> ContinuityRetiredEnrollment {
        let owner = try prepareOpen(path: path, intent: intent, authority: authority)
        try owner.finishOpen()
        return owner
    }
    public func finishOpen() throws { try native.finishOpen() }
    public func cancel() throws { try native.cancel() }
    public func close() throws { try native.close() }

    public func inventory() throws -> RetiredInventory {
        try native.call { handle in
            var value = qpc_retired_inventory_v1(), error = qpc_error_v1()
            try checked(qpc_retired_v1_inventory(handle, &value, &error), &error)
            return try RetiredInventory(bytes: octets(value.bytes))
        }
    }

    private func proposal(_ call: (UInt64, UnsafeMutablePointer<qpc_retired_proposal_v1>?,
                                   UnsafeMutablePointer<qpc_error_v1>?) -> Int32) throws -> RetiredReportProposal? {
        try native.call { handle in
            var value = qpc_retired_proposal_v1(), error = qpc_error_v1()
            try checked(call(handle, &value, &error), &error)
            return try retiredProposal(value)
        }
    }
    /// Local absence is not proof that the witness did not commit.
    public func reportProposal() throws -> RetiredReportProposal? { try proposal(qpc_retired_v1_report_proposal) }
    public func acknowledgementProposal() throws -> RetiredReportProposal? {
        try proposal(qpc_retired_v1_acknowledgement_proposal)
    }
    public func prepareReport(inventoryReceipt: [UInt8]) throws -> RetiredReportProposal {
        guard inventoryReceipt.count == 3690 else { throw ContinuityBoundaryError.inputLength }
        return try native.call { handle in
            var value = qpc_retired_proposal_v1(), error = qpc_error_v1()
            let code = inventoryReceipt.withUnsafeBufferPointer {
                qpc_retired_v1_prepare_report(handle, $0.baseAddress, $0.count, &value, &error)
            }
            try checked(code, &error)
            guard let result = try retiredProposal(value) else { throw ContinuityBoundaryError.malformedOutput }
            return result
        }
    }
    public func loadReport(inventoryReceipt: [UInt8], reportReceipt: [UInt8]) throws -> RetiredDeviceReport {
        guard inventoryReceipt.count == 3690, reportReceipt.count == 3730 else {
            throw ContinuityBoundaryError.inputLength
        }
        return try native.call { handle in
            var info = qpc_retired_report_info_v1(), error = qpc_error_v1()
            let code = inventoryReceipt.withUnsafeBufferPointer { inventory in
                reportReceipt.withUnsafeBufferPointer { report in
                    qpc_retired_v1_load_report(handle, inventory.baseAddress, inventory.count,
                        report.baseAddress, report.count, &info, &error)
                }
            }
            try checked(code, &error)
            guard (323...8388608).contains(info.length), (1...2).contains(info.views), info.reserved_zero == 0 else {
                throw ContinuityBoundaryError.malformedOutput
            }
            var bytes = [UInt8](repeating: 0, count: info.length)
            let copied = bytes.withUnsafeMutableBufferPointer {
                qpc_retired_v1_copy_report(handle, $0.baseAddress, $0.count, &error)
            }
            try checked(copied, &error)
            return try RetiredDeviceReport(info: info, bytes: bytes)
        }
    }
    /// Call only after durably retaining the complete report and accounting by its ID.
    /// Native code checks the saved bytes against the original independently retained report.
    public func prepareAcknowledgement(inventoryReceipt: [UInt8], reportReceipt: [UInt8],
                                       recordedReport: [UInt8]) throws -> RetiredReportProposal {
        guard inventoryReceipt.count == 3690, reportReceipt.count == 3730,
              (1...8388608).contains(recordedReport.count) else { throw ContinuityBoundaryError.inputLength }
        return try native.call { handle in
            var value = qpc_retired_proposal_v1(), error = qpc_error_v1()
            let code = inventoryReceipt.withUnsafeBufferPointer { inventory in
                reportReceipt.withUnsafeBufferPointer { report in
                    recordedReport.withUnsafeBufferPointer { recorded in
                        qpc_retired_v1_prepare_acknowledgement(handle, inventory.baseAddress, inventory.count,
                            report.baseAddress, report.count, recorded.baseAddress, recorded.count, &value, &error)
                    }
                }
            }
            try checked(code, &error)
            guard let result = try retiredProposal(value) else { throw ContinuityBoundaryError.malformedOutput }
            return result
        }
    }
    private func state(_ call: (UInt64, UnsafeMutablePointer<UInt32>?, UnsafeMutablePointer<qpc_error_v1>?) -> Int32)
        throws -> RetiredErasureState {
        try native.call { handle in
            var value: UInt32 = 0, error = qpc_error_v1()
            try checked(call(handle, &value, &error), &error)
            guard let state = RetiredErasureState(rawValue: value) else { throw ContinuityBoundaryError.malformedOutput }
            return state
        }
    }
    public func journalState() throws -> RetiredErasureState { try state(qpc_retired_v1_journal_state) }
    public func signerState() throws -> RetiredErasureState { try state(qpc_retired_v1_signer_state) }
    private func receiptCall(_ receipt: [UInt8], _ call: (UInt64, UnsafePointer<UInt8>?, Int,
                                                        UnsafeMutablePointer<qpc_error_v1>?) -> Int32) throws {
        guard receipt.count == 3730 else { throw ContinuityBoundaryError.inputLength }
        try native.call { handle in
            var error = qpc_error_v1()
            let code = receipt.withUnsafeBufferPointer { call(handle, $0.baseAddress, $0.count, &error) }
            try checked(code, &error)
        }
    }
    public func eraseJournal(hostAcknowledgement: [UInt8]) throws {
        try receiptCall(hostAcknowledgement, qpc_retired_v1_erase_journal)
    }
    public func prepareSignerErasure(hostAcknowledgement: [UInt8]) throws {
        try receiptCall(hostAcknowledgement, qpc_retired_v1_prepare_signer_erasure)
    }
    /// Consumes the native resource even on success. Close the registry handle afterwards.
    public func eraseSigner() throws {
        try native.call { handle in
            var error = qpc_error_v1()
            try checked(qpc_retired_v1_erase_signer(handle, &error), &error)
        }
    }
}
