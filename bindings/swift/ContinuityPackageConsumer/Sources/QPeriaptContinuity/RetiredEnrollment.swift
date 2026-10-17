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
              (bytes.starts(with: Array("QPRDMD01".utf8)) || bytes.starts(with: Array("QPRDMD02".utf8))) else {
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

    private var cleanup: RetiredCleanupOperations { RetiredCleanupOperations(native: native) }
    public func inventory() throws -> RetiredInventory { try cleanup.inventory() }
    /// Local absence is not proof that the witness did not commit.
    public func reportProposal() throws -> RetiredReportProposal? { try cleanup.reportProposal() }
    public func acknowledgementProposal() throws -> RetiredReportProposal? { try cleanup.acknowledgementProposal() }
    public func prepareReport(inventoryReceipt: [UInt8]) throws -> RetiredReportProposal {
        try cleanup.prepareReport(inventoryReceipt: inventoryReceipt)
    }
    public func loadReport(inventoryReceipt: [UInt8], reportReceipt: [UInt8]) throws -> RetiredDeviceReport {
        try cleanup.loadReport(inventoryReceipt: inventoryReceipt, reportReceipt: reportReceipt)
    }
    /// First durably retain the complete report and account by its original report ID.
    public func prepareAcknowledgement(inventoryReceipt: [UInt8], reportReceipt: [UInt8],
                                       recordedReport: [UInt8]) throws -> RetiredReportProposal {
        try cleanup.prepareAcknowledgement(inventoryReceipt: inventoryReceipt, reportReceipt: reportReceipt, recordedReport: recordedReport)
    }
    public func journalState() throws -> RetiredErasureState { try cleanup.journalState() }
    public func signerState() throws -> RetiredErasureState { try cleanup.signerState() }
    public func eraseJournal(hostAcknowledgement: [UInt8]) throws { try cleanup.eraseJournal(hostAcknowledgement: hostAcknowledgement) }
    public func prepareSignerErasure(hostAcknowledgement: [UInt8]) throws { try cleanup.prepareSignerErasure(hostAcknowledgement: hostAcknowledgement) }
    /// Consumes this cleanup-only resource on success; close its registry handle afterwards.
    public func eraseSigner() throws { try cleanup.eraseSigner() }
}
