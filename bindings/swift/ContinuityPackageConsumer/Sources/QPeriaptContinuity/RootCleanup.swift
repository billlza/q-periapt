// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation

extension ContinuityAccountAuthority {
    private var retired: RetiredCleanupOperations { RetiredCleanupOperations(native: native) }
    public func retiredInventory() throws -> RetiredInventory { try retired.inventory() }
    public func retiredReportProposal() throws -> RetiredReportProposal? { try retired.reportProposal() }
    public func retiredAcknowledgementProposal() throws -> RetiredReportProposal? { try retired.acknowledgementProposal() }
    public func prepareRetiredReport(inventoryReceipt: [UInt8]) throws -> RetiredReportProposal {
        try retired.prepareReport(inventoryReceipt: inventoryReceipt)
    }
    public func loadRetiredReport(inventoryReceipt: [UInt8], reportReceipt: [UInt8]) throws -> RetiredDeviceReport {
        try retired.loadReport(inventoryReceipt: inventoryReceipt, reportReceipt: reportReceipt)
    }
    /// First durably retain the complete report and account by its original report ID.
    public func prepareRetiredAcknowledgement(inventoryReceipt: [UInt8], reportReceipt: [UInt8],
                                               recordedReport: [UInt8]) throws -> RetiredReportProposal {
        try retired.prepareAcknowledgement(inventoryReceipt: inventoryReceipt, reportReceipt: reportReceipt, recordedReport: recordedReport)
    }
    public func retiredJournalState() throws -> RetiredErasureState { try retired.journalState() }
    public func retiredSignerState() throws -> RetiredErasureState { try retired.signerState() }
    public func eraseRetiredJournal(hostAcknowledgement: [UInt8]) throws { try retired.eraseJournal(hostAcknowledgement: hostAcknowledgement) }
    public func prepareRetiredSignerErasure(hostAcknowledgement: [UInt8]) throws { try retired.prepareSignerErasure(hostAcknowledgement: hostAcknowledgement) }
    /// Erases the historical signer while preserving this controller and the live successor.
    public func eraseRetiredSigner() throws { try retired.eraseSigner() }
}
