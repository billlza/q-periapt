// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

// Shared marshalling only; no public cleanup view can extend a controller lifetime.
struct RetiredCleanupOperations: Sendable {
    let native: NativeOwner
    func inventory() throws -> RetiredInventory {
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
    func reportProposal() throws -> RetiredReportProposal? { try proposal(qpc_retired_v1_report_proposal) }
    func acknowledgementProposal() throws -> RetiredReportProposal? {
        try proposal(qpc_retired_v1_acknowledgement_proposal)
    }
    func prepareReport(inventoryReceipt: [UInt8]) throws -> RetiredReportProposal {
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
    func loadReport(inventoryReceipt: [UInt8], reportReceipt: [UInt8]) throws -> RetiredDeviceReport {
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
    func prepareAcknowledgement(inventoryReceipt: [UInt8], reportReceipt: [UInt8],
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
    func journalState() throws -> RetiredErasureState { try state(qpc_retired_v1_journal_state) }
    func signerState() throws -> RetiredErasureState { try state(qpc_retired_v1_signer_state) }
    private func receiptCall(_ receipt: [UInt8], _ call: (UInt64, UnsafePointer<UInt8>?, Int,
                                                        UnsafeMutablePointer<qpc_error_v1>?) -> Int32) throws {
        guard receipt.count == 3730 else { throw ContinuityBoundaryError.inputLength }
        try native.call { handle in
            var error = qpc_error_v1()
            let code = receipt.withUnsafeBufferPointer { call(handle, $0.baseAddress, $0.count, &error) }
            try checked(code, &error)
        }
    }
    func eraseJournal(hostAcknowledgement: [UInt8]) throws {
        try receiptCall(hostAcknowledgement, qpc_retired_v1_erase_journal)
    }
    func prepareSignerErasure(hostAcknowledgement: [UInt8]) throws {
        try receiptCall(hostAcknowledgement, qpc_retired_v1_prepare_signer_erasure)
    }
    // Native owner kind controls whether signer erasure consumes the cleanup
    // owner or preserves the managed root controller and its live successor.
    func eraseSigner() throws {
        try native.call { handle in
            var error = qpc_error_v1()
            try checked(qpc_retired_v1_erase_signer(handle, &error), &error)
        }
    }
}
