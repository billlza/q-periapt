// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

/// Original independent application checkpoint and witness pin. Neither a receipt
/// nor a proposed successor may choose this expectation for the caller.
public struct RootReplacementScope: Sendable {
    public let checkpoint: AccountAuthorityCheckpoint
    public let witness: [UInt8]
    public let publicKey: [UInt8]
    public init(checkpoint: AccountAuthorityCheckpoint, witness: [UInt8], publicKey: [UInt8]) throws {
        guard witness.count == 32, publicKey.count == 1985 else { throw ContinuityBoundaryError.inputLength }
        guard witness.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.checkpoint = checkpoint; self.witness = witness; self.publicKey = publicKey
    }
    func withNative<T>(_ body: (UnsafePointer<qpc_root_scope_v1>) throws -> T) rethrows -> T {
        try publicKey.withUnsafeBufferPointer { key in
            var value = qpc_root_scope_v1()
            value.struct_size = UInt32(MemoryLayout.size(ofValue: value)); value.checkpoint = checkpoint.native()
            withUnsafeMutableBytes(of: &value.witness) { $0.copyBytes(from: witness) }
            value.public_key = key.baseAddress; value.public_key_length = key.count
            return try withUnsafePointer(to: &value, body)
        }
    }
}

/// Independently approved canonical plan. Width/grammar checks do not confer trust;
/// native admission verifies its exact scope against the retained original owner.
public struct RootReplacementPlan: Sendable, Equatable {
    public let bytes: [UInt8]
    public init(approvedBytes: [UInt8]) throws {
        guard (8...131072).contains(approvedBytes.count), approvedBytes.prefix(8).elementsEqual("QPAFPL01".utf8) else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        bytes = approvedBytes
    }
}
/// Exact proposal returned after binding, or independently approved for adoption.
public struct RootReplacementProposal: Sendable, Equatable {
    public let bytes: [UInt8]
    public init(approvedBytes: [UInt8]) throws {
        guard (8...65536).contains(approvedBytes.count), (approvedBytes.prefix(8).elementsEqual("QPARPL01".utf8) || approvedBytes.prefix(8).elementsEqual("QPARPL02".utf8)) else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        bytes = approvedBytes
    }
    static func decode(_ bytes: [UInt8]) throws -> Self {
        guard (8...65536).contains(bytes.count), (bytes.prefix(8).elementsEqual("QPARPL01".utf8) || bytes.prefix(8).elementsEqual("QPARPL02".utf8)) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        return try Self(approvedBytes: bytes)
    }
}
/// Durable history only. A committed root still needs current successor activation.
public enum RootReplacementState: UInt32, Sendable { case preparing = 1, pending = 2, committed = 3, closed = 4 }

struct RootAlternativeInputs: Sendable {
    let original: [UInt8], approved: [UInt8], noncommit: [UInt8], receipt: [UInt8]
    init(original: [UInt8], approved: [UInt8], noncommit: [UInt8], receipt: [UInt8]) throws {
        guard noncommit.count == 3449, (1...131072).contains(receipt.count) else { throw ContinuityBoundaryError.inputLength }
        self.original = original; self.approved = approved; self.noncommit = noncommit; self.receipt = receipt
    }
    func withNative<T>(_ body: (UnsafePointer<qpc_root_alternative_v1>) throws -> T) throws -> T {
        try configurationBlobs([original, approved, noncommit, receipt]) { blobs in
            var value = qpc_root_alternative_v1()
            value.struct_size = UInt32(MemoryLayout.size(ofValue: value))
            value.original = blobs[0].data; value.original_length = blobs[0].length
            value.approved = blobs[1].data; value.approved_length = blobs[1].length
            value.noncommit = blobs[2].data; value.noncommit_length = blobs[2].length
            value.receipt = blobs[3].data; value.receipt_length = blobs[3].length
            return try withUnsafePointer(to: &value, body)
        }
    }
}
/// Retain these exact inputs across crashes. Noncommit does not authorize selecting
/// a new target; the next plan needs separate independent approval.
public struct RootReplacementTransition: Sendable {
    public let original: RootReplacementPlan, next: RootReplacementPlan
    public let noncommitReceipt: [UInt8], freezeReceipt: [UInt8]
    let inputs: RootAlternativeInputs
    public init(original: RootReplacementPlan, independentlyApprovedNext: RootReplacementPlan,
                noncommitReceipt: [UInt8], freezeReceipt: [UInt8]) throws {
        inputs = try RootAlternativeInputs(original: original.bytes, approved: independentlyApprovedNext.bytes,
            noncommit: noncommitReceipt, receipt: freezeReceipt)
        self.original = original; next = independentlyApprovedNext
        self.noncommitReceipt = noncommitReceipt; self.freezeReceipt = freezeReceipt
    }
}
/// Exact independently approved committed winner plus the losing plan's signed
/// noncommit. Historical retirement is not live permission for successor traffic.
public struct RootReplacementAdoption: Sendable {
    public let original: RootReplacementPlan, winner: RootReplacementProposal
    public let noncommitReceipt: [UInt8], retirementReceipt: [UInt8]
    let inputs: RootAlternativeInputs
    public init(original: RootReplacementPlan, independentlyApprovedWinner: RootReplacementProposal,
                noncommitReceipt: [UInt8], retirementReceipt: [UInt8]) throws {
        guard retirementReceipt.count == 3449 else { throw ContinuityBoundaryError.inputLength }
        inputs = try RootAlternativeInputs(original: original.bytes, approved: independentlyApprovedWinner.bytes,
            noncommit: noncommitReceipt, receipt: retirementReceipt)
        self.original = original; winner = independentlyApprovedWinner
        self.noncommitReceipt = noncommitReceipt; self.retirementReceipt = retirementReceipt
    }
}
