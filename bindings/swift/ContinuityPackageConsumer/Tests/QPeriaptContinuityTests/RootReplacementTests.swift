// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
import CQPCOwner
@testable import QPeriaptContinuity

final class RootReplacementTests: XCTestCase {
    private func scope() throws -> RootReplacementScope {
        try RootReplacementScope(checkpoint: AccountAuthorityCheckpoint(
            application: ApplicationAccountID(bytes: [UInt8](repeating: 1, count: 32)), revision: 1,
            account: AccountID(bytes: [UInt8](repeating: 2, count: 32))),
            witness: [UInt8](repeating: 3, count: 32), publicKey: [UInt8](repeating: 4, count: 1985))
    }
    func testRootLayoutsKeepSizePrefixAndAllFourIndependentInputs() throws {
        XCTAssertEqual(MemoryLayout<qpc_root_scope_v1>.size, 128)
        XCTAssertEqual(MemoryLayout<qpc_root_scope_v1>.offset(of: \.checkpoint), 8)
        XCTAssertEqual(MemoryLayout<qpc_root_scope_v1>.offset(of: \.public_key), 112)
        XCTAssertEqual(MemoryLayout<qpc_root_alternative_v1>.size, 72)
        XCTAssertEqual(MemoryLayout<qpc_root_alternative_v1>.offset(of: \.original), 8)
        XCTAssertEqual(MemoryLayout<qpc_root_alternative_v1>.offset(of: \.receipt_length), 64)
        let selected = try scope()
        selected.withNative {
            XCTAssertEqual($0.pointee.struct_size, 128)
            XCTAssertEqual($0.pointee.checkpoint.revision, 1)
            XCTAssertEqual($0.pointee.public_key_length, 1985)
            XCTAssertEqual($0.pointee.public_key?.pointee, 4)
        }
        // Deliberately only grammar/ownership fixtures: no fabricated signed proof.
        var original = Array("QPAFPL01original".utf8), next = Array("QPAFPL01next".utf8)
        var noncommit = [UInt8](repeating: 5, count: 3449), freeze = [UInt8](repeating: 6, count: 5725)
        let approval = try RootReplacementTransition(original: RootReplacementPlan(approvedBytes: original),
            independentlyApprovedNext: RootReplacementPlan(approvedBytes: next), noncommitReceipt: noncommit, freezeReceipt: freeze)
        original[8] = 99; next[8] = 99; noncommit[0] = 99; freeze[0] = 99
        try approval.inputs.withNative {
            XCTAssertEqual($0.pointee.struct_size, 72)
            XCTAssertEqual($0.pointee.original?[8], UInt8(ascii: "o"))
            XCTAssertEqual($0.pointee.approved?[8], UInt8(ascii: "n"))
            XCTAssertEqual($0.pointee.noncommit?.pointee, 5)
            XCTAssertEqual($0.pointee.receipt?.pointee, 6)
            XCTAssertEqual($0.pointee.noncommit_length, 3449)
            XCTAssertEqual($0.pointee.receipt_length, 5725)
        }
    }
    func testRootApprovalsRejectWrongGrammarAndBoundsWithoutClaimingAuthority() throws {
        for bytes in [[], Array("QPAFPL02".utf8), [UInt8](repeating: 0, count: 131073)] {
            XCTAssertThrowsError(try RootReplacementPlan(approvedBytes: bytes))
        }
        for header in ["QPARPL01", "QPARPL02"] {
            XCTAssertEqual(try RootReplacementProposal(approvedBytes: Array(header.utf8)).bytes, Array(header.utf8))
        }
        XCTAssertThrowsError(try RootReplacementProposal.decode(Array("QPARPL03".utf8))) {
            XCTAssertEqual($0 as? ContinuityBoundaryError, .malformedOutput)
        }
        let plan = try RootReplacementPlan(approvedBytes: Array("QPAFPL01".utf8))
        XCTAssertThrowsError(try RootReplacementTransition(original: plan, independentlyApprovedNext: plan,
            noncommitReceipt: [UInt8](repeating: 1, count: 3448), freezeReceipt: [1]))
        XCTAssertThrowsError(try RootReplacementAdoption(original: plan,
            independentlyApprovedWinner: RootReplacementProposal(approvedBytes: Array("QPARPL02".utf8)),
            noncommitReceipt: [UInt8](repeating: 1, count: 3449), retirementReceipt: [1]))
        let good = try scope()
        XCTAssertThrowsError(try RootReplacementScope(checkpoint: good.checkpoint,
            witness: [UInt8](repeating: 0, count: 32), publicKey: good.publicKey))
    }
    func testPendingRegistryCannotGrantRootOrCleanupAuthority() throws {
        let selected = try scope()
        let key = [UInt8](repeating: 0, count: 1952) + [UInt8](arrayLiteral:
            0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
            0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
            0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96)
        let trust = try AccountAuthorityTrust(identity: AccountAuthorityID(bytes: [UInt8](repeating: 7, count: 32)),
            family: [UInt8](repeating: 8, count: 32), witness: selected.witness, publicKey: key)
        let owner = try ContinuityAccountAuthority.prepareOpen(path: "/unused", trust: trust)
        XCTAssertThrowsError(try owner.rootReplacementState()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) }
        XCTAssertThrowsError(try owner.retiredInventory()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) }
        XCTAssertThrowsError(try owner.retainRootRetirement(receipt: [])) {
            XCTAssertEqual($0 as? ContinuityBoundaryError, .inputLength)
        }
        let intent = try EnrollmentIntent(root: key, device: [UInt8](repeating: 9, count: 16), generation: 1,
            family: trust.family, validFrom: 1, validUntil: 100)
        let enrollment = try ContinuityEnrollment.prepareResume(path: "/unused", intent: intent)
        XCTAssertThrowsError(try owner.activateRootSuccessor(enrollment)) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6)
        }
        try enrollment.cancel()
        XCTAssertThrowsError(try enrollment.finishOpen()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 302) }
        try enrollment.close()
        try owner.cancel()
        XCTAssertThrowsError(try owner.finishOpen()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 302) }
        try owner.close()
    }
}
