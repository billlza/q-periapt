// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class PolicyContinuationTests: XCTestCase {
    private func metadata(proposal: Bool, policy: Bool, adopt: Bool = true) -> [UInt8] {
        let base = proposal ? 296 : 248
        var bytes = [UInt8](repeating: 1, count: base + (policy ? 33 : 0))
        let tag = (proposal ? "QPCRNP" : "QPCRNC") + (policy ? "02" : "01")
        bytes.replaceSubrange(0..<8, with: tag.utf8)
        func number(_ value: UInt64, _ offset: Int) {
            bytes.replaceSubrange(offset..<(offset + 8), with: (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) })
        }
        number(3, 200); number(7, 208)
        if proposal { number(3, 248); number(8, 256); bytes[264] = 3 }
        if policy {
            bytes[base] = adopt ? 1 : 0
            bytes.replaceSubrange((base + 1)..<(base + 33), with: repeatElement(UInt8(9), count: 32))
        }
        return bytes
    }
    func testIndependentPolicyDocumentOwnsInputAndMatchesNativeLayout() throws {
        XCTAssertEqual(MemoryLayout<qpc_policy_document_v1>.size, 104)
        XCTAssertEqual(MemoryLayout<qpc_policy_document_v1>.alignment, 8)
        XCTAssertEqual(MemoryLayout<qpc_policy_document_v1>.offset(of: \.version), 48)
        XCTAssertEqual(MemoryLayout<qpc_policy_document_v1>.offset(of: \.wire), 88)
        var root = [UInt8](repeating: 1, count: 1985), wire = [UInt8](repeating: 2, count: 19)
        let family = [UInt8](repeating: 3, count: 32)
        let checkpoint = try PolicyCheckpoint(version: 2, digest: [UInt8](repeating: 4, count: 32))
        let document = try PolicyDocument(root: root, family: family, checkpoint: checkpoint, wire: wire)
        root[0] = 9; wire[0] = 9
        XCTAssertEqual(document.root.first, 1); XCTAssertEqual(document.wire.first, 2)
        try document.withNative { pointer in
            let native = pointer.pointee
            XCTAssertEqual(native.root_length, 1985); XCTAssertEqual(native.wire_length, 19)
            XCTAssertEqual(native.version, 2)
            XCTAssertEqual(Array(UnsafeBufferPointer(start: try XCTUnwrap(native.root), count: native.root_length)), document.root)
            XCTAssertEqual(Array(UnsafeBufferPointer(start: try XCTUnwrap(native.wire), count: native.wire_length)), document.wire)
        }
        XCTAssertThrowsError(try PolicyDocument(root: [], family: family, checkpoint: checkpoint, wire: wire))
        XCTAssertThrowsError(try PolicyDocument(root: root, family: family, checkpoint: checkpoint, wire: []))
        XCTAssertThrowsError(try PolicyCheckpoint(version: 0, digest: checkpoint.digest))
        XCTAssertThrowsError(try PolicyCheckpoint(version: 1, digest: [UInt8](repeating: 0, count: 32)))
        XCTAssertThrowsError(try PolicyContinuationStatementID(bytes: [UInt8](repeating: 0, count: 32)))
    }
    func testExtendedProposalAndCancellationPreserveGAndTWithExplicitTransactionMode() throws {
        for adopt in [false, true] {
            var bytes = metadata(proposal: true, policy: true, adopt: adopt)
            let proposal = try PolicyRenewalProposal(nativeBytes: bytes)
            let cancellation = try PolicyRenewalCancellation(nativeBytes: metadata(proposal: false, policy: true, adopt: adopt))
            bytes[297] = 6
            XCTAssertEqual(proposal.policyStatement?.bytes, [UInt8](repeating: 9, count: 32))
            XCTAssertEqual(proposal.adoptsPolicy, adopt); XCTAssertEqual(cancellation.adoptsPolicy, adopt)
            XCTAssertEqual(proposal.statement.bytes, [UInt8](repeating: adopt ? 9 : 1, count: 32))
            XCTAssertEqual(cancellation.statement, proposal.statement)
            XCTAssertEqual(proposal.credentialStatement.bytes, [UInt8](repeating: 1, count: 32))
            XCTAssertThrowsError(try CredentialRenewalProposal(nativeBytes: proposal.bytes))
            XCTAssertThrowsError(try CredentialRenewalCancellation(nativeBytes: cancellation.bytes))
        }
        let legacy = try PolicyRenewalProposal(nativeBytes: metadata(proposal: true, policy: false))
        XCTAssertNil(legacy.policyStatement); XCTAssertFalse(legacy.adoptsPolicy)
        XCTAssertEqual(legacy.statement, legacy.credentialStatement)
        XCTAssertNil(try PolicyRenewalCancellation(nativeBytes: metadata(proposal: false, policy: false)).policyStatement)
    }
    func testExtendedMetadataRejectsInvalidModeTVersionAndWidth() throws {
        for proposal in [false, true] {
            let base = proposal ? 296 : 248
            let bytes = metadata(proposal: proposal, policy: true)
            var invalid = [Array(bytes.dropLast()), bytes + [0]]
            var mode = bytes; mode[base] = 2; invalid.append(mode)
            var noT = bytes; noT.replaceSubrange((base + 1)..<(base + 33), with: repeatElement(UInt8(0), count: 32)); invalid.append(noT)
            var version = bytes; version[7] = 0x31; invalid.append(version)
            for value in invalid {
                if proposal {
                    XCTAssertThrowsError(try PolicyRenewalProposal(nativeBytes: value)) {
                        XCTAssertEqual($0 as? ContinuityBoundaryError, .malformedOutput)
                    }
                } else {
                    XCTAssertThrowsError(try PolicyRenewalCancellation(nativeBytes: value)) {
                        XCTAssertEqual($0 as? ContinuityBoundaryError, .malformedOutput)
                    }
                }
            }
        }
    }
    func testVariableNativeRecordsCheckPayloadTailAndExcludeABIPadding() throws {
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_proposal_v1>.size, 336)
        XCTAssertEqual(MemoryLayout<qpc_policy_renewal_cancellation_v1>.size, 288)
        let proposal = metadata(proposal: true, policy: false)
        var raw = qpc_policy_renewal_proposal_v1(); raw.length = 296
        withUnsafeMutableBytes(of: &raw) { record in
            record[4..<(4 + proposal.count)].copyBytes(from: proposal)
            for offset in 333..<336 { record[offset] = 0xA5 }
        }
        XCTAssertEqual(try policyProposalBytes(&raw), proposal)
        withUnsafeMutableBytes(of: &raw) { $0[300] = 1 }
        XCTAssertThrowsError(try policyProposalBytes(&raw))
        raw.length = 328; XCTAssertThrowsError(try policyProposalBytes(&raw))
        let cancellation = metadata(proposal: false, policy: false)
        var cancel = qpc_policy_renewal_cancellation_v1(); cancel.length = 248
        withUnsafeMutableBytes(of: &cancel) { record in
            record[4..<(4 + cancellation.count)].copyBytes(from: cancellation)
            for offset in 285..<288 { record[offset] = 0xA5 }
        }
        XCTAssertEqual(try policyCancellationBytes(&cancel), cancellation)
        withUnsafeMutableBytes(of: &cancel) { $0[252] = 1 }
        XCTAssertThrowsError(try policyCancellationBytes(&cancel))
    }
}
