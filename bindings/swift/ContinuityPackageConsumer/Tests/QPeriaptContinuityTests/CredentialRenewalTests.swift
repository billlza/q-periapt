// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class CredentialRenewalTests: XCTestCase {
    func testCancellationOwnsTargetFreeBytesAndRejectsProposalOrInvalidHead() throws {
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_cancellation_v1>.size, 248)
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_cancellation_v1>.alignment, 1)
        func number(_ value: UInt64, _ offset: Int, _ bytes: inout [UInt8]) {
            bytes.replaceSubrange(offset..<(offset + 8), with: (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) })
        }
        var bytes = [UInt8](repeating: 1, count: 248)
        bytes.replaceSubrange(0..<8, with: "QPCRNC01".utf8)
        number(UInt64.max - 1, 200, &bytes); number(UInt64.max - 1, 208, &bytes)
        let original = bytes, cancellation = try CredentialRenewalCancellation(nativeBytes: bytes)
        bytes[136] = 7
        XCTAssertEqual(cancellation.bytes, original)
        XCTAssertEqual(cancellation.operation.bytes, Array(original[136..<168]))
        XCTAssertEqual(cancellation.statement.bytes, Array(original[168..<200]))
        XCTAssertThrowsError(try CredentialRenewalProposal(nativeBytes: original))
        var invalid = [Array(original.dropLast()), original + [0], original + [UInt8](repeating: 1, count: 48)]
        for offset in [0, 8, 40, 72, 104, 136, 168, 216] {
            var wrong = original
            wrong.replaceSubrange(offset..<(offset + (offset == 0 ? 8 : 32)), with: repeatElement(UInt8(0), count: offset == 0 ? 8 : 32))
            invalid.append(wrong)
        }
        for offset in [200, 208] {
            for value in [UInt64(0), UInt64.max] {
                var wrong = original; number(value, offset, &wrong); invalid.append(wrong)
            }
        }
        var proposal = original; proposal.replaceSubrange(0..<8, with: "QPCRNP01".utf8); invalid.append(proposal)
        for wrong in invalid {
            XCTAssertThrowsError(try CredentialRenewalCancellation(nativeBytes: wrong)) {
                XCTAssertEqual($0 as? ContinuityBoundaryError, .malformedOutput)
            }
        }
    }
    func testWitnessProposalOwnsCanonicalBytesAndRejectsOverflowOrContradictoryHeads() throws {
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_proposal_v1>.size, 296)
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_proposal_v1>.alignment, 1)
        func number(_ value: UInt64, _ offset: Int, _ bytes: inout [UInt8]) {
            bytes.replaceSubrange(offset..<(offset + 8), with: (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) })
        }
        var bytes = [UInt8](repeating: 1, count: 296)
        bytes.replaceSubrange(0..<8, with: "QPCRNP01".utf8)
        number(UInt64.max - 1, 200, &bytes); number(UInt64.max - 1, 248, &bytes)
        number(UInt64.max - 2, 208, &bytes); number(UInt64.max - 1, 256, &bytes)
        bytes[264] = 2
        let original = bytes, proposal = try CredentialRenewalProposal(nativeBytes: bytes)
        bytes[136] = 7
        XCTAssertEqual(proposal.bytes, original)
        XCTAssertEqual(proposal.operation.bytes, Array(original[136..<168]))
        XCTAssertEqual(proposal.statement.bytes, Array(original[168..<200]))
        var invalid = [Array(original.dropLast()), original + [0]]
        for offset in [0, 8, 40, 72, 104, 136, 168, 216, 264] {
            var wrong = original
            wrong.replaceSubrange(offset..<(offset + (offset == 0 ? 8 : 32)), with: repeatElement(UInt8(0), count: offset == 0 ? 8 : 32))
            invalid.append(wrong)
        }
        for (offset, value): (Int, UInt64) in [(200, 0), (200, UInt64.max), (248, 1), (208, 0),
                                               (208, UInt64.max), (208, UInt64.max - 1), (256, UInt64.max), (256, 1)] {
            var wrong = original; number(value, offset, &wrong); invalid.append(wrong)
        }
        var unchanged = original; unchanged.replaceSubrange(264..<296, with: original[216..<248]); invalid.append(unchanged)
        for wrong in invalid {
            XCTAssertThrowsError(try CredentialRenewalProposal(nativeBytes: wrong)) {
                XCTAssertEqual($0 as? ContinuityBoundaryError, .malformedOutput)
            }
        }
    }
    func testRenewalStatusPreservesHistoricalBindingAndRejectsMalformedCombinations() throws {
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_status_v1>.size, 120)
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_status_v1>.offset(of: \.checkpoint), 72)
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_status_v1>.offset(of: \.observed_at), 112)
        let id = try CredentialRenewalID(bytes: [UInt8](repeating: 1, count: 32))
        let statement = try CredentialRenewalStatementID(bytes: [UInt8](repeating: 2, count: 32))
        let head = try RosterCheckpoint(version: UInt64.max - 1, digest: [UInt8](repeating: 3, count: 32))
        let expected: [CredentialRenewalStatus] = [.absent, .pending(operation: id, statement: statement),
            .committed(operation: id, statement: statement, target: head),
            .expiredUncommitted(operation: id, statement: statement, observedHead: head, observedAt: UInt64.max),
            .closed(operation: id, statement: statement, target: head)]
        for phase: UInt32 in 0...4 {
            var raw = qpc_credential_renewal_status_v1(); raw.phase = phase
            if phase > 0 {
                withUnsafeMutableBytes(of: &raw.operation) { $0.copyBytes(from: id.bytes) }
                withUnsafeMutableBytes(of: &raw.statement) { $0.copyBytes(from: statement.bytes) }
            }
            if phase >= 2 { raw.checkpoint = head.native() }
            if phase == 3 { raw.observed_at = UInt64.max }
            XCTAssertEqual(try decodeCredentialRenewalStatus(&raw), expected[Int(phase)])
            for field in 0...3 {
                var wrong = raw
                switch field {
                case 0: withUnsafeMutableBytes(of: &wrong.operation) { _ = $0.initializeMemory(as: UInt8.self, repeating: phase == 0 ? 1 : 0) }
                case 1: withUnsafeMutableBytes(of: &wrong.statement) { _ = $0.initializeMemory(as: UInt8.self, repeating: phase == 0 ? 1 : 0) }
                case 2: wrong.checkpoint.version = phase >= 2 ? 0 : 1
                default: wrong.observed_at = phase == 3 ? 0 : 1
                }
                XCTAssertThrowsError(try decodeCredentialRenewalStatus(&wrong)) {
                    XCTAssertEqual($0 as? ContinuityBoundaryError, .malformedOutput)
                }
            }
            var wrong = raw
            withUnsafeMutableBytes(of: &wrong.checkpoint.digest) { _ = $0.initializeMemory(as: UInt8.self, repeating: phase >= 2 ? 0 : 1) }
            XCTAssertThrowsError(try decodeCredentialRenewalStatus(&wrong))
        }
        for phase: UInt32 in [5, 256, UInt32.max] {
            var raw = qpc_credential_renewal_status_v1(); raw.phase = phase
            XCTAssertThrowsError(try decodeCredentialRenewalStatus(&raw))
        }
    }

    func testOriginalRenewalIdentitiesOwnBytesAndRejectZeroOrWrongWidths() throws {
        var bytes = [UInt8](repeating: 1, count: 32)
        let operation = try CredentialRenewalID(bytes: bytes), statement = try CredentialRenewalStatementID(bytes: bytes)
        bytes[0] = 9
        XCTAssertEqual(operation.bytes, [UInt8](repeating: 1, count: 32))
        XCTAssertEqual(statement.bytes, operation.bytes)
        for invalid in [[], [UInt8](repeating: 0, count: 32), [UInt8](repeating: 1, count: 31), [UInt8](repeating: 1, count: 33)] {
            XCTAssertThrowsError(try CredentialRenewalID(bytes: invalid))
            XCTAssertThrowsError(try CredentialRenewalStatementID(bytes: invalid))
        }
    }
}
