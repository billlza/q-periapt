// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class CredentialRenewalTests: XCTestCase {
    func testRenewalStatusPreservesHistoricalBindingAndRejectsMalformedCombinations() throws {
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_status_v1>.size, 120)
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_status_v1>.offset(of: \.checkpoint), 72)
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_status_v1>.offset(of: \.observed_at), 112)
        let id = try CredentialRenewalID(bytes: [UInt8](repeating: 1, count: 32))
        let statement = try CredentialRenewalStatementID(bytes: [UInt8](repeating: 2, count: 32))
        let head = try RosterCheckpoint(version: UInt64.max - 1, digest: [UInt8](repeating: 3, count: 32))
        let expected: [CredentialRenewalStatus] = [.absent, .pending(operation: id, statement: statement),
            .committed(operation: id, statement: statement, target: head),
            .expiredUncommitted(operation: id, statement: statement, observedHead: head, observedAt: UInt64.max)]
        for phase: UInt32 in 0...3 {
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
        for phase: UInt32 in [4, 256, UInt32.max] {
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
