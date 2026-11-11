// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class CredentialRequestTests: XCTestCase {
    private func fill<T>(_ value: inout T, _ byte: UInt8) {
        withUnsafeMutableBytes(of: &value) { $0.copyBytes(from: repeatElement(byte, count: $0.count)) }
    }
    private func record() throws -> qpc_credential_renewal_request_v1 {
        var raw = qpc_credential_renewal_request_v1()
        fill(&raw.operation, 1); fill(&raw.journal, 2); fill(&raw.original_owner, 3)
        fill(&raw.original_policy_digest, 4); fill(&raw.current_policy.digest, 4); raw.current_policy.version = 1
        fill(&raw.previous_roster_checkpoint.digest, 5); raw.previous_roster_checkpoint.version = 1
        raw.original_roster_checkpoint = raw.previous_roster_checkpoint
        raw.previous_valid_until = 100; fill(&raw.account, 6)
        raw.original_credential = try publicPolicyRecord([11]); raw.original_roster = try publicPolicyRecord([12,13])
        raw.previous_credential = try publicPolicyRecord([14]); raw.previous_roster = try publicPolicyRecord([15,16])
        return raw
    }
    func testCredentialRequestNativeLayoutAndOwnedHistoricalFields() throws {
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_request_v1>.size, 33120)
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_request_v1>.alignment, 8)
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_request_v1>.offset(of: \.has_current_policy_authorization), 200)
        XCTAssertEqual(MemoryLayout<qpc_credential_renewal_request_v1>.offset(of: \.original_credential), 336)
        var raw = try record(); raw.has_current_policy_authorization = 1; fill(&raw.current_policy_authorization, 7)
        raw.previous_roster_checkpoint.version = UInt64.max - 1
        raw.previous_valid_from = UInt64.max - 2; raw.previous_valid_until = UInt64.max - 1
        let request = try CredentialRenewalRequest(native: &raw)
        raw.original_credential = try publicPolicyRecord([99]); fill(&raw.original_owner, 99)
        XCTAssertEqual(request.originalCredential, [11]); XCTAssertEqual(request.previousRoster, [15,16])
        XCTAssertEqual(request.originalOwner, [UInt8](repeating: 3, count: 32))
        XCTAssertEqual(request.currentPolicyAuthorization?.bytes, [UInt8](repeating: 7, count: 32))
        XCTAssertEqual(request.previousRosterCheckpoint.version, UInt64.max - 1)
        XCTAssertEqual(request.previousValidFrom, UInt64.max - 2); XCTAssertEqual(request.previousValidUntil, UInt64.max - 1)
    }
    func testCredentialRequestRejectsContradictoryMetadataAndDirtyRecords() throws {
        let valid = try record()
        var cases = [qpc_credential_renewal_request_v1]()
        var raw = valid; raw.reserved = 1; cases.append(raw)
        raw = valid; raw.has_current_policy_authorization = 2; cases.append(raw)
        raw = valid; raw.has_current_policy_authorization = 1; cases.append(raw)
        raw = valid; fill(&raw.current_policy_authorization, 8); cases.append(raw)
        raw = valid; fill(&raw.current_policy.digest, 8); cases.append(raw)
        raw = valid; raw.original_roster_checkpoint.version = 2; cases.append(raw)
        raw = valid; fill(&raw.original_roster_checkpoint.digest, 8); cases.append(raw)
        raw = valid; raw.previous_valid_until = UInt64.max; cases.append(raw)
        raw = valid; raw.previous_valid_from = 100; cases.append(raw)
        raw = valid; raw.original_credential.length = 0; cases.append(raw)
        raw = valid; withUnsafeMutableBytes(of: &raw.original_credential) { $0[5] = 1 }; cases.append(raw)
        for var invalid in cases {
            XCTAssertThrowsError(try CredentialRenewalRequest(native: &invalid)) {
                XCTAssertEqual($0 as? ContinuityBoundaryError, .malformedOutput)
            }
        }
        var original = valid
        XCTAssertNil(try CredentialRenewalRequest(native: &original).currentPolicyAuthorization)
    }
    func testCredentialRequestFailureLeavesOutputUntouched() throws {
        for witnessed in [false, true] {
            var raw = try record(), error = qpc_error_v1()
            let before = withUnsafeBytes(of: &raw) { Array($0) }
            let code = [UInt8](repeating: 1, count: 32).withUnsafeBufferPointer {
                witnessed ? qpc_enrollment_v1_witnessed_credential_renewal_request(0, $0.baseAddress, &raw, &error)
                    : qpc_enrollment_v1_credential_renewal_request(0, $0.baseAddress, &raw, &error)
            }
            XCTAssertEqual(code, 2)
            XCTAssertEqual(withUnsafeBytes(of: &raw) { Array($0) }, before)
        }
    }
}
