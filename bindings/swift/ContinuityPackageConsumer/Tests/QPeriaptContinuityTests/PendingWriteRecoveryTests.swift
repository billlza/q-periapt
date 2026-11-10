// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class PendingWriteRecoveryTests: XCTestCase {
    // Framing fixture only. Zero-filled views are not cryptographic approvals.
    private func framed() -> (proposal: [UInt8], metadata: [UInt8]) {
        let proposal = Array("QPWRPL01".utf8) + [UInt8](repeating: 7, count: 385)
        let view = [UInt8](repeating: 0, count: 96)
        let length: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 96]
        let metadata = Array("QPWRMD01".utf8) + Array(proposal[8..<361]) + length + view + length + view
        return (proposal, metadata)
    }
    func testPendingRequestLayoutAndIndependentCompleteSnapshot() throws {
        XCTAssertEqual(MemoryLayout<qpc_pending_write_request_info_v1>.size, 436)
        XCTAssertEqual(MemoryLayout<qpc_pending_write_request_info_v1>.alignment, 4)
        XCTAssertEqual(MemoryLayout<qpc_pending_write_request_info_v1>.offset(of: \.binding), 404)
        var fixture = framed()
        let request = try PendingWriteRecoveryRequest(proposal: fixture.proposal, binding: [UInt8](repeating: 2, count: 32),
            metadata: fixture.metadata, signedRequest: [1])
        fixture.metadata[8] = 99; fixture.proposal[8] = 99
        XCTAssertEqual(request.metadata, framed().metadata); XCTAssertEqual(request.proposal, framed().proposal)
    }
    func testPendingMetadataRejectsScopeFramingAndOverflow() throws {
        let fixture = framed()
        var invalid = [Array(fixture.metadata.dropLast()), fixture.metadata + [0]]
        var changed = fixture.metadata; changed[8] ^= 1; invalid.append(changed)
        changed = fixture.metadata; changed[361] = 255; invalid.append(changed)
        changed = fixture.metadata; changed[368] = 95; invalid.append(changed)
        for bytes in invalid {
            XCTAssertThrowsError(try PendingWriteRecoveryRequest(proposal: fixture.proposal,
                binding: [UInt8](repeating: 2, count: 32), metadata: bytes, signedRequest: [1])) {
                XCTAssertEqual($0 as? ContinuityBoundaryError, .malformedOutput)
            }
        }
    }
    func testPendingRequestFailurePreservesOutput() {
        var info = qpc_pending_write_request_info_v1(), error = qpc_error_v1()
        withUnsafeMutableBytes(of: &info) { $0.copyBytes(from: repeatElement(UInt8(37), count: $0.count)) }
        let before = withUnsafeBytes(of: &info) { Array($0) }
        XCTAssertEqual(qpc_enrollment_v1_pending_write_request(0, &info, &error), 2)
        XCTAssertEqual(withUnsafeBytes(of: &info) { Array($0) }, before)
    }
}
