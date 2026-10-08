// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
import CQPCOwner
@testable import QPeriaptContinuity

final class RetirementTests: XCTestCase {
    func testRetirementLayoutsMatchTheNativeContract() {
        XCTAssertEqual(MemoryLayout<qpc_retired_authority_v1>.size, 176)
        XCTAssertEqual(MemoryLayout<qpc_retired_authority_v1>.offset(of: \.subject), 64)
        XCTAssertEqual(MemoryLayout<qpc_retired_authority_v1>.offset(of: \.receipt), 160)
        XCTAssertEqual(MemoryLayout<qpc_retired_inventory_v1>.size, 313)
        XCTAssertEqual(MemoryLayout<qpc_retired_proposal_v1>.size, 360)
        XCTAssertEqual(MemoryLayout<qpc_retired_proposal_v1>.offset(of: \.reserved_zero), 357)
        XCTAssertEqual(MemoryLayout<qpc_retired_report_info_v1>.size, 48)
        XCTAssertEqual(MemoryLayout<qpc_retired_report_info_v1>.offset(of: \.report), 16)
    }
    func testRetirementAuthorityOwnsBoundedInputsWithoutGrantingTrust() throws {
        var witness = [UInt8](repeating: 1, count: 32), key = [UInt8](repeating: 2, count: 1985)
        var replacement = [UInt8](repeating: 3, count: 57794), subject = [UInt8](repeating: 4, count: 96)
        var receipt = [UInt8](repeating: 5, count: 3754)
        let authority = try RetiredEnrollmentAuthority(witness: witness, publicKey: key, replacement: replacement,
            subject: subject, receipt: receipt)
        witness[0] = 0; key[0] = 0; replacement[0] = 0; subject[0] = 0; receipt[0] = 0
        XCTAssertEqual(authority.witness.first, 1); XCTAssertEqual(authority.publicKey.first, 2)
        XCTAssertEqual(authority.replacement.first, 3); XCTAssertEqual(authority.subject.first, 4)
        XCTAssertEqual(authority.receipt.first, 5)
        for bad in [[UInt8](), [UInt8](repeating: 0, count: 57795)] {
            XCTAssertThrowsError(try RetiredEnrollmentAuthority(witness: witness, publicKey: key,
                replacement: bad, subject: subject, receipt: receipt))
        }
        XCTAssertThrowsError(try RetiredEnrollmentAuthority(witness: Array(witness.dropLast()), publicKey: key,
            replacement: replacement, subject: subject, receipt: receipt))
        XCTAssertThrowsError(try RetiredEnrollmentAuthority(witness: witness, publicKey: Array(key.dropLast()),
            replacement: replacement, subject: subject, receipt: receipt))
        XCTAssertThrowsError(try RetiredEnrollmentAuthority(witness: witness, publicKey: key,
            replacement: replacement, subject: Array(subject.dropLast()), receipt: receipt))
        XCTAssertThrowsError(try RetiredEnrollmentAuthority(witness: witness, publicKey: key,
            replacement: replacement, subject: subject, receipt: Array(receipt.dropLast())))
    }
    private func proposal() -> [UInt8] {
        Array("QPRRPT01QPRCLP01".utf8) + [UInt8](repeating: 1, count: 305) + [UInt8](repeating: 7, count: 32)
    }
    func testRetirementProposalRejectsDirtyAbsenceAndPreservesOriginalIdentity() throws {
        var value = qpc_retired_proposal_v1()
        XCTAssertNil(try retiredProposal(value))
        value.reserved_zero.0 = 1
        XCTAssertThrowsError(try retiredProposal(value))
        value.reserved_zero.0 = 0
        withUnsafeMutableBytes(of: &value.bytes) { $0[0] = 1 }
        XCTAssertThrowsError(try retiredProposal(value))
        value.present = 1
        let bytes = proposal()
        withUnsafeMutableBytes(of: &value.bytes) { $0.copyBytes(from: bytes) }
        let decoded = try XCTUnwrap(retiredProposal(value))
        XCTAssertEqual(decoded.bytes, bytes)
        XCTAssertEqual(decoded.inventory.bytes, Array(bytes[8..<321]))
        XCTAssertEqual(decoded.report.bytes, [UInt8](repeating: 7, count: 32))
        value.present = 2
        XCTAssertThrowsError(try retiredProposal(value))
        value.present = 1
        withUnsafeMutableBytes(of: &value.bytes) { $0[8] = 0 }
        XCTAssertThrowsError(try retiredProposal(value))
        XCTAssertThrowsError(try RetiredReportProposal(bytes: Array(bytes.prefix(352))))
        XCTAssertThrowsError(try RetiredReportProposal(bytes: Array(bytes.prefix(321)) + [UInt8](repeating: 0, count: 32)))
    }
    func testCompleteRetirementReportKeepsBytesSeparateFromItsKeyedID() throws {
        var info = qpc_retired_report_info_v1()
        let bytes = Array("QPRDMD01".utf8) + [UInt8](repeating: 9, count: 400)
        info.length = bytes.count; info.views = 2
        withUnsafeMutableBytes(of: &info.report) { $0.copyBytes(from: [UInt8](repeating: 7, count: 32)) }
        let report = try RetiredDeviceReport(info: info, bytes: bytes)
        XCTAssertEqual(report.canonicalBytes, bytes)
        XCTAssertEqual(report.report.bytes, [UInt8](repeating: 7, count: 32))
        XCTAssertEqual(report.viewCount, 2)
        for count in [0, 322, 8_388_609] {
            var bad = info; bad.length = count
            XCTAssertThrowsError(try RetiredDeviceReport(info: bad, bytes: bytes))
        }
        for views: UInt32 in [0, 3, UInt32.max] {
            var bad = info; bad.views = views
            XCTAssertThrowsError(try RetiredDeviceReport(info: bad, bytes: bytes))
        }
        var bad = info; bad.reserved_zero = 1
        XCTAssertThrowsError(try RetiredDeviceReport(info: bad, bytes: bytes))
        bad = info; withUnsafeMutableBytes(of: &bad.report) { $0.copyBytes(from: [UInt8](repeating: 0, count: 32)) }
        XCTAssertThrowsError(try RetiredDeviceReport(info: bad, bytes: bytes))
        XCTAssertThrowsError(try RetiredDeviceReport(info: info, bytes: Array(bytes.dropLast())))
        XCTAssertThrowsError(try RetiredDeviceReport(info: info, bytes: [UInt8](repeating: 0, count: bytes.count)))
    }
}
