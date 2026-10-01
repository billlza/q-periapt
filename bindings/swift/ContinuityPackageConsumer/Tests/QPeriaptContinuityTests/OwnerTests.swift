// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class OwnerTests: XCTestCase {
    func testDiagnosticRejectsInconsistentAndInvalidUTF8() throws {
        var error = qpc_error_v1()
        XCTAssertThrowsError(try checked(302, &error))
        error.code = 302; error.length = 1
        withUnsafeMutableBytes(of: &error.message) { $0[0] = 255 }
        XCTAssertThrowsError(try checked(302, &error))
        withUnsafeMutableBytes(of: &error.message) { $0[0] = 65 }
        error.truncated = 1
        XCTAssertThrowsError(try checked(302, &error)) {
            XCTAssertEqual($0 as? ContinuityFailure, ContinuityFailure(code: 302, message: "A", truncated: true))
        }
        error.length = 513
        XCTAssertThrowsError(try checked(302, &error))
    }

    func testIDsAndTextsRejectAmbiguousInput() throws {
        XCTAssertThrowsError(try SessionID(bytes: [UInt8](repeating: 0, count: 31)))
        XCTAssertThrowsError(try MessageID(bytes: [UInt8](repeating: 0, count: 33)))
        XCTAssertThrowsError(try ContinuityOwner.prepare(path: "bad\0path", quality: .oneTimeBoth))
        XCTAssertThrowsError(try ContinuityOwner.prepare(path: String(repeating: "x", count: 4097), quality: .oneTimeBoth))
        XCTAssertThrowsError(try ContinuityOwner.prepare(path: "/unused", quality: .oneTimeBoth,
            witness: .mutualTLS(address: "127.0.0.1:1", timeoutMilliseconds: 0))) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 1)
        }
    }

    func testARCRetiresPendingSlotsAndClosedAliases() throws {
        for _ in 0..<256 {
            // No explicit close: ARC must release more than the 64-slot capacity.
            _ = try ContinuityOwner.prepare(path: "/unused", quality: .oneTimeBoth)
        }
        let first = try ContinuityOwner.prepare(path: "/unused", quality: .oneTimeBoth)
        let alias = first
        try first.close()
        XCTAssertThrowsError(try alias.cancel()) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2)
        }
        let second = try ContinuityOwner.prepare(path: "/unused", quality: .oneTimeBoth)
        XCTAssertThrowsError(try alias.close()) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2)
        }
        try second.cancel()
        XCTAssertThrowsError(try second.finishOpen()) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 302)
        }
        try second.close()
    }
}
