// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
import CQPCOwner
@testable import QPeriaptContinuity

final class ServerTests: XCTestCase {
    func testCallbackCopiesBorrowedRegions() throws {
        var retained: ReceivedMessage?
        let invocation = CommitInvocation { retained = $0 }
        var session = [UInt8](repeating: 1, count: 32)
        var message = [UInt8](repeating: 2, count: 32)
        var plaintext = [UInt8](repeating: 3, count: 16384)
        let status = session.withUnsafeBufferPointer { session in
            message.withUnsafeBufferPointer { message in
                plaintext.withUnsafeBufferPointer {
                    invocation.invoke(session: session.baseAddress, message: message.baseAddress,
                        plaintext: $0.baseAddress, length: $0.count)
                }
            }
        }
        XCTAssertEqual(status, 0)
        session[0] = 9; message[0] = 9; plaintext[0] = 9
        XCTAssertEqual(retained?.session.bytes.first, 1)
        XCTAssertEqual(retained?.message.bytes.first, 2)
        XCTAssertEqual(retained?.plaintext.first, 3)
        XCTAssertEqual(retained?.plaintext.count, 16384)
        XCTAssertNil(invocation.failure)
    }

    func testCallbackFailureAndForeignBoundsCannotBecomeConsumption() throws {
        XCTAssertThrowsError(try ApplicationCommitRefusal(status: 0, reason: "unresolved")) {
            XCTAssertEqual($0 as? ContinuityBoundaryError, .invalidCommitStatus)
        }
        let original = try ApplicationCommitRefusal(status: 29, reason: "external commit unknown")
        let invocation = CommitInvocation { message in
            XCTAssertEqual(message.plaintext, [])
            throw original
        }
        let id = [UInt8](repeating: 1, count: 32)
        let status = id.withUnsafeBufferPointer {
            invocation.invoke(session: $0.baseAddress, message: $0.baseAddress, plaintext: nil, length: 0)
        }
        XCTAssertEqual(status, 29)
        XCTAssertEqual(invocation.failure as? ApplicationCommitRefusal, original)
        let bounded = CommitInvocation { _ in XCTFail("invalid foreign regions reached the application") }
        XCTAssertEqual(bounded.invoke(session: nil, message: nil, plaintext: nil, length: 0), 1)
        XCTAssertEqual(bounded.failure as? ContinuityBoundaryError, .malformedOutput)
        id.withUnsafeBufferPointer {
            XCTAssertEqual(bounded.invoke(session: $0.baseAddress, message: $0.baseAddress,
                plaintext: nil, length: 16385), 1)
        }
    }

    func testServedRecordRejectsUnknownKindsAndInconsistentBootstrap() throws {
        var record = qpc_served_v1()
        XCTAssertThrowsError(try servedExchange(&record))
        record.kind = 1; record.duplicate = 1
        XCTAssertThrowsError(try servedExchange(&record))
        record.duplicate = 0
        withUnsafeMutableBytes(of: &record.message) { $0[0] = 1 }
        XCTAssertThrowsError(try servedExchange(&record))
        record.kind = 2; record.duplicate = 2
        XCTAssertThrowsError(try servedExchange(&record))
        record.duplicate = 1
        guard case .consumed(_, _, true) = try servedExchange(&record) else {
            return XCTFail("duplicate was not retained")
        }
    }
}
