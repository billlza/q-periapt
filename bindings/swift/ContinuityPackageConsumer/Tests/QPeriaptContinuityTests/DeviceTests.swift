// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class DeviceTests: XCTestCase {
    func testPreparedDeviceCapacityCancellationAndNoPrematurePeerAuthority() throws {
        for _ in 0..<128 { _ = try ContinuityDevice.prepare(path: "/unused") }
        let parents = try (0..<64).map { _ in try ContinuityDevice.prepare(path: "/unused") }
        XCTAssertThrowsError(try ContinuityDevice.prepare(path: "/unused")) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 4)
        }
        let parent = try XCTUnwrap(parents.first)
        XCTAssertThrowsError(try parent.preparePeer(path: "/unused", quality: .oneTimeBoth, role: .initiator)) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6)
        }
        let operation = try AccountOperationID(bytes: [UInt8](repeating: 1, count: 32))
        let account = try AccountID(bytes: [UInt8](repeating: 2, count: 32))
        XCTAssertThrowsError(try parent.sendAccountMember(operation: operation, account: account,
            targets: [], selected: 0, address: "127.0.0.1:1", plaintext: [], associatedData: [])) {
            XCTAssertEqual($0 as? ContinuityBoundaryError, .inputLength)
        }
        try parent.cancel()
        XCTAssertThrowsError(try parent.finishOpen()) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 302)
        }
        try parent.close()
        XCTAssertThrowsError(try parent.preparePeer(path: "/unused", quality: .oneTimeBoth, role: .responder)) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2)
        }
        let replacement = try ContinuityDevice.prepare(path: "/unused")
        try replacement.close()
        for parent in parents.dropFirst() { try parent.close() }
    }

    func testAggregateStatusRequiresTheExactReportShapeAndPreservesUnknownStates() throws {
        let zero = [UInt8](repeating: 0, count: 32), nonzero = [UInt8](repeating: 9, count: 32)
        XCTAssertEqual(try accountStatus(0, report: zero), .absent)
        XCTAssertEqual(try accountStatus(1, report: zero), .reserved)
        XCTAssertEqual(try accountStatus(2, report: zero), .committed)
        XCTAssertEqual(try accountStatus(5, report: zero), .retired)
        let id = try AccountAbandonmentID(bytes: nonzero)
        XCTAssertEqual(try accountStatus(3, report: nonzero), .abandoning(id))
        XCTAssertEqual(try accountStatus(4, report: nonzero), .abandoned(id))
        for state: UInt8 in [0, 1, 2, 5, 6, 255] {
            XCTAssertThrowsError(try accountStatus(state, report: nonzero))
        }
        for state: UInt8 in [3, 4, 6, 255] {
            XCTAssertThrowsError(try accountStatus(state, report: zero))
        }
        XCTAssertThrowsError(try accountStatus(0, report: [0]))
    }

    func testAccountDeliveryRejectsMisboundOutputAndDistinguishesRetainedOutcomes() throws {
        XCTAssertEqual(MemoryLayout<qpc_account_target_v1>.size, 40)
        XCTAssertEqual(MemoryLayout<qpc_account_delivered_v1>.size, 88)
        let session = try SessionID(bytes: [UInt8](repeating: 7, count: 32))
        var value = qpc_account_delivered_v1()
        withUnsafeMutableBytes(of: &value.device) { $0.copyBytes(from: [UInt8](repeating: 1, count: 16)) }
        withUnsafeMutableBytes(of: &value.session) { $0.copyBytes(from: session.bytes) }
        withUnsafeMutableBytes(of: &value.message) { $0.copyBytes(from: [UInt8](repeating: 2, count: 32)) }
        let outcomes: [AccountDeliveryOutcome] = [.consumption(.confirmed), .consumption(.prefixPending),
            .resolutionPending, .deliveryUnknown, .historyRetired, .reservationAbandoned]
        for (index, outcome) in outcomes.enumerated() {
            value.outcome = UInt32(index + 1)
            value.exchanges = index == 1 ? 1 : 0
            let delivery = try accountDelivery(&value, session: session)
            XCTAssertEqual(delivery.outcome, outcome)
            XCTAssertEqual(delivery.session, session)
            XCTAssertEqual(delivery.message.bytes, [UInt8](repeating: 2, count: 32))
        }
        value.outcome = 2; value.exchanges = 0
        XCTAssertThrowsError(try accountDelivery(&value, session: session))
        value.outcome = 1; value.exchanges = 9
        XCTAssertThrowsError(try accountDelivery(&value, session: session))
        value.exchanges = 1
        XCTAssertThrowsError(try accountDelivery(&value, session: SessionID(bytes: [UInt8](repeating: 8, count: 32))))
        value.outcome = 7
        XCTAssertThrowsError(try accountDelivery(&value, session: session))
        value.outcome = 1
        withUnsafeMutableBytes(of: &value.message) { $0.copyBytes(from: [UInt8](repeating: 0, count: 32)) }
        XCTAssertThrowsError(try accountDelivery(&value, session: session))
    }
}
