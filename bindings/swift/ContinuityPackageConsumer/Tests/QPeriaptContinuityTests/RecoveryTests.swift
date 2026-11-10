// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class RecoveryTests: XCTestCase {
    func testRecoverySharesRegistryAndRetainsCancelledClosedAuthority() throws {
        for _ in 0..<128 { _ = try ContinuityRecoveryOwner.prepare(path: "/unused") }
        var operational: [ContinuityOwner] = []
        var recovery: [ContinuityRecoveryOwner] = []
        for _ in 0..<32 {
            operational.append(try ContinuityOwner.prepare(path: "/unused", quality: .oneTimeBoth))
            recovery.append(try ContinuityRecoveryOwner.prepare(path: "/unused"))
        }
        XCTAssertThrowsError(try ContinuityRecoveryOwner.prepare(path: "/unused")) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 4)
        }
        let alias = try XCTUnwrap(recovery.first)
        XCTAssertThrowsError(try alias.sessionCount()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) }
        try alias.cancel()
        XCTAssertThrowsError(try alias.finishOpen()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 302) }
        XCTAssertThrowsError(try alias.begin()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2) }
        for owner in operational { try owner.close() }
        for owner in recovery { try owner.close() }
        XCTAssertThrowsError(try alias.status()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2) }
        let replacement = try ContinuityRecoveryOwner.prepare(path: "/unused")
        XCTAssertThrowsError(try alias.close()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2) }
        try replacement.close()
    }

    func testClosureDecodingPreservesCountersAndRejectsUnknownStates() throws {
        var header = qpc_closure_header_v1()
        header.role = 2; header.peer_generation = 9
        header.pending_epoch = .max; header.has_pending_epoch = 1
        header.reserved_count = 7; header.epoch_count = 11
        withUnsafeMutableBytes(of: &header.report) { $0[31] = 42 }
        let decoded = try closureHeader(header)
        XCTAssertEqual(decoded.pendingEpoch, .max)
        XCTAssertEqual(decoded.reservedCount, 7); XCTAssertEqual(decoded.epochCount, 11)
        XCTAssertEqual(decoded.report.bytes[31], 42)
        header.has_pending_epoch = 0
        XCTAssertThrowsError(try closureHeader(header))
        header.pending_epoch = 0; header.role = 99
        XCTAssertThrowsError(try closureHeader(header))
        var epoch = qpc_closure_epoch_v1()
        epoch.has_peer_sent = 1; epoch.peer_sent = .max; epoch.resolution = 1
        epoch.unconfirmed_count = 3; epoch.delivery_count = 5; epoch.skipped_count = 8
        withUnsafeMutableBytes(of: &epoch.resolution_report) { $0[0] = 37 }
        let value = try closureEpoch(epoch)
        XCTAssertEqual(value.peerSent, .max)
        XCTAssertEqual(value.unconfirmedCount, 3); XCTAssertEqual(value.deliveryCount, 5); XCTAssertEqual(value.skippedCount, 8)
        guard case let .pending(id) = value.resolution else { return XCTFail("lost resolution") }
        XCTAssertEqual(id.bytes[0], 37)
        epoch.resolution = 0
        XCTAssertThrowsError(try closureEpoch(epoch))
        epoch.resolution = 3
        XCTAssertThrowsError(try closureEpoch(epoch))
        epoch.resolution = 2; epoch.reserved_zero = 1
        XCTAssertThrowsError(try closureEpoch(epoch))
        epoch.reserved_zero = 0; epoch.has_peer_sent = 2
        XCTAssertThrowsError(try closureEpoch(epoch))
    }

    func testClosureStatusKeepsReportIdentityAndRejectsMalformedOpen() throws {
        var status = qpc_closure_status_v1()
        XCTAssertEqual(try closureStatus(status), .open)
        withUnsafeMutableBytes(of: &status.report) { $0[2] = 13 }
        XCTAssertThrowsError(try closureStatus(status))
        status.phase = 1
        let id = try ClosureReportID(bytes: withUnsafeBytes(of: status.report) { Array($0) })
        XCTAssertEqual(try closureStatus(status), .pending(id))
        status.phase = 2
        XCTAssertEqual(try closureStatus(status), .closed(id))
        status.phase = 3
        XCTAssertThrowsError(try closureStatus(status))
    }
}
