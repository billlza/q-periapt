// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class AccountRecoveryTests: XCTestCase {
    func testCompleteAccountMetadataPreservesFullWidthAndRejectsMalformedPresence() throws {
        var header = qpc_account_cleanup_header_v1()
        withUnsafeMutableBytes(of: &header.batch) { $0[31] = 17 }
        withUnsafeMutableBytes(of: &header.report) { $0[0] = 23 }
        header.member_count = 32
        let h = try accountCleanupHeader(header)
        XCTAssertEqual(h.operation.bytes[31], 17); XCTAssertEqual(h.report.bytes[0], 23)
        XCTAssertEqual(h.memberCount, 32)
        for count in [UInt32(0), 33, .max] {
            header.member_count = count
            XCTAssertThrowsError(try accountCleanupHeader(header))
        }
        header.member_count = 2; header.reserved_zero = 1
        XCTAssertThrowsError(try accountCleanupHeader(header))
        header.reserved_zero = 0; header.batch = qpc_account_cleanup_header_v1().batch
        XCTAssertThrowsError(try accountCleanupHeader(header))

        var member = qpc_account_cleanup_member_v1()
        withUnsafeMutableBytes(of: &member.device) { $0[15] = 7 }
        withUnsafeMutableBytes(of: &member.session) { $0[31] = 11 }
        withUnsafeMutableBytes(of: &member.context) { $0[3] = 19 }
        member.role = 1; member.generation = .max; member.epoch_count = 4
        member.confirmed_epoch = .max - 3; member.sending_epoch = .max - 2
        member.receiving_epoch = .max - 1; member.pending_epoch = .max; member.has_pending_epoch = 1
        let m = try accountCleanupMember(member)
        XCTAssertEqual(m.device[15], 7); XCTAssertEqual(m.session.bytes[31], 11); XCTAssertEqual(m.context[3], 19)
        XCTAssertEqual(m.role, .initiator); XCTAssertEqual(m.generation, .max)
        XCTAssertEqual(m.confirmedEpoch, .max - 3); XCTAssertEqual(m.sendingEpoch, .max - 2)
        XCTAssertEqual(m.receivingEpoch, .max - 1); XCTAssertEqual(m.pendingEpoch, .max)
        XCTAssertEqual(m.epochCount, 4)
        member.has_pending_epoch = 0
        XCTAssertThrowsError(try accountCleanupMember(member))
        member.pending_epoch = 0
        XCTAssertNil(try accountCleanupMember(member).pendingEpoch)
        member.has_pending_epoch = 2
        XCTAssertThrowsError(try accountCleanupMember(member))
        member.has_pending_epoch = 0; member.role = 99
        XCTAssertThrowsError(try accountCleanupMember(member))
        member.role = 1; member.generation = 0
        XCTAssertThrowsError(try accountCleanupMember(member))
        member.generation = 1; member.epoch_count = 5
        XCTAssertThrowsError(try accountCleanupMember(member))
        member.epoch_count = 1; member.reserved_zero = 1
        XCTAssertThrowsError(try accountCleanupMember(member))
    }

    func testAccountCleanupStatusRejectsNarrowingAndKeepsExactReport() throws {
        var status = qpc_account_cleanup_status_v1()
        for (phase, state) in [(UInt32(0), AccountStatus.absent), (1, .reserved), (2, .committed), (5, .retired)] {
            status.phase = phase
            XCTAssertEqual(try decodeAccountCleanupStatus(status), state)
        }
        for phase in [UInt32(3), 4, 6, 256, .max] {
            status.phase = phase
            XCTAssertThrowsError(try decodeAccountCleanupStatus(status))
        }
        withUnsafeMutableBytes(of: &status.report) { $0[9] = 31 }
        let report = try AccountAbandonmentID(bytes: octets(status.report))
        status.phase = 3; XCTAssertEqual(try decodeAccountCleanupStatus(status), .abandoning(report))
        status.phase = 4; XCTAssertEqual(try decodeAccountCleanupStatus(status), .abandoned(report))
        for phase in [UInt32(0), 1, 2, 5, 259] {
            status.phase = phase
            XCTAssertThrowsError(try decodeAccountCleanupStatus(status))
        }
    }

    func testAccountCleanupCannotAcquireAuthorityFromPendingOrClosedOwner() throws {
        let owner = try ContinuityRecoveryOwner.prepare(path: "/unused")
        let operation = try AccountOperationID(bytes: [UInt8](repeating: 1, count: 32))
        let report = try AccountAbandonmentID(bytes: [UInt8](repeating: 2, count: 32))
        let actions: [() throws -> Void] = [
            { try owner.select(account: operation) }, { _ = try owner.beginAccountCleanup() },
            { _ = try owner.accountCleanupStatus() }, { _ = try owner.accountMember(at: 0) },
            { _ = try owner.accountReservation(member: 0) }, { _ = try owner.accountEpoch(member: 0, at: 0) },
            { _ = try owner.accountUnconfirmed(member: 0, epoch: 0, at: 0) },
            { _ = try owner.accountDelivery(member: 0, epoch: 0, at: 0) },
            { _ = try owner.accountSkippedPosition(member: 0, epoch: 0, at: 0) },
            { try owner.acknowledgeAccount(report: report) }, { try owner.retireAccount() },
        ]
        for action in actions {
            XCTAssertThrowsError(try action()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) }
        }
        try owner.cancel()
        XCTAssertThrowsError(try owner.finishOpen()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 302) }
        for action in actions {
            XCTAssertThrowsError(try action()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2) }
        }
        try owner.close()
    }
}
