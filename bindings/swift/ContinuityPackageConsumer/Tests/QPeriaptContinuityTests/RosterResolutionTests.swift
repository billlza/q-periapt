// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import XCTest
@testable import QPeriaptContinuity

final class RosterResolutionTests: XCTestCase {
    private func checkpoint(_ version: UInt64, _ byte: UInt8) -> qpc_roster_checkpoint_v1 {
        var value = qpc_roster_checkpoint_v1()
        value.version = version
        withUnsafeMutableBytes(of: &value.digest) { $0.copyBytes(from: [UInt8](repeating: byte, count: 32)) }
        return value
    }
    private func raw(_ outcome: UInt32 = 4) -> qpc_roster_refresh_resolution_v1 {
        var value = qpc_roster_refresh_resolution_v1()
        value.outcome = outcome
        withUnsafeMutableBytes(of: &value.journal) { $0.copyBytes(from: [UInt8](repeating: 9, count: 32)) }
        value.previous = checkpoint(1, 1); value.target = checkpoint(2, 2)
        value.observed = checkpoint(3, 3); value.observed_at = 185
        return value
    }
    func testABIHasExplicitReservedFieldAndExactOffsets() {
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_resolution_v1>.size, 168)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_resolution_v1>.alignment, 8)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_resolution_v1>.offset(of: \.journal), 8)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_resolution_v1>.offset(of: \.previous), 40)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_resolution_v1>.offset(of: \.target), 80)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_resolution_v1>.offset(of: \.observed), 120)
        XCTAssertEqual(MemoryLayout<qpc_roster_refresh_resolution_v1>.offset(of: \.observed_at), 160)
    }
    func testAllFourOutcomesAndUnsignedUnknownRemainDistinct() throws {
        for (code, version, digest, expected): (UInt32, UInt64, UInt8, RosterRefreshOutcome) in [
            (1, 2, 2, .committed), (2, 1, 1, .expiredUncommitted),
            (3, 2, 3, .supersededUncommitted), (4, 3, 3, .supersededUnknown)
        ] {
            var value = raw(code); value.observed = checkpoint(version, digest)
            XCTAssertEqual(try decodeRosterRefreshResolution(&value).outcome, expected)
        }
        var value = raw()
        value.previous = checkpoint(UInt64.max - 3, 1)
        value.target = checkpoint(UInt64.max - 2, 2)
        value.observed = checkpoint(UInt64.max - 1, 3)
        XCTAssertEqual(try decodeRosterRefreshResolution(&value).observed.version, UInt64.max - 1)
    }
    func testMalformedOrContradictoryResultsNeverBecomeNoCommit() {
        var variants = [qpc_roster_refresh_resolution_v1]()
        for outcome in [UInt32(0), 1, 2, 3, 5] { variants.append(raw(outcome)) }
        var reserved = raw(); reserved.reserved = 1; variants.append(reserved)
        var time = raw(); time.observed_at = 0; variants.append(time)
        var order = raw(); order.previous = checkpoint(3, 1); variants.append(order)
        var fork = raw(2); fork.observed = checkpoint(1, 9); variants.append(fork)
        var zero = raw(); zero.observed = checkpoint(0, 3); variants.append(zero)
        var digest = raw(); digest.target = checkpoint(2, 0); variants.append(digest)
        for var value in variants {
            XCTAssertThrowsError(try decodeRosterRefreshResolution(&value))
        }
    }
    func testResolvedEnrollmentPreservesOriginalPairAndRejectsUnknownPhase() throws {
        var value = qpc_enrollment_status_v1()
        value.phase = 7
        withUnsafeMutableBytes(of: &value.signing_id) { $0.copyBytes(from: [UInt8](repeating: 1, count: 32)) }
        withUnsafeMutableBytes(of: &value.journal) { $0.copyBytes(from: [UInt8](repeating: 2, count: 32)) }
        value.previous = checkpoint(1, 1); value.next = checkpoint(2, 2)
        let decoded = try enrollmentStatus(&value)
        XCTAssertEqual(decoded.phase, .rosterResolved)
        XCTAssertEqual(decoded.previous?.version, 1); XCTAssertEqual(decoded.next?.version, 2)
        value.phase = 8; XCTAssertThrowsError(try enrollmentStatus(&value))
    }
}
