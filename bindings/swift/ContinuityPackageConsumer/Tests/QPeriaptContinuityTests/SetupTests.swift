// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class SetupTests: XCTestCase {
    func testPendingSetupSharesCapacityAndCannotActivateAfterCancellation() throws {
        for _ in 0..<128 { _ = try ContinuitySetup.prepareCreate(path: "/unused") }
        let owners = try (0..<64).map { index in
            if index % 2 == 0 { return try ContinuitySetup.prepareCreate(path: "/unused") }
            return try ContinuitySetup.prepareResume(path: "/unused")
        }
        XCTAssertThrowsError(try ContinuityDevice.prepare(path: "/unused")) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 4)
        }
        for owner in owners {
            XCTAssertThrowsError(try owner.status()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) }
            XCTAssertThrowsError(try owner.prepareStorage()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) }
            XCTAssertThrowsError(try owner.activate()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) }
            try owner.cancel()
            XCTAssertThrowsError(try owner.finishOpen()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 302) }
            XCTAssertThrowsError(try owner.activate()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2) }
            try owner.close()
            XCTAssertThrowsError(try owner.status()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2) }
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2) }
        }
        let replacement = try ContinuityDevice.prepare(path: "/unused")
        try replacement.close()
    }
    func testInstallationStatusRejectsUnknownPhaseAndZeroJournal() throws {
        XCTAssertEqual(MemoryLayout<qpc_setup_status_v1>.size, 36)
        var value = qpc_setup_status_v1()
        value.phase = 1
        XCTAssertThrowsError(try installationStatus(&value))
        let bytes = [UInt8](repeating: 1, count: 32)
        let id = try JournalID(bytes: bytes)
        withUnsafeMutableBytes(of: &value.journal) { $0.copyBytes(from: bytes) }
        for phase in [InstallationPhase.creating, .active] {
            value.phase = phase.rawValue
            XCTAssertEqual(try installationStatus(&value), InstallationStatus(phase: phase, journal: id))
        }
        for phase: UInt32 in [0, 3, 256, UInt32.max] {
            value.phase = phase
            XCTAssertThrowsError(try installationStatus(&value))
        }
    }
    func testOriginalGenesisRejectsMisbindingAndUnexpectedWitnessMetadata() throws {
        XCTAssertEqual(MemoryLayout<qpc_setup_preparation_v1>.size, 164)
        var value = qpc_setup_preparation_v1()
        value.protection = 1
        XCTAssertThrowsError(try installationPreparation(&value))
        let journal = [UInt8](repeating: 7, count: 32)
        let id = try JournalID(bytes: journal)
        withUnsafeMutableBytes(of: &value.journal) { $0.copyBytes(from: journal) }
        XCTAssertEqual(try installationPreparation(&value), .local(id))
        let subject = journal + [UInt8](repeating: 8, count: 32) + [UInt8](repeating: 9, count: 32)
        let digest = [UInt8](repeating: 10, count: 32)
        withUnsafeMutableBytes(of: &value.subject) { $0.copyBytes(from: subject) }
        XCTAssertThrowsError(try installationPreparation(&value))
        withUnsafeMutableBytes(of: &value.image_digest) { $0.copyBytes(from: digest) }
        value.protection = 2
        let expected = WitnessGenesis(journal: id, subject: subject, imageDigest: digest)
        XCTAssertEqual(try installationPreparation(&value), .requiresEnrollment(expected))
        for offset in [0, 32, 64] {
            var malformed = subject
            malformed.replaceSubrange(offset..<offset+32, with: [UInt8](repeating: 0, count: 32))
            withUnsafeMutableBytes(of: &value.subject) { $0.copyBytes(from: malformed) }
            XCTAssertThrowsError(try installationPreparation(&value))
        }
        withUnsafeMutableBytes(of: &value.subject) { $0.copyBytes(from: subject) }
        withUnsafeMutableBytes(of: &value.image_digest) { $0.copyBytes(from: [UInt8](repeating: 0, count: 32)) }
        XCTAssertThrowsError(try installationPreparation(&value))
        withUnsafeMutableBytes(of: &value.image_digest) { $0.copyBytes(from: digest) }
        for protection: UInt32 in [0, 3, 258, UInt32.max] {
            value.protection = protection
            XCTAssertThrowsError(try installationPreparation(&value))
        }
    }
}
