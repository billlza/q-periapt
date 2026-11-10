// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
@testable import QPeriaptContinuity
import CQPCOwner

final class EnrollmentTests: XCTestCase {
    // A canonical public pair used only as independent input. No root signature
    // or credential grant is fabricated. The native owner generates and signs
    // its actual enrollment request using a fresh protected device key.
    private func publicRoot() -> [UInt8] {
        [UInt8](repeating: 0, count: 1952) + [
            0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
            0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
            0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
            0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        ]
    }
    private func intent() throws -> EnrollmentIntent {
        let now = UInt64(Date().timeIntervalSince1970)
        return try EnrollmentIntent(root: publicRoot(), device: [UInt8](repeating: 7, count: 16),
            generation: UInt64.max - 1, family: [UInt8](repeating: 8, count: 32),
            validFrom: now - 1, validUntil: now + 3600)
    }
    private func refuses(_ code: Int32, _ body: () throws -> Void,
                         file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, code, file: file, line: line)
        }
    }
    private func directory(_ body: (String) throws -> Void) throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("continuity-enrollment-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer {
            do { try FileManager.default.removeItem(at: url) }
            catch { XCTFail("enrollment test cleanup failed: \(error)") }
        }
        // Foundation preserves /var on macOS even after resolvingSymlinksInPath.
        // The native directory capability refuses symlink traversal, so retain
        // the actual POSIX canonical path of this newly created test directory.
        guard let canonical = realpath(url.path, nil) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { free(canonical) }
        try body(String(cString: canonical))
    }

    func testNativeEnrollmentLayoutsMatchHeader() {
        XCTAssertEqual(MemoryLayout<qpc_enrollment_intent_v1>.size, 88)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_intent_v1>.alignment, 8)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_intent_v1>.offset(of: \.generation), 32)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_intent_v1>.offset(of: \.family), 40)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_intent_v1>.offset(of: \.valid_from), 72)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_intent_v1>.offset(of: \.valid_until), 80)
        XCTAssertEqual(MemoryLayout<qpc_roster_checkpoint_v1>.size, 40)
        XCTAssertEqual(MemoryLayout<qpc_roster_checkpoint_v1>.alignment, 8)
        XCTAssertEqual(MemoryLayout<qpc_account_pin_v1>.size, 120)
        XCTAssertEqual(MemoryLayout<qpc_account_pin_v1>.alignment, 8)
        XCTAssertEqual(MemoryLayout<qpc_account_pin_v1>.offset(of: \.root), 32)
        XCTAssertEqual(MemoryLayout<qpc_account_pin_v1>.offset(of: \.checkpoint), 80)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_status_v1>.size, 152)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_status_v1>.alignment, 8)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_status_v1>.offset(of: \.signing_id), 4)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_status_v1>.offset(of: \.journal), 36)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_status_v1>.offset(of: \.previous), 72)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_status_v1>.offset(of: \.next), 112)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_request_v1>.size, 8196)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_request_v1>.alignment, 4)
        XCTAssertEqual(MemoryLayout<qpc_enrollment_request_v1>.offset(of: \.length), 0)
    }

    func testSixPhasesRejectImpossibleIdentityAndCheckpointCombinations() throws {
        let signing = [UInt8](repeating: 1, count: 32), journal = [UInt8](repeating: 2, count: 32)
        let previous = try RosterCheckpoint(version: UInt64.max - 2, digest: [UInt8](repeating: 3, count: 32))
        let next = try RosterCheckpoint(version: UInt64.max - 1, digest: [UInt8](repeating: 4, count: 32))
        for phase: UInt32 in 1...6 {
            var raw = qpc_enrollment_status_v1()
            raw.phase = phase
            withUnsafeMutableBytes(of: &raw.signing_id) { $0.copyBytes(from: signing) }
            if phase >= 3 { withUnsafeMutableBytes(of: &raw.journal) { $0.copyBytes(from: journal) } }
            if phase == 6 { raw.previous = previous.native(); raw.next = next.native() }
            let status = try enrollmentStatus(&raw)
            XCTAssertEqual(status.phase.rawValue, phase)
            XCTAssertEqual(status.signingID.bytes, signing)
            XCTAssertEqual(status.journal?.bytes, phase >= 3 ? journal : nil)
            XCTAssertEqual(status.previous, phase == 6 ? previous : nil)
            XCTAssertEqual(status.next, phase == 6 ? next : nil)
            var wrong = raw
            withUnsafeMutableBytes(of: &wrong.signing_id) { _ = $0.initializeMemory(as: UInt8.self, repeating: 0) }
            XCTAssertThrowsError(try enrollmentStatus(&wrong))
            wrong = raw
            withUnsafeMutableBytes(of: &wrong.journal) { _ = $0.initializeMemory(as: UInt8.self, repeating: phase >= 3 ? 0 : 1) }
            XCTAssertThrowsError(try enrollmentStatus(&wrong))
            wrong = raw
            wrong.previous.version = phase == 6 ? 0 : 1
            XCTAssertThrowsError(try enrollmentStatus(&wrong))
            wrong = raw
            withUnsafeMutableBytes(of: &wrong.next.digest) { _ = $0.initializeMemory(as: UInt8.self, repeating: phase == 6 ? 0 : 1) }
            XCTAssertThrowsError(try enrollmentStatus(&wrong))
            if phase == 6 {
                wrong = raw; wrong.next.version = previous.version
                XCTAssertThrowsError(try enrollmentStatus(&wrong))
                wrong = raw; wrong.next.version = UInt64.max
                XCTAssertThrowsError(try enrollmentStatus(&wrong))
            }
        }
        for phase: UInt32 in [0, 7, 256, UInt32.max] {
            var raw = qpc_enrollment_status_v1(); raw.phase = phase
            withUnsafeMutableBytes(of: &raw.signing_id) { $0.copyBytes(from: signing) }
            XCTAssertThrowsError(try enrollmentStatus(&raw))
        }
    }

    func testRequestRejectsTruncationAndUnexpectedTail() throws {
        var raw = qpc_enrollment_request_v1()
        XCTAssertThrowsError(try enrollmentRequest(&raw))
        raw.length = 8193
        XCTAssertThrowsError(try enrollmentRequest(&raw))
        raw.length = UInt32.max
        XCTAssertThrowsError(try enrollmentRequest(&raw))
        raw.length = 3
        withUnsafeMutableBytes(of: &raw) { $0[4] = 1; $0[5] = 2; $0[6] = 3 }
        XCTAssertEqual(try enrollmentRequest(&raw), [1, 2, 3])
        withUnsafeMutableBytes(of: &raw) { $0[8195] = 1 }
        XCTAssertThrowsError(try enrollmentRequest(&raw))
    }

    func testApprovedValuesOwnBytesAndPreserveUnsignedCounters() throws {
        var root = publicRoot(), device = [UInt8](repeating: 7, count: 16), family = [UInt8](repeating: 8, count: 32)
        let approved = try EnrollmentIntent(root: root, device: device, generation: UInt64.max - 1,
            family: family, validFrom: UInt64.max - 3, validUntil: UInt64.max - 1)
        root[0] = 99; device[0] = 99; family[0] = 99
        XCTAssertEqual(approved.root, publicRoot())
        XCTAssertEqual(approved.device, [UInt8](repeating: 7, count: 16))
        XCTAssertEqual(approved.family, [UInt8](repeating: 8, count: 32))
        approved.withNative { raw in
            XCTAssertEqual(raw.pointee.generation, UInt64.max - 1)
            XCTAssertEqual(raw.pointee.valid_until, UInt64.max - 1)
        }
        for generation: UInt64 in [0, UInt64.max] {
            XCTAssertThrowsError(try EnrollmentIntent(root: root, device: device, generation: generation,
                family: family, validFrom: 1, validUntil: 2))
        }
        XCTAssertThrowsError(try EnrollmentIntent(root: Array(root.dropLast()), device: device,
            generation: 1, family: family, validFrom: 1, validUntil: 2))
        XCTAssertThrowsError(try EnrollmentIntent(root: root, device: device, generation: 1,
            family: family, validFrom: 2, validUntil: 2))
        XCTAssertThrowsError(try RosterCheckpoint(version: 0, digest: family))
        XCTAssertThrowsError(try RosterCheckpoint(version: 1, digest: [UInt8](repeating: 0, count: 32)))
    }

    func testPreparationCopiesIntentAndNativeRequestSurvivesFailedActivation() throws {
        try directory { path in
            try ContinuityEnrollment.provisionWrappingKey(path: path)
            var approved = try intent()
            let original = approved
            let owner = try ContinuityEnrollment.prepareCreate(path: path, intent: approved)
            approved = try EnrollmentIntent(root: publicRoot(), device: [UInt8](repeating: 9, count: 16),
                generation: 1, family: original.family, validFrom: original.validFrom, validUntil: original.validUntil)
            // The prepared C owner must retain original input after the caller replaces it.
            try owner.finishOpen()
            let initial = try owner.status()
            XCTAssertEqual(initial.phase, .preparing)
            let request = try owner.request()
            XCTAssertEqual(request.count, 5506)
            XCTAssertEqual(Array(request[12..<44]), initial.signingID.bytes)
            XCTAssertEqual(Array(request[76..<92]), original.device)
            XCTAssertEqual(Array(request[92..<100]), [255, 255, 255, 255, 255, 255, 255, 254])
            XCTAssertEqual(Array(request[116..<148]), original.family)
            XCTAssertEqual(try owner.request(), request)
            let requested = try owner.status()
            XCTAssertEqual(requested.phase, .requested)
            XCTAssertNil(requested.journal)
            XCTAssertFalse(FileManager.default.fileExists(atPath: path + "/sdk.redb"))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path + "/tls-key"))
            let pin = try AccountPin(account: AccountID(bytes: Array(request[44..<76])), root: original.root,
                family: original.family, checkpoint: RosterCheckpoint(version: 1, digest: original.family))
            XCTAssertThrowsError(try owner.accept(certificate: [], roster: [1], pin: pin))
            XCTAssertThrowsError(try owner.refreshRoster(previous: pin.checkpoint, roster: [], pin: pin))
            let operation = try CredentialRenewalID(bytes: original.family)
            XCTAssertEqual(try owner.credentialRenewalStatus(), .absent)
            XCTAssertThrowsError(try owner.stageCredentialRenewal(grant: [], pin: pin, operation: operation))
            XCTAssertThrowsError(try owner.stageCredentialRenewal(grant: [UInt8](repeating: 1, count: 65537), pin: pin, operation: operation))
            XCTAssertEqual(try owner.status(), requested, "shape refusal consumed original registration")
            // This actual failure happens after transfer begins: configured_policy
            // reads the absent sdk-policy file before opening sdk.redb, so the C
            // configuration boundary returns 500. The temporary successor must not close the unique
            // NativeOwner held by the registration wrapper before explicit disposal.
            refuses(500) { _ = try owner.activate() }
            refuses(2) { _ = try owner.status() }
            try owner.close()
            let resumed = try ContinuityEnrollment.resume(path: path, intent: original)
            XCTAssertEqual(try resumed.status(), requested)
            XCTAssertEqual(try resumed.request(), request)
            try resumed.close()
            XCTAssertThrowsError(try ContinuityEnrollment.resume(path: path, intent: approved)) {
                XCTAssertNotNil($0 as? ContinuityFailure)
            }
            let again = try ContinuityEnrollment.resume(path: path, intent: original)
            XCTAssertEqual(try again.status(), requested)
            try again.close()
        }
    }

    func testPendingRegistrationSharesQuotaAndPreservesCloseAfterRefusal() throws {
        let approved = try intent()
        for _ in 0..<128 { _ = try ContinuityEnrollment.prepareCreate(path: "/unused", intent: approved) }
        let owners = try (0..<64).map { index in
            if index % 2 == 0 { return try ContinuityEnrollment.prepareCreate(path: "/unused", intent: approved) }
            return try ContinuityEnrollment.prepareResume(path: "/unused", intent: approved)
        }
        refuses(4) { _ = try ContinuityDevice.prepare(path: "/unused") }
        for owner in owners {
            refuses(6) { _ = try owner.status() }
            refuses(6) { _ = try owner.activate() }
            try owner.cancel()
            refuses(302) { try owner.finishOpen() }
            refuses(2) { _ = try owner.request() }
            try owner.close()
            refuses(2) { try owner.close() }
        }
        let replacement = try ContinuitySetup.prepareCreate(path: "/unused")
        try replacement.close()
    }
}
