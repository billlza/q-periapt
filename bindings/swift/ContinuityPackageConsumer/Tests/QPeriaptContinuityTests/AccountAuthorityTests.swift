// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
import Foundation
import Darwin
@testable import QPeriaptContinuity
import CQPCOwner

final class AccountAuthorityTests: XCTestCase {
    // Canonical public bytes only; these tests fabricate no witness signature or account grant.
    private func trust() throws -> AccountAuthorityTrust {
        let key = [UInt8](repeating: 0, count: 1952) + [UInt8](arrayLiteral:
            0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
            0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
            0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96)
        return try AccountAuthorityTrust(identity: AccountAuthorityID(bytes: [UInt8](repeating: 1, count: 32)),
            family: [UInt8](repeating: 2, count: 32), witness: [UInt8](repeating: 3, count: 32), publicKey: key)
    }
    func testAuthorityLayoutsAndCheckpointRejectMalformedOutput() throws {
        XCTAssertEqual(MemoryLayout<qpc_authority_options_v1>.size, 120)
        XCTAssertEqual(MemoryLayout<qpc_authority_options_v1>.offset(of: \.public_key), 104)
        XCTAssertEqual(MemoryLayout<qpc_authority_checkpoint_v1>.size, 72)
        XCTAssertEqual(MemoryLayout<qpc_authority_checkpoint_v1>.offset(of: \.revision), 32)
        XCTAssertEqual(MemoryLayout<qpc_authority_association_v1>.size, 80)
        XCTAssertEqual(MemoryLayout<qpc_authority_enrollment_selection_v1>.size, 88)
        XCTAssertEqual(MemoryLayout<qpc_authority_enrollment_selection_v1>.offset(of: \.checkpoint), 16)
        let checkpoint = try AccountAuthorityCheckpoint(
            application: ApplicationAccountID(bytes: [UInt8](repeating: 4, count: 32)),
            revision: UInt64.max - 1, account: AccountID(bytes: [UInt8](repeating: 5, count: 32)))
        var raw = checkpoint.native()
        XCTAssertEqual(try accountAuthorityCheckpoint(&raw), checkpoint)
        for revision: UInt64 in [0, UInt64.max] {
            raw.revision = revision
            XCTAssertThrowsError(try accountAuthorityCheckpoint(&raw)) {
                XCTAssertEqual($0 as? ContinuityBoundaryError, .malformedOutput)
            }
        }
        raw = checkpoint.native()
        withUnsafeMutableBytes(of: &raw.account) { $0.copyBytes(from: [UInt8](repeating: 0, count: 32)) }
        XCTAssertThrowsError(try accountAuthorityCheckpoint(&raw))
    }
    func testAuthorityInputsOwnBytesAndRejectEmptyScope() throws {
        let original = try trust()
        var family = original.family, publicKey = original.publicKey
        let selected = try AccountAuthorityTrust(identity: original.identity, family: family,
            witness: original.witness, publicKey: publicKey)
        family[0] = 99; publicKey[0] = 99
        selected.withNative { pointer in
            var raw = pointer.pointee
            XCTAssertEqual(withUnsafeBytes(of: &raw.family) { Array($0) }, original.family)
            XCTAssertEqual(raw.public_key?.pointee, 0)
            XCTAssertEqual(raw.public_key_length, 1985)
        }
        XCTAssertThrowsError(try AccountAuthorityTrust(identity: original.identity, family: [UInt8](repeating: 0, count: 32),
            witness: original.witness, publicKey: original.publicKey))
        XCTAssertThrowsError(try AccountAuthorityTrust(identity: original.identity, family: original.family,
            witness: original.witness, publicKey: Array(original.publicKey.dropLast())))
    }
    func testPendingAuthorityUsesSharedCapacityAndPreservesCancellation() throws {
        let input = try trust()
        for _ in 0..<128 { _ = try ContinuityAccountAuthority.prepareOpen(path: "/unused", trust: input) }
        let owners = try (0..<64).map { _ in try ContinuityAccountAuthority.prepareOpen(path: "/unused", trust: input) }
        XCTAssertThrowsError(try ContinuityDevice.prepare(path: "/unused")) {
            XCTAssertEqual(($0 as? ContinuityFailure)?.code, 4)
        }
        for owner in owners {
            try owner.cancel()
            XCTAssertThrowsError(try owner.finishOpen()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 302) }
            try owner.close()
            XCTAssertThrowsError(try owner.close()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2) }
        }
        let replacement = try ContinuityDevice.prepare(path: "/unused")
        try replacement.close()
    }
    func testAuthorityPersistsAndFinalARCReleaseFreesItsOriginalLease() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("continuity-authority-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer {
            do { try FileManager.default.removeItem(at: url) }
            catch { XCTFail("authority fixture cleanup failed: \(error)") }
        }
        guard let canonical = realpath(url.path, nil) else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { free(canonical) }
        let path = String(cString: canonical), input = try trust()
        try ContinuityAccountAuthority.provisionWrappingKey(path: path)
        var owner: ContinuityAccountAuthority? = try .prepareCreate(path: path, trust: input)
        let stillAlive = { [weak owner] in owner != nil }
        try XCTUnwrap(owner).finishOpen()
        owner = nil
        XCTAssertFalse(stillAlive())
        let reopened = try ContinuityAccountAuthority.prepareOpen(path: path, trust: input)
        try reopened.finishOpen()
        try reopened.close()
    }
}
