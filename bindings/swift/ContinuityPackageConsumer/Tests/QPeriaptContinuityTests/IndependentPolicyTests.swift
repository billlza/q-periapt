// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import XCTest
@testable import QPeriaptContinuity

final class IndependentPolicyTests: XCTestCase {
    private func proposal() -> [UInt8] {
        var bytes = [UInt8](repeating: 1, count: 296)
        bytes.replaceSubrange(0..<8, with: "QPPWNP01".utf8)
        func counter(_ offset: Int, _ value: UInt64) {
            var value = value.bigEndian
            withUnsafeBytes(of: &value) { bytes.replaceSubrange(offset..<(offset + 8), with: $0) }
        }
        counter(200, UInt64.max - 1); counter(248, UInt64.max - 1)
        counter(208, UInt64.max - 2); counter(256, UInt64.max - 1)
        bytes[295] = 2
        return bytes
    }
    func testIndependentDescriptorPreservesAllBytesAndRejectsOtherDomains() throws {
        var bytes = proposal(); let original = bytes
        let parsed = try IndependentPolicyProposal(retainedBytes: bytes)
        bytes[295] = 3
        XCTAssertEqual(parsed.bytes, original)
        XCTAssertEqual(parsed.operation.bytes, [UInt8](repeating: 1, count: 32))
        XCTAssertEqual(parsed.statement.bytes, [UInt8](repeating: 1, count: 32))
        var raw = parsed.native(); XCTAssertEqual(try independentPolicyProposal(&raw), parsed)
        var invalid = [Array(original.dropLast()), original + [0]]
        for tag in ["QPCRNP01", "QPCRNP02", "QPPWNP02"] {
            var changed = original; changed.replaceSubrange(0..<8, with: tag.utf8); invalid.append(changed)
        }
        for offset in [8, 40, 72, 104, 136, 168, 216, 264] {
            var changed = original; changed.replaceSubrange(offset..<(offset + 32), with: [UInt8](repeating: 0, count: 32)); invalid.append(changed)
        }
        for offset in [200, 208, 248, 256] {
            var changed = original; changed.replaceSubrange(offset..<(offset + 8), with: [UInt8](repeating: 255, count: 8)); invalid.append(changed)
        }
        var identical = original; identical.replaceSubrange(264..<296, with: original[216..<248]); invalid.append(identical)
        for bytes in invalid { XCTAssertThrowsError(try IndependentPolicyProposal(retainedBytes: bytes)) }
    }
    func testPreparationDistinguishesCanonicalAbsenceAndRejectsDirtyFlags() throws {
        XCTAssertEqual(MemoryLayout<qpc_independent_policy_preparation_v1>.size, 304)
        var raw = qpc_independent_policy_preparation_v1()
        XCTAssertNil(try independentPolicyPreparation(&raw))
        raw.proposal = try IndependentPolicyProposal(retainedBytes: proposal()).native()
        XCTAssertThrowsError(try independentPolicyPreparation(&raw))
        raw.present = 1; XCTAssertEqual(try independentPolicyPreparation(&raw)?.bytes, proposal())
        raw.reserved = 1; XCTAssertThrowsError(try independentPolicyPreparation(&raw))
        raw.reserved = 0
        for flag in [UInt32(2), 257, UInt32.max] { raw.present = flag; XCTAssertThrowsError(try independentPolicyPreparation(&raw)) }
    }
    func testProgressKeepsEveryTerminalAndRetirementStateDistinct() throws {
        XCTAssertEqual(MemoryLayout<qpc_independent_policy_progress_v1>.size, 344)
        XCTAssertEqual(MemoryLayout<qpc_independent_policy_progress_v1>.offset(of: \.target), 304)
        var raw = qpc_independent_policy_progress_v1()
        XCTAssertEqual(try independentPolicyProgress(&raw), .absent)
        let parsed = try IndependentPolicyProposal(retainedBytes: proposal())
        let target = try PolicyCheckpoint(version: UInt64.max - 1, digest: [UInt8](repeating: 9, count: 32))
        raw.proposal = parsed.native(); raw.target = target.native()
        XCTAssertThrowsError(try independentPolicyProgress(&raw))
        raw.phase = 1; XCTAssertEqual(try independentPolicyProgress(&raw), .reserved(proposal: parsed, target: target))
        raw.retired = 1; XCTAssertThrowsError(try independentPolicyProgress(&raw))
        for retired: UInt32 in [0, 1] {
            raw.retired = retired; raw.phase = 2
            XCTAssertEqual(try independentPolicyProgress(&raw), .applied(proposal: parsed, target: target, retired: retired == 1))
            raw.phase = 3
            XCTAssertEqual(try independentPolicyProgress(&raw), .closed(proposal: parsed, target: target, retired: retired == 1))
        }
        for phase in [UInt32(4), 256, UInt32.max] { raw.phase = phase; XCTAssertThrowsError(try independentPolicyProgress(&raw)) }
        raw.phase = 2; raw.retired = 2; XCTAssertThrowsError(try independentPolicyProgress(&raw))
        raw.retired = 0; raw.target.version = 0; XCTAssertThrowsError(try independentPolicyProgress(&raw))
        for code in [UInt32(0), 6, 257, UInt32.max] { XCTAssertNil(IndependentPolicyState(rawValue: code)) }
        XCTAssertEqual((1...5).compactMap { IndependentPolicyState(rawValue: UInt32($0)) }, [.prepared, .applied, .closed, .acknowledged, .unavailable])
    }
    func testWitnessCallsRespectPreparedCancelledAndClosedOwnerBoundaries() throws {
        let point = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        let octets = Array(point.utf8)
        let pointBytes = try stride(from: 0, to: octets.count, by: 2).map {
            try XCTUnwrap(UInt8(String(decoding: octets[$0..<($0 + 2)], as: UTF8.self), radix: 16))
        }
        let root = [UInt8](repeating: 1, count: 1952) + pointBytes
        let intent = try EnrollmentIntent(root: root, device: [UInt8](repeating: 2, count: 16),
            generation: 1, family: [UInt8](repeating: 3, count: 32), validFrom: 0, validUntil: UInt64.max - 1)
        let owner = try ContinuityEnrollment.prepareResume(path: "/unused", intent: intent)
        defer { XCTAssertNoThrow(try owner.close()) }
        let parsed = try IndependentPolicyProposal(retainedBytes: proposal())
        let calls: [() throws -> Void] = [
            { _ = try owner.policyRenewalRequest(operation: parsed.operation) },
            { _ = try owner.witnessedPolicyRenewalRequest(operation: parsed.operation) },
            { _ = try owner.recoverWitnessedPolicyRenewalPreparation() },
            { _ = try owner.witnessedPolicyRenewalProgress() },
            { _ = try owner.commitWitnessedPolicyRenewal(parsed) },
            { _ = try owner.reconcileWitnessedPolicyRenewal(parsed) },
            { _ = try owner.closeWitnessedPolicyRenewal(parsed) }
        ]
        for call in calls { XCTAssertThrowsError(try call()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) } }
        try owner.cancel()
        // Native take_owner checks the owner kind before cancellation. Only
        // finishOpen admits the prepared construction and consumes its request.
        for call in calls { XCTAssertThrowsError(try call()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 6) } }
        XCTAssertThrowsError(try owner.finishOpen()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 302) }
        for call in calls { XCTAssertThrowsError(try call()) { XCTAssertEqual(($0 as? ContinuityFailure)?.code, 2) } }
    }
}
