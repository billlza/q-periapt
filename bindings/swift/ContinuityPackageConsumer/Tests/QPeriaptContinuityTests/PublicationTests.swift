// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
import CQPCOwner
@testable import QPeriaptContinuity

final class PublicationTests: XCTestCase {
    func plan() throws -> PublicationPlan {
        try PublicationPlan(directory: [UInt8](repeating: 99, count: 32), validFrom: 100, validUntil: 200,
            keys: [PublicationKey(kind: .signedClassical, validFrom: 100, validUntil: 200),
                   PublicationKey(kind: .lastResortPQ, validFrom: 100, validUntil: 200)])
    }
    func testPublicationLayoutsAndPlanOwnCompleteOriginalInputs() throws {
        XCTAssertEqual(MemoryLayout<qpc_publication_key_v1>.size, 56)
        XCTAssertEqual(MemoryLayout<qpc_publication_plan_v1>.size, 72)
        XCTAssertEqual(MemoryLayout<qpc_publication_plan_v1>.offset(of: \.keys), 56)
        XCTAssertEqual(MemoryLayout<qpc_publication_status_v1>.size, 104)
        let plan = try plan()
        try plan.withNative { native in
            XCTAssertEqual(native.pointee.struct_size, 72)
            XCTAssertEqual(native.pointee.reserved_zero, 0)
            XCTAssertEqual(native.pointee.count, 2)
            let keys = try XCTUnwrap(native.pointee.keys)
            XCTAssertEqual(keys.pointee.kind, 1)
            XCTAssertEqual(keys.advanced(by: 1).pointee.kind, 3)
            var bound = 0, error = qpc_error_v1()
            let code = qpc_device_v1_publication_size_bound(native, &bound, &error)
            try checked(code, &error)
            XCTAssertGreaterThan(bound, 3667)
            XCTAssertLessThan(bound, 10000)
        }
        XCTAssertThrowsError(try PublicationPlan(directory: [0], validFrom: 100, validUntil: 200, keys: plan.keys))
        XCTAssertThrowsError(try PublicationPlan(directory: [UInt8](repeating: 0, count: 32), validFrom: 100, validUntil: 200, keys: plan.keys))
        XCTAssertThrowsError(try PublicationKey(kind: .oneTimePQ, validFrom: 200, validUntil: 100))
        XCTAssertThrowsError(try PublicationPlan(directory: plan.directory, validFrom: 101, validUntil: 200, keys: plan.keys))
        let id = try PrekeyInventoryID(bytes: [UInt8](repeating: 9, count: 32))
        XCTAssertThrowsError(try PublicationPlan(directory: plan.directory, validFrom: 100, validUntil: 200,
            keys: [.init(kind: .signedClassical, validFrom: 100, validUntil: 200, reusedRequest: id),
                   .init(kind: .lastResortPQ, validFrom: 100, validUntil: 200, reusedRequest: id)]))
    }
    func testPublicationStatesRejectDirtyAbsenceAndUnknownCompletion() throws {
        var value = qpc_publication_status_v1()
        XCTAssertEqual(try publicationStatus(value), .absent)
        value.state = 3
        XCTAssertEqual(try publicationStatus(value), .retired)
        value.intent.0 = 1
        XCTAssertThrowsError(try publicationStatus(value))
        value.state = 1
        XCTAssertEqual(try publicationStatus(value), .reserved(intent: octets(value.intent)))
        value.artifact.0 = 1
        XCTAssertThrowsError(try publicationStatus(value))
        value.state = 2
        XCTAssertThrowsError(try publicationStatus(value))
        value.manifest.0 = 1
        XCTAssertEqual(try publicationStatus(value), .prepared(intent: octets(value.intent), manifest: octets(value.manifest), artifact: octets(value.artifact)))
        value.reserved_zero = 1
        XCTAssertThrowsError(try publicationStatus(value))
        value.reserved_zero = 0; value.state = 4
        XCTAssertThrowsError(try publicationStatus(value))
    }
    private func fixture() -> [UInt8] {
        var bytes = Array("QPPUBA01".utf8) + [UInt8](repeating: 1, count: 32)
        bytes += [UInt8](repeating: 2, count: 32) + [UInt8](repeating: 3, count: 32)
        bytes += [0, 0, 14, 83] + [UInt8](repeating: 4, count: 3667) + [0, 2]
        bytes += [UInt8](repeating: 5, count: 32) + [UInt8](repeating: 6, count: 32)
        for index: UInt8 in [0, 1] { bytes += [0, 62, 0, index] + [UInt8](repeating: 7, count: 60) }
        return bytes
    }
    func testPublicationArtifactOwnsCompleteBytesAndRejectsTruncationSubstitutionAndTail() throws {
        let id = try PrekeyPublicationID(bytes: [UInt8](repeating: 1, count: 32)), plan = try plan()
        var bytes = fixture()
        let result = try PreparedPublication(bytes: bytes, expectedID: id, plan: plan)
        XCTAssertEqual(result.canonicalBytes, bytes)
        XCTAssertEqual(result.membershipProofs.count, 2)
        XCTAssertEqual(result.inventoryRequests.map(\.bytes), [[UInt8](repeating: 5, count: 32), [UInt8](repeating: 6, count: 32)])
        bytes[0] = 0
        XCTAssertEqual(result.canonicalBytes.first, 81)
        for wrong in [bytes, Array(fixture().dropLast()), fixture() + [1], Array(fixture().prefix(8))] {
            XCTAssertThrowsError(try PreparedPublication(bytes: wrong, expectedID: id, plan: plan))
        }
        XCTAssertThrowsError(try PreparedPublication(bytes: fixture(), expectedID: .init(bytes: [UInt8](repeating: 9, count: 32)), plan: plan))
        var reordered = fixture(); reordered[reordered.count - 61] = 0
        XCTAssertThrowsError(try PreparedPublication(bytes: reordered, expectedID: id, plan: plan))
    }
    func testPreparedDeviceCannotPublishOrAcquireAuthorityAndClosedOwnerStaysClosed() throws {
        let device = try ContinuityDevice.prepare(path: "/not-an-enrolled-device")
        let id = try PrekeyPublicationID(bytes: [UInt8](repeating: 1, count: 32))
        XCTAssertThrowsError(try device.nextPublication())
        XCTAssertThrowsError(try device.preparePublication(id, plan: plan()))
        try device.cancel()
        XCTAssertThrowsError(try device.status(publication: id))
        try device.close()
        XCTAssertThrowsError(try device.nextPublication())
    }
}
