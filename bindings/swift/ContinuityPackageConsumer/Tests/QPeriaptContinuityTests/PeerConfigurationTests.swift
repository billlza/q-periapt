// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptContinuity
import CQPCOwner

final class PeerConfigurationTests: XCTestCase {
    private func account(_ root: [UInt8]) throws -> AccountPin {
        try AccountPin(account: AccountID(bytes: [UInt8](repeating: 1, count: 32)), root: root,
            family: [UInt8](repeating: 2, count: 32),
            checkpoint: RosterCheckpoint(version: 1, digest: [UInt8](repeating: 3, count: 32)))
    }
    func testCallerMutationCannotChangeStoredOrNativePeerInputs() throws {
        var root = [UInt8](repeating: 4, count: 1985), device = [UInt8](repeating: 5, count: 16)
        var bundle: [UInt8] = [6, 7], certificate: [UInt8] = [8, 9], directory = [UInt8](repeating: 10, count: 32)
        let expectation = try PeerDeviceExpectation(account: account(root), device: device, generation: UInt64.max)
        let value = try PeerConfiguration(initiator: expectation, responder: expectation, directory: directory,
            bundle: bundle, tlsPeerCertificate: certificate, tlsPeerName: "peer.test")
        root[0] = 0; device[0] = 0; bundle[0] = 0; certificate[0] = 0; directory[0] = 0
        try value.withNative(quality: .oneTimeBoth, role: .initiator) { pointer in
            let input = pointer.pointee
            XCTAssertEqual(input.header.struct_size, 384); XCTAssertEqual(input.header.version, 1)
            XCTAssertEqual(input.initiator.generation, UInt64.max)
            XCTAssertEqual(Array(UnsafeBufferPointer(start: input.initiator.account.root, count: input.initiator.account.root_length)), [UInt8](repeating: 4, count: 1985))
            XCTAssertEqual(Array(UnsafeBufferPointer(start: input.bundle.data, count: input.bundle.length)), [6, 7])
            XCTAssertEqual(Array(UnsafeBufferPointer(start: input.tls_peer.data, count: input.tls_peer.length)), [8, 9])
            XCTAssertEqual(input.quality, 1); XCTAssertEqual(input.role, 1)
        }
        XCTAssertEqual(value.initiator.device, [UInt8](repeating: 5, count: 16))
        XCTAssertEqual(value.directory, [UInt8](repeating: 10, count: 32))
    }
    func testWidthsAndBoundsPrecedeNativeAdmission() throws {
        XCTAssertEqual(MemoryLayout<qpc_peer_device_v1>.size, 144)
        XCTAssertEqual(MemoryLayout<qpc_peer_configuration_v1>.size, 384)
        let pin = try account([UInt8](repeating: 4, count: 1985))
        XCTAssertThrowsError(try PeerDeviceExpectation(account: pin, device: [1], generation: 1))
        XCTAssertThrowsError(try PeerDeviceExpectation(account: pin, device: [UInt8](repeating: 1, count: 16), generation: 0))
        let expected = try PeerDeviceExpectation(account: pin, device: [UInt8](repeating: 1, count: 16), generation: 1)
        for name in ["", "a\u{0}b", String(repeating: "é", count: 65)] {
            XCTAssertThrowsError(try PeerConfiguration(initiator: expected, responder: expected,
                directory: [UInt8](repeating: 1, count: 32), bundle: [1], tlsPeerCertificate: [1], tlsPeerName: name))
        }
        XCTAssertThrowsError(try PeerConfiguration(initiator: expected, responder: expected,
            directory: [UInt8](repeating: 1, count: 32), bundle: [UInt8](repeating: 1, count: 65537),
            tlsPeerCertificate: [1], tlsPeerName: "peer.test"))
    }
}
