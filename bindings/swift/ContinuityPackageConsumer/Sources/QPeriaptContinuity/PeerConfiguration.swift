// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner

/// Independently approved account, roster head and exact device generation.
/// Incoming public bundles cannot select or replace this expectation.
public struct PeerDeviceExpectation: Sendable {
    public let account: AccountPin
    public let device: [UInt8]
    public let generation: UInt64
    public init(account: AccountPin, device: [UInt8], generation: UInt64) throws {
        guard device.count == 16 else { throw ContinuityBoundaryError.inputLength }
        guard device.contains(where: { $0 != 0 }), generation != 0 else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        self.account = account; self.device = device; self.generation = generation
    }
    func withNative<T>(_ body: (qpc_peer_device_v1) throws -> T) rethrows -> T {
        try account.withNative { account in
            var value = qpc_peer_device_v1()
            value.account = account.pointee; value.generation = generation
            withUnsafeMutableBytes(of: &value.device) { $0.copyBytes(from: device) }
            return try body(value)
        }
    }
}

/// Copied public inputs under a live device. Account/directory/TLS expectations
/// must come from independent host trust. The signed bundle remains untrusted.
/// Construction and preparation do not authenticate a remote TLS endpoint.
public struct PeerConfiguration: Sendable {
    public let initiator: PeerDeviceExpectation
    public let responder: PeerDeviceExpectation
    public let directory: [UInt8]
    public let bundle: [UInt8]
    public let tlsPeerCertificate: [UInt8]
    public let tlsPeerName: String
    private let nameBytes: [UInt8]
    public init(initiator: PeerDeviceExpectation, responder: PeerDeviceExpectation,
                directory: [UInt8], bundle: [UInt8], tlsPeerCertificate: [UInt8], tlsPeerName: String) throws {
        guard directory.count == 32, (1...65536).contains(bundle.count),
              (1...8192).contains(tlsPeerCertificate.count) else { throw ContinuityBoundaryError.inputLength }
        guard directory.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        nameBytes = try textBytes(tlsPeerName, maximum: 128)
        self.initiator = initiator; self.responder = responder; self.directory = directory
        self.bundle = bundle; self.tlsPeerCertificate = tlsPeerCertificate; self.tlsPeerName = tlsPeerName
    }
    func withNative<T>(quality: PrekeyQuality, role: BootstrapRole,
                       _ body: (UnsafePointer<qpc_peer_configuration_v1>) throws -> T) throws -> T {
        try initiator.withNative { initiator in
            try responder.withNative { responder in
                try configurationBlobs([bundle, tlsPeerCertificate, nameBytes]) { blobs in
                    var value = qpc_peer_configuration_v1()
                    value.header = qpc_configuration_header_v1(struct_size: UInt32(MemoryLayout.size(ofValue: value)), version: 1)
                    value.quality = quality.rawValue; value.role = role.rawValue
                    value.initiator = initiator; value.responder = responder
                    withUnsafeMutableBytes(of: &value.directory) { $0.copyBytes(from: directory) }
                    value.bundle = blobs[0]; value.tls_peer = blobs[1]; value.tls_name = blobs[2]
                    return try withUnsafePointer(to: &value, body)
                }
            }
        }
    }
}
