// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

// Every pointer remains inside the innermost synchronous call. Empty optional
// fields use NULL/0, not an empty Array's implementation-dependent base address.
func configurationBlobs<T>(_ arrays: [[UInt8]],
    _ body: ([qpc_configuration_blob_v1]) throws -> T) throws -> T {
    func visit(_ index: Int, _ values: [qpc_configuration_blob_v1]) throws -> T {
        if index == arrays.count { return try body(values) }
        return try arrays[index].withUnsafeBufferPointer { bytes in
            let value = qpc_configuration_blob_v1(data: bytes.isEmpty ? nil : bytes.baseAddress,
                                                   length: bytes.count)
            return try visit(index + 1, values + [value])
        }
    }
    return try visit(0, [])
}

/// Original SDK authority supplied by the host independently of stored or incoming data.
/// Recoverable trust always retains the original deployment roots and scope.
public struct SdkPolicyTrust: Sendable {
    fileprivate let mode: UInt32
    fileprivate let scope: [UInt8]
    fileprivate let root: [UInt8]
    fileprivate let recoveryRoot: [UInt8]
    public static func fixed(root: [UInt8]) throws -> Self {
        guard root.count == 1952 else { throw ContinuityBoundaryError.inputLength }
        return Self(mode: 1, scope: [UInt8](repeating: 0, count: 32), root: root, recoveryRoot: [])
    }
    public static func recoverable(scope: [UInt8], initialRoot: [UInt8], recoveryRoot: [UInt8]) throws -> Self {
        guard scope.count == 32, initialRoot.count == 1952, recoveryRoot.count == 1952 else {
            throw ContinuityBoundaryError.inputLength
        }
        guard scope.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        return Self(mode: 2, scope: scope, root: initialRoot, recoveryRoot: recoveryRoot)
    }
    fileprivate func native(_ root: qpc_configuration_blob_v1, _ recovery: qpc_configuration_blob_v1) -> qpc_configuration_sdk_trust_v1 {
        var value = qpc_configuration_sdk_trust_v1()
        value.mode = mode; value.initial_root = root; value.recovery_root = recovery
        withUnsafeMutableBytes(of: &value.scope) { $0.copyBytes(from: scope) }
        return value
    }
}

/// Exact signed initial SDK policy; this is never a desired update during current-open.
public struct InitialSdkPolicy: Sendable {
    fileprivate let trust: SdkPolicyTrust
    fileprivate let policy: [UInt8]
    fileprivate let signature: [UInt8]
    fileprivate let enrollment: [UInt8]
    public init(trust: SdkPolicyTrust, policy: [UInt8], signature: [UInt8], recoveryEnrollment: [UInt8]? = nil) throws {
        guard (1...65536).contains(policy.count), signature.count == 3309 else {
            throw ContinuityBoundaryError.inputLength
        }
        if trust.mode == 1 {
            guard recoveryEnrollment == nil else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        } else {
            guard recoveryEnrollment?.count == 3309 else { throw ContinuityBoundaryError.inputLength }
        }
        self.trust = trust; self.policy = policy; self.signature = signature
        enrollment = recoveryEnrollment ?? []
    }
}

/// Caller-supplied local DER identity, independent of account and peer trust.
/// The caller controls its input copies. Native owned DER snapshots are cleared
/// by the existing key loader; this value makes no erase guarantee for caller storage.
public struct LocalTlsIdentity: Sendable {
    fileprivate let certificate: [UInt8]
    fileprivate let key: [UInt8]
    public init(certificate: [UInt8], privateKey: [UInt8]) throws {
        guard (1...8192).contains(certificate.count), (1...8192).contains(privateKey.count) else {
            throw ContinuityBoundaryError.inputLength
        }
        self.certificate = certificate; key = privateKey
    }
}

private func configurationPolicy(_ policy: PolicyDocument, _ root: qpc_configuration_blob_v1,
                                  _ wire: qpc_configuration_blob_v1) -> qpc_configuration_protocol_v1 {
    var value = qpc_configuration_protocol_v1()
    value.root = root; value.policy = wire; value.version = policy.checkpoint.version
    withUnsafeMutableBytes(of: &value.family) { $0.copyBytes(from: policy.family) }
    withUnsafeMutableBytes(of: &value.digest) { $0.copyBytes(from: policy.checkpoint.digest) }
    return value
}

/// Immutable bounded first-use inputs. Preparation grants neither a device identity
/// nor traffic permission. Native finishOpen validates signatures and local TLS,
/// then publishes configuration, SDK storage and the initial wrapping key together.
public struct InstallationConfiguration: Sendable {
    private let sdk: InitialSdkPolicy
    private let policy: PolicyDocument
    private let tls: LocalTlsIdentity
    public init(sdk: InitialSdkPolicy, protocolPolicy: PolicyDocument, tls: LocalTlsIdentity) {
        self.sdk = sdk; policy = protocolPolicy; self.tls = tls
    }
    fileprivate func withNative<T>(_ body: (UnsafePointer<qpc_configuration_create_v1>) throws -> T) throws -> T {
        try configurationBlobs([sdk.trust.root, sdk.trust.recoveryRoot, sdk.policy, sdk.signature,
                                sdk.enrollment, policy.root, policy.wire, tls.certificate, tls.key]) { blobs in
            var value = qpc_configuration_create_v1()
            value.header = qpc_configuration_header_v1(struct_size: UInt32(MemoryLayout.size(ofValue: value)), version: 1)
            value.sdk = sdk.trust.native(blobs[0], blobs[1])
            value.sdk_policy = blobs[2]; value.sdk_signature = blobs[3]; value.recovery_enrollment = blobs[4]
            value.protocol = configurationPolicy(policy, blobs[5], blobs[6])
            value.tls_certificate = blobs[7]; value.tls_key = blobs[8]
            return try withUnsafePointer(to: &value, body)
        }
    }
}

/// Original independently provisioned witness pin and explicitly chosen carrier.
/// This value is not witness enrollment or proof of an authenticated remote reply.
public struct ConfigurationWitness: Sendable {
    private let carrier: UInt32
    private let identity: [UInt8]
    private let publicKey: [UInt8]
    private let address: [UInt8]
    private let timeout: UInt32
    private let peer: [UInt8]
    private let tls: LocalTlsIdentity?
    private let name: [UInt8]
    private init(carrier: UInt32, identity: [UInt8], publicKey: [UInt8], address: String,
                 timeoutMilliseconds: UInt32, peer: [UInt8], tls: LocalTlsIdentity?, name: [UInt8]) throws {
        guard identity.count == 32, publicKey.count == 1985 else { throw ContinuityBoundaryError.inputLength }
        guard identity.contains(where: { $0 != 0 }), (1...10000).contains(timeoutMilliseconds) else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        self.carrier = carrier; self.identity = identity; self.publicKey = publicKey
        self.address = try textBytes(address, maximum: 128); timeout = timeoutMilliseconds
        self.peer = peer; self.tls = tls; self.name = name
    }
    public static func signedTCP(identity: [UInt8], publicKey: [UInt8], address: String,
                                 timeoutMilliseconds: UInt32) throws -> Self {
        try Self(carrier: 1, identity: identity, publicKey: publicKey, address: address,
                 timeoutMilliseconds: timeoutMilliseconds, peer: [], tls: nil, name: [])
    }
    public static func mutualTLS(identity: [UInt8], publicKey: [UInt8], address: String,
                                 timeoutMilliseconds: UInt32, peerCertificate: [UInt8],
                                 serverName: String, localIdentity: LocalTlsIdentity) throws -> Self {
        guard (1...8192).contains(peerCertificate.count) else { throw ContinuityBoundaryError.inputLength }
        return try Self(carrier: 2, identity: identity, publicKey: publicKey, address: address,
                        timeoutMilliseconds: timeoutMilliseconds, peer: peerCertificate, tls: localIdentity,
                        name: textBytes(serverName, maximum: 128))
    }
    fileprivate func withNative<T>(_ body: (UnsafePointer<qpc_configuration_witness_v1>) throws -> T) throws -> T {
        try configurationBlobs([publicKey, address, peer, tls?.certificate ?? [], tls?.key ?? [], name]) { blobs in
            var value = qpc_configuration_witness_v1()
            value.header = qpc_configuration_header_v1(struct_size: UInt32(MemoryLayout.size(ofValue: value)), version: 1)
            value.carrier = carrier
            withUnsafeMutableBytes(of: &value.identity) { $0.copyBytes(from: identity) }
            value.options = qpc_witness_v1(address: blobs[1].data, address_length: blobs[1].length, timeout_ms: timeout)
            value.public_key = blobs[0]; value.tls_peer = blobs[2]; value.tls_certificate = blobs[3]
            value.tls_key = blobs[4]; value.tls_name = blobs[5]
            return try withUnsafePointer(to: &value, body)
        }
    }
}

/// One owned configuration/SDK lease. Creation, exact initial reconciliation and
/// current-open are separate operations. No error authorizes missing-state repair.
public final class ContinuityConfiguration: Sendable {
    private let reference: OwnerTransferReference
    private init(_ native: NativeOwner) { reference = OwnerTransferReference(native, label: "configuration") }
    private static func initial(path: String, input: InstallationConfiguration, reconcile: Bool) throws -> Self {
        let path = try textBytes(path, maximum: 4096)
        let native = try NativeOwner.prepareConfiguration { handle, error in
            try input.withNative { input in
                path.withUnsafeBufferPointer {
                    if reconcile { return qpc_configuration_v1_prepare_reconcile($0.baseAddress, $0.count, input, &handle, &error) }
                    return qpc_configuration_v1_prepare_create($0.baseAddress, $0.count, input, &handle, &error)
                }
            }
        }
        return Self(native)
    }
    public static func prepareCreate(path: String, input: InstallationConfiguration) throws -> ContinuityConfiguration {
        try initial(path: path, input: input, reconcile: false)
    }
    /// Compare the exact independently retained first-use inputs after an unknown
    /// publication result; never overwrite, advance policy or regenerate a key.
    public static func prepareReconcile(path: String, input: InstallationConfiguration) throws -> ContinuityConfiguration {
        try initial(path: path, input: input, reconcile: true)
    }
    /// Open the committed SDK state under original host trust and pinned protocol
    /// metadata. Stored root files are not trust, and initial policy is not replayed.
    public static func prepareOpen(path: String, trust: SdkPolicyTrust, protocolPolicy: PolicyDocument) throws -> ContinuityConfiguration {
        let path = try textBytes(path, maximum: 4096)
        let native = try NativeOwner.prepareConfiguration { handle, error in
            try configurationBlobs([trust.root, trust.recoveryRoot, protocolPolicy.root, protocolPolicy.wire]) { blobs in
                var value = qpc_configuration_open_v1()
                value.header = qpc_configuration_header_v1(struct_size: UInt32(MemoryLayout.size(ofValue: value)), version: 1)
                value.sdk = trust.native(blobs[0], blobs[1])
                value.protocol = configurationPolicy(protocolPolicy, blobs[2], blobs[3])
                return path.withUnsafeBufferPointer { qpc_configuration_v1_prepare_open($0.baseAddress, $0.count, &value, &handle, &error) }
            }
        }
        return ContinuityConfiguration(native)
    }
    public func finishOpen() throws { try reference.call { try $0.finishOpen() } }
    public func cancel() throws { try reference.call(cancellation: true) { try $0.cancel() } }
    public func close() throws { try reference.close() }
    private func enrollment(intent: EnrollmentIntent, witness: ConfigurationWitness?, mode: UInt32) throws -> ContinuityEnrollment {
        try reference.transfer { native in
            let successor = ContinuityEnrollment.configured(native)
            try native.call { handle in
                var error = qpc_error_v1()
                func begin(_ witness: UnsafePointer<qpc_configuration_witness_v1>?) throws {
                    let code = intent.withNative { qpc_configuration_v1_begin_enrollment(handle, $0, mode, witness, &error) }
                    try checked(code, &error)
                }
                if let witness { try witness.withNative(begin) } else { try begin(nil) }
            }
            return successor
        }
    }
    /// Move the existing owner into a new, explicitly approved original registration.
    /// Missing witness input never permits activation under a required profile.
    public func createEnrollment(intent: EnrollmentIntent, witness: ConfigurationWitness? = nil) throws -> ContinuityEnrollment {
        try enrollment(intent: intent, witness: witness, mode: 1)
    }
    /// Resume only the original approved intent; a failed open is not first use.
    public func resumeEnrollment(intent: EnrollmentIntent, witness: ConfigurationWitness? = nil) throws -> ContinuityEnrollment {
        try enrollment(intent: intent, witness: witness, mode: 2)
    }
    /// Move this configured target's SDK lease into the original enrollment.
    /// This selects no durable approval/adoption; use the existing signed renewal
    /// transaction afterward. A failure after admission can consume both owners.
    public func selectContinuationTarget(for enrollment: ContinuityEnrollment) throws {
        try reference.transfer { native in
            try enrollment.selectConfiguration(native)
            // Only the now-empty source slot is closed. The target SDK lease is
            // already held by enrollment; keeping this Swift object cannot pin it.
            try native.close()
        }
    }
}
