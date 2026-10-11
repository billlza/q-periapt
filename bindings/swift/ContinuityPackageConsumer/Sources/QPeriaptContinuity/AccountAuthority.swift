// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

public enum AccountAuthorityTag: Sendable {}
public enum ApplicationAccountTag: Sendable {}
public typealias AccountAuthorityID = ContinuityID<AccountAuthorityTag>
public typealias ApplicationAccountID = ContinuityID<ApplicationAccountTag>

/// Original host-provisioned registry identity, family and independent witness pin.
public struct AccountAuthorityTrust: Sendable {
    public let identity: AccountAuthorityID
    public let family: [UInt8]
    public let witness: [UInt8]
    public let publicKey: [UInt8]

    public init(identity: AccountAuthorityID, family: [UInt8], witness: [UInt8], publicKey: [UInt8]) throws {
        guard family.count == 32, witness.count == 32, publicKey.count == 1985 else {
            throw ContinuityBoundaryError.inputLength
        }
        guard [identity.bytes, family, witness].allSatisfy({ $0.contains(where: { $0 != 0 }) }) else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        self.identity = identity; self.family = family; self.witness = witness; self.publicKey = publicKey
    }
    func withNative<T>(_ body: (UnsafePointer<qpc_authority_options_v1>) throws -> T) rethrows -> T {
        try publicKey.withUnsafeBufferPointer { key in
            var value = qpc_authority_options_v1()
            value.struct_size = UInt32(MemoryLayout.size(ofValue: value))
            withUnsafeMutableBytes(of: &value.identity) { $0.copyBytes(from: identity.bytes) }
            withUnsafeMutableBytes(of: &value.family) { $0.copyBytes(from: family) }
            withUnsafeMutableBytes(of: &value.witness) { $0.copyBytes(from: witness) }
            value.public_key = key.baseAddress; value.public_key_length = key.count
            return try withUnsafePointer(to: &value, body)
        }
    }
}

/// Public expected mapping, not authority without its original live registry.
public struct AccountAuthorityCheckpoint: Sendable, Equatable {
    public let application: ApplicationAccountID
    public let revision: UInt64
    public let account: AccountID
    public init(application: ApplicationAccountID, revision: UInt64, account: AccountID) throws {
        guard revision > 0, revision < UInt64.max, application.bytes.contains(where: { $0 != 0 }),
              account.bytes.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.application = application; self.revision = revision; self.account = account
    }
    func native() -> qpc_authority_checkpoint_v1 {
        var value = qpc_authority_checkpoint_v1()
        withUnsafeMutableBytes(of: &value.application) { $0.copyBytes(from: application.bytes) }
        value.revision = revision
        withUnsafeMutableBytes(of: &value.account) { $0.copyBytes(from: account.bytes) }
        return value
    }
}

func accountAuthorityCheckpoint(_ raw: inout qpc_authority_checkpoint_v1) throws -> AccountAuthorityCheckpoint {
    let application = withUnsafeBytes(of: &raw.application) { Array($0) }
    let account = withUnsafeBytes(of: &raw.account) { Array($0) }
    guard raw.revision > 0, raw.revision < UInt64.max,
          application.contains(where: { $0 != 0 }), account.contains(where: { $0 != 0 }) else {
        throw ContinuityBoundaryError.malformedOutput
    }
    return try AccountAuthorityCheckpoint(application: ApplicationAccountID(bytes: application),
        revision: raw.revision, account: AccountID(bytes: account))
}

/// Host-owned registry. Keep this object alive while selected children operate.
/// Children do not retain it through ARC; close or final release revokes their
/// native read access. Reopening does not revive an old child's admission.
public final class ContinuityAccountAuthority: Sendable {
    let native: NativeOwner
    private init(_ native: NativeOwner) { self.native = native }

    public static func provisionWrappingKey(path: String) throws {
        let path = try textBytes(path, maximum: 4096)
        var error = qpc_error_v1()
        let code = path.withUnsafeBufferPointer {
            qpc_authority_v1_provision_wrapping_key($0.baseAddress, $0.count, &error)
        }
        try checked(code, &error)
    }
    private static func prepare(path: String, trust: AccountAuthorityTrust, create: Bool) throws -> Self {
        let path = try textBytes(path, maximum: 4096)
        return Self(try NativeOwner.prepareOwned { handle, error in
            trust.withNative { trust in
                path.withUnsafeBufferPointer {
                    if create { return qpc_authority_v1_prepare_create($0.baseAddress, $0.count, trust, &handle, &error) }
                    return qpc_authority_v1_prepare_open($0.baseAddress, $0.count, trust, &handle, &error)
                }
            }
        })
    }
    public static func prepareCreate(path: String, trust: AccountAuthorityTrust) throws -> ContinuityAccountAuthority {
        try prepare(path: path, trust: trust, create: true)
    }
    public static func prepareOpen(path: String, trust: AccountAuthorityTrust) throws -> ContinuityAccountAuthority {
        try prepare(path: path, trust: trust, create: false)
    }
    public func finishOpen() throws { try native.finishOpen() }
    public func cancel() throws { try native.cancel() }
    public func close() throws { try native.close() }

    public func checkpoint(application: ApplicationAccountID) throws -> AccountAuthorityCheckpoint {
        try native.call { handle in
            var output = qpc_authority_checkpoint_v1(), error = qpc_error_v1()
            let code = application.bytes.withUnsafeBufferPointer {
                qpc_authority_v1_checkpoint(handle, $0.baseAddress, &output, &error)
            }
            try checked(code, &error)
            let checkpoint = try accountAuthorityCheckpoint(&output)
            guard checkpoint.application == application else { throw ContinuityBoundaryError.malformedOutput }
            return checkpoint
        }
    }
    /// Associate only an independently approved pin and actual verified credential/roster.
    public func associate(application: ApplicationAccountID, pin: AccountPin,
                          certificate: [UInt8], roster: [UInt8]) throws -> AccountAuthorityCheckpoint {
        guard (1...8192).contains(certificate.count), (1...65536).contains(roster.count),
              application.bytes.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        return try native.call { handle in
            try pin.withNative { nativePin in
                try configurationBlobs([certificate, roster]) { blobs in
                    var input = qpc_authority_association_v1()
                    input.struct_size = UInt32(MemoryLayout.size(ofValue: input))
                    withUnsafeMutableBytes(of: &input.application) { $0.copyBytes(from: application.bytes) }
                    input.pin = nativePin
                    input.certificate = blobs[0].data; input.certificate_length = blobs[0].length
                    input.roster = blobs[1].data; input.roster_length = blobs[1].length
                    var output = qpc_authority_checkpoint_v1(), error = qpc_error_v1()
                    try checked(qpc_authority_v1_associate(handle, &input, &output, &error), &error)
                    let checkpoint = try accountAuthorityCheckpoint(&output)
                    guard checkpoint.application == application, checkpoint.account == pin.account else {
                        throw ContinuityBoundaryError.malformedOutput
                    }
                    return checkpoint
                }
            }
        }
    }
    func select(enrollment: NativeOwner, checkpoint: AccountAuthorityCheckpoint) throws {
        try native.call { registry in
            try enrollment.call { handle in
                var input = qpc_authority_enrollment_selection_v1(), error = qpc_error_v1()
                input.struct_size = UInt32(MemoryLayout.size(ofValue: input))
                input.registry = registry; input.checkpoint = checkpoint.native()
                try checked(qpc_authority_v1_select_enrollment(handle, &input, &error), &error)
            }
        }
    }
}
