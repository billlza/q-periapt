// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPeriapt
import Foundation

/// Public error classification from the native ABI 2 SDK extension.
public struct QPeriaptSDKError: Error, Equatable, Sendable, CustomStringConvertible, LocalizedError {
    public let operation: String
    public let code: Int32
    public var description: String {
        "\(operation): \(String(cString: q_periapt_status_name(code))) (\(code))"
    }
    public var errorDescription: String? { description }
}

func check(_ code: Int32, _ operation: String) throws {
    guard code == Q_PERIAPT_OK else {
        throw QPeriaptSDKError(operation: operation, code: code)
    }
}

/// Only immutable handle identities cross threads. All mutable key/secret state
/// and operation/disposal synchronization remain in the native registry.
final class OwnedHandle: Sendable {
    let value: UInt64
    let parent: OwnedHandle?

    init(_ value: UInt64, parent: OwnedHandle? = nil) {
        self.value = value
        self.parent = parent
    }

    func use<T>(_ body: (UInt64) throws -> T) rethrows -> T {
        // Pin this wrapper and its parent through the native call, even when an
        // optimizer can otherwise prove the raw integer is our last Swift use.
        try withExtendedLifetime(self) { try body(value) }
    }

    func close() throws {
        let status = use { q_periapt_sdk_close($0) }
        if status != Q_PERIAPT_ERR_CLOSED { try check(status, "close") }
    }

    deinit {
        let status = q_periapt_sdk_close(value)
        if status != Q_PERIAPT_OK && status != Q_PERIAPT_ERR_CLOSED {
            // Destructors cannot throw. Explicit close reports failures to the
            // caller; an unexpected destructor failure is observable as well.
            NSLog("Q-Periapt SDK owner disposal failed with status %d", status)
        }
    }
}

extension Array where Element == UInt8 {
    func withInput<T>(_ body: (QPeriaptInput) throws -> T) rethrows -> T {
        try withUnsafeBufferPointer { pointer in
            try body(QPeriaptInput(data: pointer.baseAddress, len: UInt(pointer.count)))
        }
    }
    mutating func withOutput<T>(_ body: (QPeriaptOutput) throws -> T) rethrows -> T {
        try withUnsafeMutableBufferPointer { pointer in
            try body(QPeriaptOutput(data: pointer.baseAddress, len: UInt(pointer.count)))
        }
    }
}

/// Public, copyable hybrid encapsulation key. Private bytes are never part of it.
public struct QPeriaptPublicKey: Sendable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) throws {
        guard bytes.count == Int(Q_PERIAPT_SDK_PUBLIC_KEY_LEN) else {
            throw QPeriaptSDKError(operation: "public key", code: Q_PERIAPT_ERR_LENGTH)
        }
        self.bytes = bytes
    }
}

/// Public ciphertext. Correct-length invalid PQ ciphertexts use implicit rejection.
public struct QPeriaptCiphertext: Sendable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) throws {
        guard bytes.count == Int(Q_PERIAPT_SDK_CIPHERTEXT_LEN) else {
            throw QPeriaptSDKError(operation: "ciphertext", code: Q_PERIAPT_ERR_LENGTH)
        }
        self.bytes = bytes
    }
}

/// Immutable verified configuration. Persist trustedState() atomically before
/// using its keys. The host pins trust roots and maintains rollback state.
public final class QPeriaptRuntime: Sendable {
    let owned: OwnedHandle
    init(owned: OwnedHandle) { self.owned = owned }

    public init(policy: [UInt8], signature: [UInt8], trustRoot: [UInt8],
                previousState: [UInt8] = [], maxLiveKeys: UInt32 = 32,
                maxInFlight: UInt32 = 4) throws {
        guard q_periapt_abi_version() == 2,
              q_periapt_sdk_extension_version() == Q_PERIAPT_SDK_EXTENSION_VERSION,
              let size = UInt32(exactly: MemoryLayout<QPeriaptRuntimeOptions>.size) else {
            throw QPeriaptSDKError(operation: "SDK contract", code: Q_PERIAPT_ERR_LIMITS)
        }
        var handle: UInt64 = 0
        let status = policy.withInput { policyInput in
            signature.withInput { signatureInput in
                trustRoot.withInput { rootInput in
                    previousState.withInput { stateInput in
                        var options = QPeriaptRuntimeOptions(
                            struct_size: size,
                            extension_version: UInt32(Q_PERIAPT_SDK_EXTENSION_VERSION),
                            policy: policyInput, signature: signatureInput,
                            trust_root: rootInput, previous_state: stateInput,
                            max_live_keys: maxLiveKeys, max_in_flight: maxInFlight)
                        return q_periapt_sdk_runtime_new(&options, &handle)
                    }
                }
            }
        }
        try check(status, "verify policy")
        owned = OwnedHandle(handle)
    }

    public func trustedState() throws -> [UInt8] {
        try owned.use { handle in
            var bytes = [UInt8](repeating: 0, count: 36)
            try check(bytes.withOutput { q_periapt_sdk_runtime_state(handle, $0) }, "trusted state")
            return bytes
        }
    }

    /// A verified policy can disable the fixed suite. Such a runtime retains
    /// trusted state and accepts newer policy updates; key operations fail.
    public func isEnabled() throws -> Bool {
        try owned.use { handle in
            var enabled: UInt32 = 0
            try check(q_periapt_sdk_runtime_enabled(handle, &enabled), "runtime enabled")
            return enabled == 1
        }
    }

    public func preparePolicyUpdate(policy: [UInt8], signature: [UInt8]) throws -> QPeriaptPolicyUpdate {
        try owned.use { handle in
            var update: UInt64 = 0
            let status = policy.withInput { policyInput in
                signature.withInput { q_periapt_sdk_runtime_prepare_update(handle, policyInput, $0, &update) }
            }
            try check(status, "prepare policy update")
            return QPeriaptPolicyUpdate(owned: OwnedHandle(update, parent: owned))
        }
    }

    public func generateKey() throws -> QPeriaptKey {
        try owned.use { handle in
            var key: UInt64 = 0
            try check(q_periapt_sdk_key_generate(handle, &key), "generate key")
            return QPeriaptKey(owned: OwnedHandle(key, parent: owned))
        }
    }

    public func encapsulate(to peer: QPeriaptPublicKey,
                            applicationContext: [UInt8]) throws -> QPeriaptSDKEncapsulation {
        try owned.use { handle in
            var bytes = [UInt8](repeating: 0, count: Int(Q_PERIAPT_SDK_CIPHERTEXT_LEN))
            var secret: UInt64 = 0
            let status = peer.bytes.withInput { peerInput in
                applicationContext.withInput { contextInput in
                    bytes.withOutput { q_periapt_sdk_encapsulate(handle, peerInput, contextInput, $0, &secret) }
                }
            }
            try check(status, "encapsulate")
            let owner = QPeriaptSecret(owned: OwnedHandle(secret, parent: owned))
            return QPeriaptSDKEncapsulation(ciphertext: try QPeriaptCiphertext(bytes: bytes), secret: owner)
        }
    }

    /// Revoke this runtime and its child handles; repeated close is harmless.
    /// Native work already holding a lease retains its storage until it finishes.
    public func close() throws { try owned.close() }

    @available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    public func generateKeyAsync() async throws -> QPeriaptKey {
        try await runOwnedOperation { try self.generateKey() }
    }

    @available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    public func encapsulateAsync(to peer: QPeriaptPublicKey,
                                 applicationContext: [UInt8]) async throws -> QPeriaptSDKEncapsulation {
        try await runOwnedOperation { try self.encapsulate(to: peer, applicationContext: applicationContext) }
    }
}

/// A shared Swift reference to one native key owner, never a private-key array.
public final class QPeriaptKey: Sendable {
    fileprivate let owned: OwnedHandle
    fileprivate init(owned: OwnedHandle) { self.owned = owned }

    public func publicKey() throws -> QPeriaptPublicKey {
        try owned.use { handle in
            var bytes = [UInt8](repeating: 0, count: Int(Q_PERIAPT_SDK_PUBLIC_KEY_LEN))
            try check(bytes.withOutput { q_periapt_sdk_key_public(handle, $0) }, "public key")
            return try QPeriaptPublicKey(bytes: bytes)
        }
    }

    public func decapsulate(_ ciphertext: QPeriaptCiphertext,
                            applicationContext: [UInt8]) throws -> QPeriaptSecret {
        try owned.use { handle in
            var secret: UInt64 = 0
            let status = ciphertext.bytes.withInput { ciphertextInput in
                applicationContext.withInput { q_periapt_sdk_decapsulate(handle, ciphertextInput, $0, &secret) }
            }
            try check(status, "decapsulate")
            return QPeriaptSecret(owned: OwnedHandle(secret, parent: owned.parent))
        }
    }

    public func close() throws { try owned.close() }

    @available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    public func decapsulateAsync(_ ciphertext: QPeriaptCiphertext,
                                 applicationContext: [UInt8]) async throws -> QPeriaptSecret {
        try await runOwnedOperation { try self.decapsulate(ciphertext, applicationContext: applicationContext) }
    }
}

/// Explicit plaintext expanded-key transfer. The application protects and erases
/// every Swift array copy. Imports bind to the supplied verified runtime and use
/// fresh platform randomness for the native pairwise consistency check.
public enum QPeriaptExpert {
    public static func importExpanded(_ bytes: [UInt8], into runtime: QPeriaptRuntime) throws -> QPeriaptKey {
        try runtime.owned.use { handle in
            var key: UInt64 = 0
            try check(bytes.withInput { q_periapt_sdk_expert_key_import(handle, $0, &key) }, "expert key import")
            return QPeriaptKey(owned: OwnedHandle(key, parent: runtime.owned))
        }
    }

    public static func exportExpanded(_ key: QPeriaptKey) throws -> [UInt8] {
        try key.owned.use { handle in
            var bytes = [UInt8](repeating: 0, count: Int(Q_PERIAPT_SDK_EXPANDED_KEY_LEN))
            try check(bytes.withOutput { q_periapt_sdk_expert_key_export(handle, $0) }, "expert key export")
            return bytes
        }
    }
}

/// Public state pair for a root-scoped, atomic host compare-and-persist operation.
public struct QPeriaptPolicyStates: Sendable {
    public let previous: [UInt8]
    public let next: [UInt8]
}

/// Prepared policy with no key-operation API. Close cancels preparation; it does
/// not undo host persistence. Only one candidate can replace its old runtime.
public final class QPeriaptPolicyUpdate: Sendable {
    private let owned: OwnedHandle
    fileprivate init(owned: OwnedHandle) { self.owned = owned }

    public func states() throws -> QPeriaptPolicyStates {
        try owned.use { handle in
            var bytes = [UInt8](repeating: 0, count: Int(Q_PERIAPT_SDK_POLICY_UPDATE_STATES_LEN))
            try check(bytes.withOutput { q_periapt_sdk_policy_update_states(handle, $0) }, "policy states")
            return QPeriaptPolicyStates(previous: Array(bytes.prefix(36)), next: Array(bytes.suffix(36)))
        }
    }

    /// Call only after atomic persistence succeeds. Revokes old owners and
    /// returns an independent runtime, which may be disabled by the new policy.
    /// If activation fails after persistence, stop old-runtime use and recover
    /// from the signed policy and persisted state. The SDK cannot verify storage.
    public func activateAfterPersisting() throws -> QPeriaptRuntime {
        try owned.use { handle in
            var runtime: UInt64 = 0
            try check(q_periapt_sdk_policy_update_activate(handle, &runtime), "activate policy update")
            return QPeriaptRuntime(owned: OwnedHandle(runtime))
        }
    }

    public func close() throws { try owned.close() }
}

/// Public ciphertext plus an owned secret reference. Copying this value aliases
/// the secret owner; it does not copy secret bytes, and close affects all aliases.
public struct QPeriaptSDKEncapsulation: Sendable {
    public let ciphertext: QPeriaptCiphertext
    public let secret: QPeriaptSecret
}

/// Global initiator/responder directions, shared by both protocol peers.
public enum QPeriaptKeyPurpose: UInt32, Sendable {
    case initiatorTraffic = 1
    case responderTraffic = 2
    case initiatorConfirmation = 3
    case responderConfirmation = 4
    case exporter = 5
}

/// A native combined-secret owner with explicit purpose derivation and export.
public final class QPeriaptSecret: Sendable {
    private let owned: OwnedHandle
    fileprivate init(owned: OwnedHandle) { self.owned = owned }

    /// Labels identify the application protocol/version/algorithm using 1..255
    /// printable ASCII bytes. Directions refer to global initiator/responder roles.
    public func deriveKey(purpose: QPeriaptKeyPurpose, protocolLabel: [UInt8],
                          context: [UInt8]) throws -> QPeriaptDerivedKey {
        try owned.use { handle in
            var key: UInt64 = 0
            let status = protocolLabel.withInput { label in
                context.withInput { q_periapt_sdk_secret_derive(handle, purpose.rawValue, label, $0, &key) }
            }
            try check(status, "derive purpose key")
            return QPeriaptDerivedKey(owned: OwnedHandle(key, parent: owned.parent))
        }
    }

    /// Copies the secret into caller-owned Swift storage. The caller must erase
    /// every independent copy; close cannot erase exported copy-on-write arrays.
    public func exportForProtocol() throws -> [UInt8] {
        try owned.use { handle in
            var bytes = [UInt8](repeating: 0, count: 32)
            try check(bytes.withOutput { q_periapt_sdk_secret_export(handle, $0) }, "export protocol secret")
            return bytes
        }
    }

    public func close() throws { try owned.close() }
}

/// One purpose-derived application key. Copies of this reference alias one owner.
public final class QPeriaptDerivedKey: Sendable {
    private let owned: OwnedHandle
    fileprivate init(owned: OwnedHandle) { self.owned = owned }
    /// Copy into caller-owned Swift memory for a cipher/MAC; erase every copy.
    public func exportForProtocol() throws -> [UInt8] {
        try owned.use { handle in
            var bytes = [UInt8](repeating: 0, count: 32)
            try check(bytes.withOutput { q_periapt_sdk_derived_key_export(handle, $0) }, "export derived key")
            return bytes
        }
    }
    public func close() throws { try owned.close() }
}

/// Cancellation never detaches a native call from its owner. A worker retains
/// all captured owners and discards its result on cancellation after the call.
/// Native cryptographic operations are synchronous and not forcibly interrupted.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
func runOwnedOperation<T: Sendable>(_ operation: @escaping @Sendable () throws -> T) async throws -> T {
    try Task.checkCancellation()
    let worker = Task.detached {
        try Task.checkCancellation()
        let result = try operation()
        try Task.checkCancellation()
        return result
    }
    return try await withTaskCancellationHandler {
        let result = try await worker.value
        try Task.checkCancellation()
        return result
    } onCancel: {
        worker.cancel()
    }
}
