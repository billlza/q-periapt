// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPeriapt

/// ORIGINAL independent recovery configuration. Retain it outside incoming
/// messages and the store. Construction checks shape, not operational key custody.
/// This profile has one fixed recovery root and no automatic v1-store migration.
public struct QPeriaptPolicyRecoveryTrust: Sendable {
    public let scope: [UInt8]
    public let initialRoot: [UInt8]
    public let recoveryRoot: [UInt8]
    /// Complete public statement for the recovery key to sign before provisioning.
    public let enrollmentMessage: [UInt8]

    public init(scope: [UInt8], initialRoot: [UInt8], recoveryRoot: [UInt8]) throws {
        var message = [UInt8](repeating: 0, count: Int(Q_PERIAPT_POLICY_RECOVERY_ENROLLMENT_MESSAGE_LEN))
        let status = scope.withInput { domain in
            initialRoot.withInput { initial in
                recoveryRoot.withInput { recovery in
                    message.withOutput { q_periapt_sdk_policy_recovery_enrollment_message(domain, initial, recovery, $0) }
                }
            }
        }
        try check(status, "recovery trust configuration")
        self.scope = scope; self.initialRoot = initialRoot; self.recoveryRoot = recoveryRoot
        enrollmentMessage = message
    }
}

/// Canonical public statement, without either role signature. Parsing does not
/// authorize recovery. The independent issuer must inspect the exact intent.
public struct QPeriaptPolicyRecoveryRequest: Sendable {
    public let encoded: [UInt8]
    public let approvalMessage: [UInt8]
    public let possessionMessage: [UInt8]

    public init(encoded: [UInt8]) throws {
        var approval = [UInt8](repeating: 0, count: Int(Q_PERIAPT_POLICY_RECOVERY_APPROVAL_MESSAGE_LEN))
        var possession = [UInt8](repeating: 0, count: Int(Q_PERIAPT_POLICY_RECOVERY_POSSESSION_MESSAGE_LEN))
        let status = encoded.withInput { request in
            approval.withOutput { approvalOutput in
                possession.withOutput { q_periapt_sdk_policy_recovery_signing_messages(request, approvalOutput, $0) }
            }
        }
        try check(status, "recovery request grammar")
        self.encoded = encoded; approvalMessage = approval; possessionMessage = possession
    }

    // Native parsing validated the fixed 2168-byte QPRCV001 layout above.
    public var trustBinding: [UInt8] { Array(encoded[8..<40]) }
    public var generation: UInt64 { encoded[40..<48].reduce(0) { ($0 << 8) | UInt64($1) } }
    public var operation: [UInt8] { Array(encoded[48..<80]) }
    public var previousRootDigest: [UInt8] { Array(encoded[80..<112]) }
    public var states: QPeriaptPolicyStates {
        QPeriaptPolicyStates(previous: Array(encoded[112..<148]), next: Array(encoded[2132..<2168]))
    }
    public var historyBinding: [UInt8] { Array(encoded[148..<180]) }
    public var incomingRoot: [UInt8] { Array(encoded[180..<2132]) }
}

/// Original request and two role signatures to retain across unknown outcomes.
/// Assembly/parsing verifies grammar and lengths only; the store verifies authority.
public struct QPeriaptPolicyRecoveryAuthorization: Sendable {
    public let request: QPeriaptPolicyRecoveryRequest
    public let encoded: [UInt8]

    public init(request: QPeriaptPolicyRecoveryRequest, approvalSignature: [UInt8],
                possessionSignature: [UInt8]) throws {
        guard approvalSignature.count == 3309, possessionSignature.count == 3309 else {
            throw QPeriaptSDKError(operation: "recovery role signatures", code: Q_PERIAPT_ERR_LENGTH)
        }
        self.request = request
        encoded = request.encoded + approvalSignature + possessionSignature
    }

    public init(encoded: [UInt8]) throws {
        guard encoded.count == Int(Q_PERIAPT_POLICY_RECOVERY_AUTHORIZATION_LEN) else {
            throw QPeriaptSDKError(operation: "recovery authorization", code: Q_PERIAPT_ERR_LENGTH)
        }
        request = try QPeriaptPolicyRecoveryRequest(encoded: Array(encoded.prefix(Int(Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN))))
        self.encoded = encoded
    }
}

/// Durable disposition of the ORIGINAL operation; not an independent receipt.
public enum QPeriaptPolicyRecoveryDisposition: UInt32, Sendable {
    case applied = 1
    case alreadyApplied = 2
    case appliedThenAdvanced = 3
}

/// Only a new application transfers ownership. Replays preserve the existing
/// owner and its keys/connections; they never return a duplicate native handle.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
public enum QPeriaptPolicyRecoveryResult: Sendable {
    case applied(QPeriaptPersistentRuntime)
    case alreadyApplied
    case appliedThenAdvanced

    func discardReturnedOwner() async throws {
        if case let .applied(owner) = self { try await owner.close() }
    }
}

/// Opening always returns a new owned runtime, including when the original
/// recovery committed earlier or was followed by a newer authorized policy.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
public struct QPeriaptPolicyRecoveryReopen: Sendable {
    public let runtime: QPeriaptPersistentRuntime
    public let disposition: QPeriaptPolicyRecoveryDisposition
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
extension QPeriaptPersistentRuntime {
    /// Explicit first provisioning with independent enrollment approval. Never
    /// replaces an existing file or silently enrolls an existing v1 store.
    public static func provisionRecoverable(at path: String, policy: [UInt8], signature: [UInt8],
        trust: QPeriaptPolicyRecoveryTrust, enrollmentSignature: [UInt8],
        maxLiveKeys: UInt32 = 32, maxInFlight: UInt32 = 4) async throws -> QPeriaptPersistentRuntime {
        try await runPersistentOperation {
            try constructRecoverable(at: path, policy: policy, signature: signature, trust: trust,
                enrollment: enrollmentSignature, authorization: [], mode: .provision,
                maxLiveKeys: maxLiveKeys, maxInFlight: maxInFlight).0
        }
    }

    /// Open using ORIGINAL trust and reconcile a desired ordinary policy under
    /// the currently authorized root. Use openRecovering for uncertain root changes.
    public static func openRecoverable(at path: String, policy: [UInt8], signature: [UInt8],
        trust: QPeriaptPolicyRecoveryTrust, maxLiveKeys: UInt32 = 32,
        maxInFlight: UInt32 = 4) async throws -> QPeriaptPersistentRuntime {
        try await runPersistentOperation {
            try constructRecoverable(at: path, policy: policy, signature: signature, trust: trust,
                enrollment: [], authorization: [], mode: .configured,
                maxLiveKeys: maxLiveKeys, maxInFlight: maxInFlight).0
        }
    }

    /// Explicitly enroll an existing v1 store after closing its previous owner.
    /// Retain the exact original signed policy, independent trust and enrollment
    /// proof for retries after errors/cancellation. The policy floor is preserved;
    /// missing files are never provisioned. Later policy/root changes require
    /// their own recovery entry. Success does not imply a new commit occurred.
    public static func enrollRecovery(at path: String, policy: [UInt8], signature: [UInt8],
        trust: QPeriaptPolicyRecoveryTrust, enrollmentSignature: [UInt8],
        maxLiveKeys: UInt32 = 32, maxInFlight: UInt32 = 4) async throws -> QPeriaptPersistentRuntime {
        try await runPersistentOperation {
            try enrollRecoverySynchronously(at: path, policy: policy, signature: signature, trust: trust,
                enrollmentSignature: enrollmentSignature, maxLiveKeys: maxLiveKeys, maxInFlight: maxInFlight)
        }
    }

    static func enrollRecoverySynchronously(at path: String, policy: [UInt8], signature: [UInt8],
        trust: QPeriaptPolicyRecoveryTrust, enrollmentSignature: [UInt8],
        maxLiveKeys: UInt32 = 32, maxInFlight: UInt32 = 4) throws -> QPeriaptPersistentRuntime {
        try constructRecoverable(at: path, policy: policy, signature: signature, trust: trust,
            enrollment: enrollmentSignature, authorization: [], mode: .enroll,
            maxLiveKeys: maxLiveKeys, maxInFlight: maxInFlight).0
    }

    /// Reconcile the SAME original authorization/target after an uncertain call
    /// or cancellation. A later authorized state is retained, never rolled back.
    public static func openRecovering(at path: String, policy: [UInt8], signature: [UInt8],
        trust: QPeriaptPolicyRecoveryTrust, authorization: QPeriaptPolicyRecoveryAuthorization,
        maxLiveKeys: UInt32 = 32, maxInFlight: UInt32 = 4) async throws -> QPeriaptPolicyRecoveryReopen {
        try await runPersistentOperation({
            let (owner, raw) = try constructRecoverable(at: path, policy: policy, signature: signature,
                trust: trust, enrollment: [], authorization: authorization.encoded, mode: .recovering,
                maxLiveKeys: maxLiveKeys, maxInFlight: maxInFlight)
            guard let disposition = QPeriaptPolicyRecoveryDisposition(rawValue: raw) else {
                try owner.runtime.owned.close()
                throw QPeriaptSDKError(operation: "recovery open disposition", code: Q_PERIAPT_ERR_INTERNAL)
            }
            return QPeriaptPolicyRecoveryReopen(runtime: owner, disposition: disposition)
        }, discard: { try await $0.runtime.close() })
    }

    /// Prepare a public, immutable statement without changing persistent state.
    /// Generate one nonzero operation ID and retain it before requesting signatures.
    public func prepareAuthorityRecovery(operation: [UInt8], policy: [UInt8], signature: [UInt8],
        incomingRoot: [UInt8]) async throws -> QPeriaptPolicyRecoveryRequest {
        try await runPersistentOperation({
            try self.runtime.owned.use { handle in
                var request = [UInt8](repeating: 0, count: Int(Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN))
                let status = operation.withInput { operationInput in
                    policy.withInput { policyInput in
                        signature.withInput { signatureInput in
                            incomingRoot.withInput { rootInput in
                                request.withOutput { q_periapt_sdk_runtime_prepare_recovery(handle, operationInput,
                                    policyInput, signatureInput, rootInput, $0) }
                            }
                        }
                    }
                }
                try check(status, "prepare authority recovery")
                return try QPeriaptPolicyRecoveryRequest(encoded: request)
            }
        }, discard: { _ in /* Public statement owns no runtime and performed no mutation. */ })
    }

    /// Verify both roles, persist the transition and transfer ownership only when
    /// newly applied. Cancellation can follow a commit: recover the original intent.
    public func recoverAuthority(_ authorization: QPeriaptPolicyRecoveryAuthorization,
        policy: [UInt8], signature: [UInt8]) async throws -> QPeriaptPolicyRecoveryResult {
        try await runPersistentOperation({
            try self.recoverAuthoritySynchronously(authorization, policy: policy, signature: signature)
        }, discard: { try await $0.discardReturnedOwner() })
    }

    func recoverAuthoritySynchronously(_ authorization: QPeriaptPolicyRecoveryAuthorization,
        policy: [UInt8], signature: [UInt8]) throws -> QPeriaptPolicyRecoveryResult {
        try runtime.owned.use { previous in
            var handle: UInt64 = 0
            var raw: UInt32 = 0
            let status = authorization.encoded.withInput { approval in
                policy.withInput { document in
                    signature.withInput { q_periapt_sdk_runtime_recover_authority(previous, approval, document, $0, &handle, &raw) }
                }
            }
            try check(status, "recover policy authority")
            if raw == QPeriaptPolicyRecoveryDisposition.applied.rawValue, handle != 0, handle != previous {
                return .applied(QPeriaptPersistentRuntime(handle: handle))
            }
            if handle == 0 {
                switch QPeriaptPolicyRecoveryDisposition(rawValue: raw) {
                case .alreadyApplied: return .alreadyApplied
                case .appliedThenAdvanced: return .appliedThenAdvanced
                default: break
                }
            }
            // A malformed native outcome must not leak returned ownership.
            if handle != 0 { try OwnedHandle(handle).close() }
            throw QPeriaptSDKError(operation: "recovery ownership disposition", code: Q_PERIAPT_ERR_INTERNAL)
        }
    }

    private enum RecoveryOpenMode { case provision, enroll, configured, recovering }
    private static func constructRecoverable(at path: String, policy: [UInt8], signature: [UInt8],
        trust: QPeriaptPolicyRecoveryTrust, enrollment: [UInt8], authorization: [UInt8], mode: RecoveryOpenMode,
        maxLiveKeys: UInt32, maxInFlight: UInt32) throws -> (QPeriaptPersistentRuntime, UInt32) {
        guard q_periapt_abi_version() == 2,
              q_periapt_sdk_extension_version() == Q_PERIAPT_SDK_EXTENSION_VERSION,
              let size = UInt32(exactly: MemoryLayout<QPeriaptRecoverableStoreOptions>.size) else {
            throw QPeriaptSDKError(operation: "recoverable SDK contract", code: Q_PERIAPT_ERR_LIMITS)
        }
        var handle: UInt64 = 0
        var disposition: UInt32 = 0
        let status = Array(path.utf8).withInput { pathInput in
            policy.withInput { policyInput in
                signature.withInput { signatureInput in
                    trust.scope.withInput { scope in
                        trust.initialRoot.withInput { initial in
                            trust.recoveryRoot.withInput { recovery in
                                enrollment.withInput { enrollmentInput in
                                    authorization.withInput { approval in
                                        var options = QPeriaptRecoverableStoreOptions(struct_size: size,
                                            extension_version: UInt32(Q_PERIAPT_SDK_EXTENSION_VERSION), path: pathInput,
                                            policy: policyInput, signature: signatureInput, scope: scope, initial_root: initial,
                                            recovery_root: recovery, enrollment_signature: enrollmentInput,
                                            max_live_keys: maxLiveKeys, max_in_flight: maxInFlight)
                                        switch mode {
                                        case .provision: return q_periapt_sdk_runtime_provision_recoverable_store(&options, &handle)
                                        case .enroll: return q_periapt_sdk_runtime_enroll_recovery_store(&options, &handle)
                                        case .configured: return q_periapt_sdk_runtime_open_recoverable_store(&options, &handle)
                                        case .recovering: return q_periapt_sdk_runtime_open_recovering_store(&options, approval, &handle, &disposition)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        try check(status, "open recoverable policy store")
        guard handle != 0 else {
            throw QPeriaptSDKError(operation: "recovery runtime ownership", code: Q_PERIAPT_ERR_INTERNAL)
        }
        return (QPeriaptPersistentRuntime(handle: handle), disposition)
    }
}
