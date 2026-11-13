// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPeriapt

/// A persistent policy epoch and its immutable SDK runtime. macOS is the
/// currently implemented Swift host; other Apple targets report unsupported.
/// Keep the current owner while using its keys/connections. Explicit close
/// revokes aliases and releases the store lease; child owners retain storage.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
public final class QPeriaptPersistentRuntime: Sendable {
    /// Use for keys and connections. Manual prepare/activate is rejected by the
    /// native owner: persistent policy changes must use update(policy:signature:).
    /// This reference keeps its epoch; a successful update returns a new owner.
    public let runtime: QPeriaptRuntime

    init(handle: UInt64) { runtime = QPeriaptRuntime(owned: OwnedHandle(handle)) }

    /// Explicit first installation; parent directory must already be private.
    /// Never overwrites an existing file or stores private KEM/TLS keys.
    public static func provision(at path: String, policy: [UInt8], signature: [UInt8],
                                 trustRoot: [UInt8], maxLiveKeys: UInt32 = 32,
                                 maxInFlight: UInt32 = 4) async throws -> QPeriaptPersistentRuntime {
        try await runPersistentOperation {
            try construct(at: path, creating: true, policy: policy, signature: signature,
                          trustRoot: trustRoot, maxLiveKeys: maxLiveKeys, maxInFlight: maxInFlight)
        }
    }

    /// Open existing state and reconcile this configured signed policy before
    /// exposing a runtime. Missing/corrupt state never becomes first installation.
    /// Use the latest requested policy after a commit with an uncertain outcome.
    public static func open(at path: String, policy: [UInt8], signature: [UInt8],
                            trustRoot: [UInt8], maxLiveKeys: UInt32 = 32,
                            maxInFlight: UInt32 = 4) async throws -> QPeriaptPersistentRuntime {
        try await runPersistentOperation {
            try construct(at: path, creating: false, policy: policy, signature: signature,
                          trustRoot: trustRoot, maxLiveKeys: maxLiveKeys, maxInFlight: maxInFlight)
        }
    }

    /// Persist a strictly newer policy and return its owner. Success closes this
    /// epoch and its keys/connections. Cancellation can follow a completed commit:
    /// it is never proof of rollback. Recover by opening with the requested policy.
    /// Competing updates to the same epoch have at most one successful successor.
    public func update(policy: [UInt8], signature: [UInt8]) async throws -> QPeriaptPersistentRuntime {
        try await runPersistentOperation { try self.updateSynchronously(policy: policy, signature: signature) }
    }

    /// Complete disposal even if the calling task is cancelled. Disk cleanup
    /// runs on a worker; no owner is freed while a native call still borrows it.
    /// Prefer this over runtime.close(), which is the synchronous C operation.
    public func close() async throws {
        let owner = runtime.owned
        let worker = Task.detached { try owner.close() }
        try await worker.value
    }

    // Synchronous worker operations are internal so ordinary callers do not
    // accidentally perform durable writes on the UI actor.
    static func construct(at path: String, creating: Bool, policy: [UInt8], signature: [UInt8],
                          trustRoot: [UInt8], maxLiveKeys: UInt32 = 32,
                          maxInFlight: UInt32 = 4) throws -> QPeriaptPersistentRuntime {
        guard q_periapt_abi_version() == 2,
              q_periapt_sdk_extension_version() == Q_PERIAPT_SDK_EXTENSION_VERSION,
              let size = UInt32(exactly: MemoryLayout<QPeriaptStoreOptions>.size) else {
            throw QPeriaptSDKError(operation: "persistent SDK contract", code: Q_PERIAPT_ERR_LIMITS)
        }
        var handle: UInt64 = 0
        let status = Array(path.utf8).withInput { pathInput in
            policy.withInput { policyInput in
                signature.withInput { signatureInput in
                    trustRoot.withInput { rootInput in
                        var options = QPeriaptStoreOptions(
                            struct_size: size, extension_version: UInt32(Q_PERIAPT_SDK_EXTENSION_VERSION),
                            path: pathInput, policy: policyInput, signature: signatureInput,
                            trust_root: rootInput, max_live_keys: maxLiveKeys, max_in_flight: maxInFlight)
                        return creating ? q_periapt_sdk_runtime_provision_store(&options, &handle)
                                        : q_periapt_sdk_runtime_open_store(&options, &handle)
                    }
                }
            }
        }
        try check(status, creating ? "provision policy store" : "open configured policy store")
        return QPeriaptPersistentRuntime(handle: handle)
    }

    func updateSynchronously(policy: [UInt8], signature: [UInt8]) throws -> QPeriaptPersistentRuntime {
        try runtime.owned.use { previous in
            var handle: UInt64 = 0
            let status = policy.withInput { document in
                signature.withInput { q_periapt_sdk_runtime_update_store(previous, document, $0, &handle) }
            }
            try check(status, "persist policy update")
            return QPeriaptPersistentRuntime(handle: handle)
        }
    }
}

/// Always await an admitted write, then explicitly close a result discarded by
/// cancellation. Unlike a KEM-only result, that write may already be durable.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
func runPersistentOperation(_ operation: @escaping @Sendable () throws -> QPeriaptPersistentRuntime)
    async throws -> QPeriaptPersistentRuntime {
    try await runPersistentOperation(operation, discard: { try await $0.close() })
}

/// Share admitted-worker cancellation across mutations and public recovery statements.
/// The result-specific disposer closes only ownership returned by that operation.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
func runPersistentOperation<Result: Sendable>(
    _ operation: @escaping @Sendable () throws -> Result,
    discard: @escaping @Sendable (Result) async throws -> Void
) async throws -> Result {
    try Task.checkCancellation()
    let worker = Task.detached {
        try Task.checkCancellation()
        return try operation()
    }
    let result = try await withTaskCancellationHandler {
        try await worker.value
    } onCancel: {
        worker.cancel()
    }
    if Task.isCancelled {
        try await discard(result)
        throw CancellationError()
    }
    return result
}
