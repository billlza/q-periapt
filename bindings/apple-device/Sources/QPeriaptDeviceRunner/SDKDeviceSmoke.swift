// SPDX-License-Identifier: Apache-2.0 OR MIT
#if QPERIAPT_SDK_DEVICE
import CQPeriapt
import Foundation

/// Actual public Swift/ABI 2 owner calls. Policy-update storage in this suite is
/// a test-only in-memory slot; it does not qualify durable rollback protection.
enum SDKDeviceSmoke {
    static let version = "0.2.0-alpha.1"

    private struct Policy: Sendable {
        let bytes: [UInt8]
        let signature: [UInt8]
        let root: [UInt8]

        init(_ name: String, resources: Bundle) throws {
            let vector = try DeviceSmoke.vector(name, resources: resources)
            bytes = Array(try DeviceSmoke.stringField(vector, "policy_toml").utf8)
            signature = try DeviceSmoke.hexField(vector, "signature")
            root = try DeviceSmoke.hexField(vector, "verification_key")
        }

        func runtime(maxKeys: UInt32 = 8, state: [UInt8] = []) throws -> QPeriaptRuntime {
            try QPeriaptRuntime(policy: bytes, signature: signature, trustRoot: root,
                               previousState: state, maxLiveKeys: maxKeys)
        }
    }

    private static func require(_ condition: Bool, _ label: String) throws {
        guard condition else { throw DeviceSmokeError.mismatch(label) }
    }

    private static func expect(_ code: Int32, _ label: String, _ body: () throws -> Void) throws {
        do { try body() }
        catch let error as QPeriaptSDKError where error.code == code { return }
        throw DeviceSmokeError.expectedFailureMissing(label)
    }

    private static func sameSecret(_ left: QPeriaptSecret, _ right: QPeriaptSecret) throws -> Bool {
        var a = try left.exportForProtocol()
        defer { QPeriaptHybrid.wipe(&a) }
        var b = try right.exportForProtocol()
        defer { QPeriaptHybrid.wipe(&b) }
        return a == b
    }

    private static func owners(_ policy: Policy) throws {
        let runtime = try policy.runtime()
        let key = try runtime.generateKey()
        let purposes: [QPeriaptKeyPurpose] = [.initiatorTraffic, .responderTraffic,
                                            .initiatorConfirmation, .responderConfirmation, .exporter]
        for size in [0, 32, 65_536] {
            let context = [UInt8](repeating: 0x51, count: size)
            let enc = try runtime.encapsulate(to: key.publicKey(), applicationContext: context)
            let dec = try key.decapsulate(enc.ciphertext, applicationContext: context)
            try require(try sameSecret(enc.secret, dec), "SDK owner roundtrip")
            for purpose in purposes {
                let a = try enc.secret.deriveKey(purpose: purpose, protocolLabel: Array("device/v1/aes256".utf8), context: context)
                let b = try dec.deriveKey(purpose: purpose, protocolLabel: Array("device/v1/aes256".utf8), context: context)
                var left = try a.exportForProtocol()
                var right = try b.exportForProtocol()
                defer { QPeriaptHybrid.wipe(&left); QPeriaptHybrid.wipe(&right) }
                try require(left == right && left.count == 32, "SDK purpose derivation")
                for other in purposes where other.rawValue > purpose.rawValue {
                    let separated = try enc.secret.deriveKey(purpose: other, protocolLabel: Array("device/v1/aes256".utf8), context: context)
                    var material = try separated.exportForProtocol()
                    defer { QPeriaptHybrid.wipe(&material) }
                    try require(left != material, "SDK purpose separation")
                    try separated.close()
                }
                try a.close(); try b.close()
                try expect(-9, "closed derived key") { _ = try a.exportForProtocol() }
            }
            var ciphertext = enc.ciphertext.bytes
            ciphertext[0] ^= 1
            let rejected = try key.decapsulate(QPeriaptCiphertext(bytes: ciphertext), applicationContext: context)
            try require(try !sameSecret(rejected, enc.secret), "SDK implicit rejection")
            try rejected.close(); try dec.close(); try enc.secret.close()
        }
        try expect(-2, "SDK context bound") {
            let unexpected = try runtime.encapsulate(to: key.publicKey(), applicationContext: [UInt8](repeating: 0, count: 65_537))
            try unexpected.secret.close()
        }
        let pending = try runtime.encapsulate(to: key.publicKey(), applicationContext: [])
        try runtime.close(); try runtime.close()
        try expect(-9, "revoked key") { _ = try key.publicKey() }
        try expect(-9, "revoked secret") { _ = try pending.secret.exportForProtocol() }
        try pending.secret.close(); try key.close()
    }

    private static func updates(_ policy: Policy, resources: Bundle) throws {
        let runtime = try policy.runtime()
        let key = try runtime.generateKey()
        var bytes = try QPeriaptExpert.exportExpanded(key)
        defer { QPeriaptHybrid.wipe(&bytes) }
        try require(bytes.count == 2440, "expanded SDK format")
        let imported = try QPeriaptExpert.importExpanded(bytes, into: runtime)
        try require(try imported.publicKey().bytes == key.publicKey().bytes, "paired expert public key")
        let enc = try runtime.encapsulate(to: imported.publicKey(), applicationContext: [42])
        let dec = try imported.decapsulate(enc.ciphertext, applicationContext: [42])
        try require(try sameSecret(enc.secret, dec), "expert import roundtrip")
        bytes[0] ^= 1
        try expect(-13, "invalid expanded format") {
            let unexpected = try QPeriaptExpert.importExpanded(bytes, into: runtime)
            try unexpected.close()
        }
        let revoked = try Policy("sdk-policy-revocation-vectors", resources: resources)
        let update = try runtime.preparePolicyUpdate(policy: revoked.bytes, signature: revoked.signature)
        let states = try update.states()
        try require(try states.previous == runtime.trustedState(), "update previous state")
        // The fixture has one serialized test host. This slot models its
        // compare/persist obligation without claiming process-restart durability.
        var stored = states.previous
        try require(stored == states.previous, "test state comparison")
        stored = states.next
        let disabled = try update.activateAfterPersisting()
        try require(try !disabled.isEnabled(), "signed revocation")
        try expect(-3, "disabled key generation") { try disabled.generateKey().close() }
        try expect(-9, "old key generation revoked") { _ = try key.publicKey() }
        try expect(-9, "old secret generation revoked") { _ = try dec.exportForProtocol() }
        try update.close(); try runtime.close()
        try require(try !disabled.isEnabled(), "stale close cannot revoke successor")
        let recovered = try revoked.runtime(state: stored)
        let enabled = try Policy("sdk-policy-update-vectors", resources: resources)
        let nextUpdate = try recovered.preparePolicyUpdate(policy: enabled.bytes, signature: enabled.signature)
        stored = try nextUpdate.states().next
        let next = try nextUpdate.activateAfterPersisting()
        try require(try next.isEnabled() && next.trustedState() == stored, "newer signed policy re-enables")
        try next.generateKey().close()
        try next.close(); try nextUpdate.close(); try recovered.close(); try disabled.close()
        try imported.close(); try key.close(); try dec.close(); try enc.secret.close()
    }

    private actor StartGate {
        private var continuation: CheckedContinuation<Void, Never>?
        private var released = false
        func wait() async {
            if released { return }
            await withCheckedContinuation { continuation = $0 }
        }
        func release() {
            released = true
            continuation?.resume()
            continuation = nil
        }
    }

    private static func resources(_ policy: Policy) async throws {
        let runtime = try policy.runtime(maxKeys: 1)
        let key = try runtime.generateKey()
        try expect(-10, "SDK key quota") { try runtime.generateKey().close() }
        try key.close()
        let gate = StartGate()
        let task = Task {
            await gate.wait()
            return try await runtime.generateKeyAsync()
        }
        task.cancel()
        await gate.release()
        do {
            let unexpected = try await task.value
            try unexpected.close()
            throw DeviceSmokeError.expectedFailureMissing("pre-cancelled SDK operation")
        } catch is CancellationError {
            // The gate never throws: this rejection must come from the SDK call.
        }
        let replacement = try await runtime.generateKeyAsync()
        let enc = try await runtime.encapsulateAsync(to: replacement.publicKey(), applicationContext: [1, 2, 3])
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<4 {
                group.addTask {
                    let dec = try await replacement.decapsulateAsync(enc.ciphertext, applicationContext: [1, 2, 3])
                    try require(try sameSecret(enc.secret, dec), "concurrent SDK decapsulation")
                    try dec.close()
                }
            }
            try await group.waitForAll()
        }
        try enc.secret.close(); try replacement.close(); try runtime.close()
    }

    static func run(resources bundle: Bundle = .main) async throws -> [String] {
        try require(QPeriaptHybrid.runtimeAbiVersion == 2 &&
                    QPeriaptHybrid.runtimeVersion == version && q_periapt_sdk_extension_version() == 1,
                    "SDK runtime metadata")
        var completed: [String] = []
        try DeviceSmoke.run(expectedRuntimeVersion: version, resources: bundle)
        completed.append("compatibilitySignedPolicy")
        let policy = try Policy("signed-policy-vectors", resources: bundle)
        try owners(policy)
        completed.append("ownedKeysAndPurposeDerivation")
        try updates(policy, resources: bundle)
        completed.append("expertTransferAndPolicyRevocation")
        try await resources(policy)
        completed.append("resourceLimitsAndCancellation")
        return completed
    }
}
#endif
