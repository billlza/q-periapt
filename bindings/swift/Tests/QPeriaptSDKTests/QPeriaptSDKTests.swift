// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import Darwin
import XCTest
@testable import QPeriaptSDK

private struct Fixture: Decodable {
    let policy_toml: String
    let signature: String
    let verification_key: String
}
private enum FixtureError: Error { case invalidHex }

final class QPeriaptSDKTests: XCTestCase {
    func hex(_ value: String) throws -> [UInt8] {
        guard value.count.isMultiple(of: 2) else { throw FixtureError.invalidHex }
        var bytes: [UInt8] = []
        var cursor = value.startIndex
        while cursor < value.endIndex {
            let next = value.index(cursor, offsetBy: 2)
            guard let byte = UInt8(value[cursor..<next], radix: 16) else { throw FixtureError.invalidHex }
            bytes.append(byte); cursor = next
        }
        return bytes
    }
    private func fixture(_ name: String = "signed-policy-vectors.json") throws -> Fixture {
        let file = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent(name)
        return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: file))
    }

    func storeDirectory() throws -> URL {
        let folder = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("qperiapt-store-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        // Foundation preserves the /var system alias even after
        // resolvingSymlinksInPath(). Resolve this newly created test directory
        // explicitly; the product API continues to reject symlink components.
        guard let canonical = folder.path.withCString({ realpath($0, nil) }) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { free(canonical) }
        return URL(fileURLWithPath: String(cString: canonical), isDirectory: true)
    }

    func removeStoreDirectory(_ folder: URL) {
        do { try FileManager.default.removeItem(at: folder) }
        catch { XCTFail("temporary store cleanup failed: \(error)") }
    }

    @available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    func testPersistentRuntimeReopensRevocationAndRejectsManualActivation() async throws {
        let folder = try storeDirectory()
        defer { removeStoreDirectory(folder) }
        let path = folder.appendingPathComponent("policy.redb").path
        let initial = try fixture()
        let revoked = try fixture("sdk-policy-revocation-vectors.json")
        let enabled = try fixture("sdk-policy-update-vectors.json")
        let store = try await QPeriaptPersistentRuntime.provision(at: path, policy: Array(initial.policy_toml.utf8),
            signature: hex(initial.signature), trustRoot: hex(initial.verification_key))
        let key = try store.runtime.generateKey()
        do {
            let unexpected = try await QPeriaptPersistentRuntime.open(at: path, policy: Array(initial.policy_toml.utf8),
                signature: hex(initial.signature), trustRoot: hex(initial.verification_key))
            try await unexpected.close()
            XCTFail("second owner acquired the same store")
        } catch let error as QPeriaptSDKError { XCTAssertEqual(error.code, -20) }
        XCTAssertThrowsError(try store.runtime.preparePolicyUpdate(policy: Array(revoked.policy_toml.utf8),
            signature: hex(revoked.signature))) { error in XCTAssertEqual((error as? QPeriaptSDKError)?.code, -24) }
        let disabled = try await store.update(policy: Array(revoked.policy_toml.utf8), signature: hex(revoked.signature))
        XCTAssertFalse(try disabled.runtime.isEnabled())
        XCTAssertThrowsError(try key.publicKey()) { error in XCTAssertEqual((error as? QPeriaptSDKError)?.code, -9) }
        try key.close()
        try await store.close() // stale alias cannot close the successor/store lease
        XCTAssertFalse(try disabled.runtime.isEnabled())
        try await disabled.close()
        do {
            let unexpected = try await QPeriaptPersistentRuntime.open(at: path, policy: Array(initial.policy_toml.utf8),
                signature: hex(initial.signature), trustRoot: hex(initial.verification_key))
            try await unexpected.close()
            XCTFail("rollback configuration opened a persisted revocation")
        } catch let error as QPeriaptSDKError { XCTAssertEqual(error.code, -3) }
        let recovered = try await QPeriaptPersistentRuntime.open(at: path, policy: Array(enabled.policy_toml.utf8),
            signature: hex(enabled.signature), trustRoot: hex(enabled.verification_key))
        XCTAssertTrue(try recovered.runtime.isEnabled())
        XCTAssertEqual(try recovered.runtime.trustedState().prefix(4), [0, 0, 0, 4])
        try await recovered.close()
    }

    @available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    func testCancelledCommittedUpdateClosesUndeliveredOwnerAndRecoversNewState() async throws {
        let folder = try storeDirectory()
        defer { removeStoreDirectory(folder) }
        let path = folder.appendingPathComponent("policy.redb").path
        let initial = try fixture()
        let revoked = try fixture("sdk-policy-revocation-vectors.json")
        let policy = Array(revoked.policy_toml.utf8)
        let signature = try hex(revoked.signature)
        let root = try hex(initial.verification_key)
        let store = try await QPeriaptPersistentRuntime.provision(at: path, policy: Array(initial.policy_toml.utf8),
            signature: hex(initial.signature), trustRoot: root)
        let committed = DispatchSemaphore(value: 0)
        let resume = DispatchSemaphore(value: 0)
        let task = Task {
            try await runPersistentOperation {
                let result = try store.updateSynchronously(policy: policy, signature: signature)
                committed.signal()
                guard resume.wait(timeout: .now() + 5) == .success else {
                    throw QPeriaptSDKError(operation: "test release deadline", code: -15)
                }
                return result
            }
        }
        let ready = await withCheckedContinuation { continuation in
            DispatchQueue.global().async { continuation.resume(returning: committed.wait(timeout: .now() + 5) == .success) }
        }
        XCTAssertTrue(ready)
        task.cancel(); resume.signal()
        do {
            let unexpected = try await task.value
            try await unexpected.close()
            XCTFail("cancelled update returned its new owner")
        } catch is CancellationError {
            // Cancellation follows a real completed disk commit; it cannot undo it.
        }
        XCTAssertThrowsError(try store.runtime.isEnabled())
        let recovered = try await QPeriaptPersistentRuntime.open(at: path, policy: policy, signature: signature, trustRoot: root)
        XCTAssertFalse(try recovered.runtime.isEnabled())
        XCTAssertEqual(try recovered.runtime.trustedState().prefix(4), [0, 0, 0, 3])
        try await store.close()
        XCTAssertFalse(try recovered.runtime.isEnabled())
        try await recovered.close()
    }

    @available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    func testPersistentChildRetainsStoreLeaseUntilFinalOwnerDisposal() async throws {
        let folder = try storeDirectory()
        defer { removeStoreDirectory(folder) }
        let path = folder.appendingPathComponent("policy.redb").path
        let initial = try fixture()
        let policy = Array(initial.policy_toml.utf8)
        let signature = try hex(initial.signature)
        let root = try hex(initial.verification_key)
        var store: QPeriaptPersistentRuntime? = try await .provision(at: path, policy: policy, signature: signature, trustRoot: root)
        var key: QPeriaptKey? = try XCTUnwrap(store).runtime.generateKey()
        store = nil
        XCTAssertEqual(try XCTUnwrap(key).publicKey().bytes.count, 1216)
        do {
            let unexpected = try await QPeriaptPersistentRuntime.open(at: path, policy: policy, signature: signature, trustRoot: root)
            try await unexpected.close()
            XCTFail("live child lost its persistent parent lease")
        } catch let error as QPeriaptSDKError { XCTAssertEqual(error.code, -20) }
        try XCTUnwrap(key).close(); key = nil
        let reopened = try await QPeriaptPersistentRuntime.open(at: path, policy: policy, signature: signature, trustRoot: root)
        XCTAssertTrue(try reopened.runtime.isEnabled())
        try await reopened.close()
    }

    func testExpertTransferAndPolicyRevocationRecovery() throws {
        let runtime = try runtime()
        XCTAssertTrue(try runtime.isEnabled())
        let key = try runtime.generateKey()
        var exported = try QPeriaptExpert.exportExpanded(key)
        defer { for index in exported.indices { exported[index] = 0 } }
        XCTAssertEqual(exported.count, 2440)
        let imported = try QPeriaptExpert.importExpanded(exported, into: runtime)
        XCTAssertEqual(try imported.publicKey().bytes, try key.publicKey().bytes)
        let enc = try runtime.encapsulate(to: imported.publicKey(), applicationContext: [42])
        let dec = try imported.decapsulate(enc.ciphertext, applicationContext: [42])
        XCTAssertEqual(try enc.secret.exportForProtocol(), try dec.exportForProtocol())
        exported[0] ^= 1
        XCTAssertThrowsError(try QPeriaptExpert.importExpanded(exported, into: runtime)) { error in
            XCTAssertEqual((error as? QPeriaptSDKError)?.code, -13)
        }
        let revoked = try fixture("sdk-policy-revocation-vectors.json")
        let update = try runtime.preparePolicyUpdate(policy: Array(revoked.policy_toml.utf8), signature: hex(revoked.signature))
        let states = try update.states()
        XCTAssertEqual(states.previous, try runtime.trustedState())
        XCTAssertEqual(states.next.prefix(4), [0, 0, 0, 3])
        // Test-only in-memory compare/persist; no durable-store claim.
        var stored = states.previous
        XCTAssertEqual(stored, states.previous); stored = states.next
        let disabled = try update.activateAfterPersisting()
        XCTAssertFalse(try disabled.isEnabled())
        XCTAssertThrowsError(try disabled.generateKey()) { error in
            XCTAssertEqual((error as? QPeriaptSDKError)?.code, -3)
        }
        XCTAssertThrowsError(try key.publicKey())
        XCTAssertThrowsError(try dec.exportForProtocol())
        XCTAssertThrowsError(try update.activateAfterPersisting())
        try update.close(); try runtime.close()
        XCTAssertFalse(try disabled.isEnabled()) // stale wrappers cannot close the successor
        let recovered = try QPeriaptRuntime(policy: Array(revoked.policy_toml.utf8), signature: hex(revoked.signature),
            trustRoot: hex(revoked.verification_key), previousState: stored)
        XCTAssertFalse(try recovered.isEnabled())
        let allowed = try fixture("sdk-policy-update-vectors.json")
        let enable = try recovered.preparePolicyUpdate(policy: Array(allowed.policy_toml.utf8), signature: hex(allowed.signature))
        stored = try enable.states().next
        let next = try enable.activateAfterPersisting()
        XCTAssertEqual(try next.trustedState(), stored)
        XCTAssertTrue(try next.isEnabled())
        try next.generateKey().close()
        try next.close(); try enable.close(); try recovered.close(); try disabled.close()
        try key.close(); try imported.close(); try dec.close(); try enc.secret.close()
    }
    private func runtime(maxKeys: UInt32 = 32) throws -> QPeriaptRuntime {
        let f = try fixture()
        return try QPeriaptRuntime(policy: Array(f.policy_toml.utf8), signature: hex(f.signature),
                                  trustRoot: hex(f.verification_key), maxLiveKeys: maxKeys)
    }

    func testActualNativeRoundtripImplicitRejectionAndClose() throws {
        let runtime = try runtime()
        let key = try runtime.generateKey()
        for count in [0, 32, 65_536] {
            let context = [UInt8](repeating: 0x51, count: count)
            let result = try runtime.encapsulate(to: key.publicKey(), applicationContext: context)
            let recovered = try key.decapsulate(result.ciphertext, applicationContext: context)
            XCTAssertEqual(try result.secret.exportForProtocol(), try recovered.exportForProtocol())
            var previous: [UInt8]? = nil
            for purpose in [QPeriaptKeyPurpose.initiatorTraffic, .responderTraffic,
                            .initiatorConfirmation, .responderConfirmation, .exporter] {
                let left = try result.secret.deriveKey(purpose: purpose, protocolLabel: Array("app/v1/aes256".utf8), context: context)
                let right = try recovered.deriveKey(purpose: purpose, protocolLabel: Array("app/v1/aes256".utf8), context: context)
                let bytes = try left.exportForProtocol()
                XCTAssertEqual(bytes, try right.exportForProtocol())
                XCTAssertNotEqual(bytes, previous)
                previous = bytes
                try left.close(); try right.close()
                XCTAssertThrowsError(try left.exportForProtocol())
            }
            XCTAssertThrowsError(try result.secret.deriveKey(purpose: .exporter, protocolLabel: [], context: [])) { error in
                XCTAssertEqual((error as? QPeriaptSDKError)?.code, -2)
            }
            XCTAssertThrowsError(try result.secret.deriveKey(purpose: .exporter, protocolLabel: [0], context: [])) { error in
                XCTAssertEqual((error as? QPeriaptSDKError)?.code, -12)
            }
            var changed = result.ciphertext.bytes
            changed[0] ^= 1
            let rejected = try key.decapsulate(QPeriaptCiphertext(bytes: changed), applicationContext: context)
            XCTAssertNotEqual(try rejected.exportForProtocol(), try result.secret.exportForProtocol())
            try recovered.close(); try rejected.close(); try result.secret.close()
        }
        let pending = try runtime.encapsulate(to: key.publicKey(), applicationContext: [])
        let derived = try pending.secret.deriveKey(purpose: .exporter, protocolLabel: Array("app/v1".utf8), context: [])
        try runtime.close(); try runtime.close()
        XCTAssertThrowsError(try key.publicKey()) { error in
            XCTAssertEqual((error as? QPeriaptSDKError)?.code, -9)
        }
        XCTAssertThrowsError(try pending.secret.exportForProtocol()) { error in
            XCTAssertEqual((error as? QPeriaptSDKError)?.code, -9)
        }
        XCTAssertThrowsError(try derived.exportForProtocol()) { error in
            XCTAssertEqual((error as? QPeriaptSDKError)?.code, -9)
        }
        try derived.close()
        try key.close(); try pending.secret.close()
    }

    func testPolicyRollbackTamperingBudgetsAndInvalidPublicInputs() throws {
        let runtime = try runtime(maxKeys: 1)
        let state = try runtime.trustedState()
        XCTAssertEqual(state.count, 36)
        let f = try fixture()
        XCTAssertThrowsError(try QPeriaptRuntime(policy: Array(f.policy_toml.utf8),
            signature: hex(f.signature), trustRoot: hex(f.verification_key), previousState: [0, 0, 0, 2])) { error in
                XCTAssertEqual((error as? QPeriaptSDKError)?.code, -2)
        }
        var future = state; future[3] = 3
        XCTAssertThrowsError(try QPeriaptRuntime(policy: Array(f.policy_toml.utf8),
            signature: hex(f.signature), trustRoot: hex(f.verification_key), previousState: future)) { error in
                XCTAssertEqual((error as? QPeriaptSDKError)?.code, -3)
        }
        var signature = try hex(f.signature); signature[0] ^= 1
        XCTAssertThrowsError(try QPeriaptRuntime(policy: Array(f.policy_toml.utf8),
            signature: signature, trustRoot: hex(f.verification_key))) { error in
                XCTAssertEqual((error as? QPeriaptSDKError)?.code, -3)
        }
        let key = try runtime.generateKey()
        XCTAssertThrowsError(try runtime.generateKey()) { error in
            XCTAssertEqual((error as? QPeriaptSDKError)?.code, -10)
        }
        XCTAssertThrowsError(try runtime.encapsulate(to: key.publicKey(),
            applicationContext: [UInt8](repeating: 0, count: 65_537))) { error in
                XCTAssertEqual((error as? QPeriaptSDKError)?.code, -2)
        }
        let invalid = try QPeriaptCiphertext(bytes: [UInt8](repeating: 0, count: 1120))
        XCTAssertThrowsError(try key.decapsulate(invalid, applicationContext: [])) { error in
            XCTAssertEqual((error as? QPeriaptSDKError)?.code, -6)
        }
        try key.close()
        let next = try runtime.generateKey()
        XCTAssertThrowsError(try key.publicKey())
        try next.close(); try runtime.close()
    }

    func testChildRetainsNativeParentUntilExplicitClose() throws {
        var runtime: QPeriaptRuntime? = try self.runtime(maxKeys: 1)
        let key = try XCTUnwrap(runtime).generateKey()
        runtime = nil
        XCTAssertEqual(try key.publicKey().bytes.count, 1216)
        try key.close()
        XCTAssertThrowsError(try key.publicKey())
    }

    @available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    func testConcurrentOwnedCallsAndAsynchronousRoundtrip() async throws {
        let runtime = try runtime()
        let key = try await runtime.generateKeyAsync()
        let result = try await runtime.encapsulateAsync(to: key.publicKey(), applicationContext: [1, 2, 3])
        let expected = try result.secret.exportForProtocol()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<4 {
                group.addTask {
                    let recovered = try await key.decapsulateAsync(result.ciphertext, applicationContext: [1, 2, 3])
                    XCTAssertEqual(try recovered.exportForProtocol(), expected)
                    try recovered.close()
                }
            }
            try await group.waitForAll()
        }
        try result.secret.close(); try key.close(); try runtime.close()
    }

    @available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    func testCancellationDiscardsCompletedNativeOwnerAndReturnsQuota() async throws {
        let runtime = try runtime(maxKeys: 1)
        let entered = DispatchSemaphore(value: 0)
        let resume = DispatchSemaphore(value: 0)
        let operation = Task {
            try await runOwnedOperation {
                let key = try runtime.generateKey()
                entered.signal()
                guard resume.wait(timeout: .now() + 5) == .success else {
                    throw QPeriaptSDKError(operation: "test resume timeout", code: -5)
                }
                return key
            }
        }
        // Use the blocking primitive outside the async body, while the actual
        // native owner is held by the worker. This tests post-native cancellation
        // and cleanup; C/Rust tests separately cover an active native borrow.
        let started = await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                continuation.resume(returning: entered.wait(timeout: .now() + 5) == .success)
            }
        }
        XCTAssertTrue(started)
        operation.cancel(); resume.signal()
        do {
            let unexpected = try await operation.value
            try unexpected.close()
            XCTFail("cancelled operation returned an owner")
        } catch is CancellationError {
            // Expected explicit cancellation, never an empty successful result.
        }
        let replacement = try runtime.generateKey()
        try replacement.close(); try runtime.close()
    }
}
