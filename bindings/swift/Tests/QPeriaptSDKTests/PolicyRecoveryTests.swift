// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import XCTest
@testable import QPeriaptSDK

private enum RecoveryFixtureError: Error { case shape, missingField }
private struct RecoveryFixture: Sendable {
    let fields: [String: [UInt8]]
    func bytes(_ name: String) throws -> [UInt8] {
        guard let value = fields[name] else { throw RecoveryFixtureError.missingField }
        return value
    }
    func trust() throws -> QPeriaptPolicyRecoveryTrust {
        try QPeriaptPolicyRecoveryTrust(scope: bytes("scope"), initialRoot: bytes("initial_root"),
                                       recoveryRoot: bytes("recovery_root"))
    }
    func authorization() throws -> QPeriaptPolicyRecoveryAuthorization {
        try QPeriaptPolicyRecoveryAuthorization(encoded: bytes("authorization"))
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
extension QPeriaptSDKTests {
    private func recoveryFixture() throws -> RecoveryFixture {
        let file = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("sdk-policy-recovery-vectors.json")
        let fields = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: file))
        guard fields.count == 19 else { throw RecoveryFixtureError.shape }
        return try RecoveryFixture(fields: fields.mapValues { try hex($0) })
    }
    private func recoverableStore(_ fixture: RecoveryFixture, at path: String) async throws -> QPeriaptPersistentRuntime {
        try await .provisionRecoverable(at: path, policy: fixture.bytes("initial_policy"),
            signature: fixture.bytes("initial_signature"), trust: fixture.trust(),
            enrollmentSignature: fixture.bytes("enrollment_signature"))
    }

    func testRecoveryStatementGrammarAndIndependentRoleMessages() throws {
        let fixture = try recoveryFixture()
        let trust = try fixture.trust()
        XCTAssertEqual(trust.enrollmentMessage, try fixture.bytes("enrollment_message"))
        let request = try QPeriaptPolicyRecoveryRequest(encoded: fixture.bytes("request"))
        XCTAssertEqual(request.operation, try fixture.bytes("operation"))
        XCTAssertEqual(request.incomingRoot, try fixture.bytes("incoming_root"))
        XCTAssertEqual(request.generation, 1)
        XCTAssertEqual(request.states.previous.prefix(4), [255,255,255,255])
        XCTAssertEqual(request.states.next.prefix(4), [0,0,0,1])
        XCTAssertEqual(request.approvalMessage, try fixture.bytes("approval_message"))
        XCTAssertEqual(request.possessionMessage, try fixture.bytes("possession_message"))
        XCTAssertNotEqual(request.approvalMessage, request.possessionMessage)
        let authorization = try QPeriaptPolicyRecoveryAuthorization(request: request,
            approvalSignature: fixture.bytes("approval_signature"), possessionSignature: fixture.bytes("possession_signature"))
        XCTAssertEqual(authorization.encoded, try fixture.bytes("authorization"))
        XCTAssertThrowsError(try QPeriaptPolicyRecoveryRequest(encoded: Array(request.encoded.dropLast())))
        XCTAssertThrowsError(try QPeriaptPolicyRecoveryAuthorization(encoded: authorization.encoded + [0]))
        XCTAssertThrowsError(try QPeriaptPolicyRecoveryTrust(scope: [UInt8](repeating: 0, count: 32),
            initialRoot: trust.initialRoot, recoveryRoot: trust.recoveryRoot))
        XCTAssertThrowsError(try QPeriaptPolicyRecoveryTrust(scope: trust.scope,
            initialRoot: trust.initialRoot, recoveryRoot: trust.initialRoot))
    }

    func testPersistentRecoveryExhaustionAndIdempotentOwnerPreservation() async throws {
        let fixture = try recoveryFixture()
        let folder = try storeDirectory(); defer { removeStoreDirectory(folder) }
        let path = folder.appendingPathComponent("policy.redb").path
        let original = try await recoverableStore(fixture, at: path)
        XCTAssertEqual(try original.runtime.trustedState().prefix(4), [255,255,255,255])
        let oldKey = try original.runtime.generateKey()
        let oldPublic = try oldKey.publicKey().bytes
        let request = try await original.prepareAuthorityRecovery(operation: fixture.bytes("operation"),
            policy: fixture.bytes("next_policy"), signature: fixture.bytes("next_signature"),
            incomingRoot: fixture.bytes("incoming_root"))
        XCTAssertEqual(request.encoded, try fixture.bytes("request"))
        let swapped = try QPeriaptPolicyRecoveryAuthorization(request: request,
            approvalSignature: fixture.bytes("possession_signature"), possessionSignature: fixture.bytes("approval_signature"))
        do {
            let unexpected = try await original.recoverAuthority(swapped, policy: fixture.bytes("next_policy"), signature: fixture.bytes("next_signature"))
            try await unexpected.discardReturnedOwner()
            XCTFail("swapped signer roles were accepted")
        } catch let error as QPeriaptSDKError { XCTAssertEqual(error.code, -3) }
        XCTAssertEqual(try oldKey.publicKey().bytes, oldPublic)
        let authorization = try fixture.authorization()
        let applied = try await original.recoverAuthority(authorization, policy: fixture.bytes("next_policy"), signature: fixture.bytes("next_signature"))
        guard case let .applied(disabled) = applied else { XCTFail("expected newly applied recovery"); return }
        XCTAssertThrowsError(try oldKey.publicKey())
        XCTAssertFalse(try disabled.runtime.isEnabled())
        let repeated = try await disabled.recoverAuthority(authorization, policy: fixture.bytes("next_policy"), signature: fixture.bytes("next_signature"))
        guard case .alreadyApplied = repeated else {
            try await repeated.discardReturnedOwner(); XCTFail("expected idempotent replay"); return
        }
        let current = try await disabled.update(policy: fixture.bytes("current_policy"), signature: fixture.bytes("current_signature"))
        let currentKey = try current.runtime.generateKey()
        let currentPublic = try currentKey.publicKey().bytes
        let advanced = try await current.recoverAuthority(authorization, policy: fixture.bytes("next_policy"), signature: fixture.bytes("next_signature"))
        guard case .appliedThenAdvanced = advanced else {
            try await advanced.discardReturnedOwner(); XCTFail("expected advanced original receipt"); return
        }
        XCTAssertEqual(try currentKey.publicKey().bytes, currentPublic)
        try await current.close()
        let reopened = try await QPeriaptPersistentRuntime.openRecovering(at: path,
            policy: fixture.bytes("next_policy"), signature: fixture.bytes("next_signature"),
            trust: fixture.trust(), authorization: authorization)
        XCTAssertEqual(reopened.disposition, .appliedThenAdvanced)
        XCTAssertEqual(try reopened.runtime.runtime.trustedState().prefix(4), [0,0,0,2])
        try await original.close(); try await disabled.close()
        XCTAssertTrue(try reopened.runtime.runtime.isEnabled())
        try await reopened.runtime.close()
        let ordinary = try await QPeriaptPersistentRuntime.openRecoverable(at: path,
            policy: fixture.bytes("current_policy"), signature: fixture.bytes("current_signature"), trust: fixture.trust())
        XCTAssertTrue(try ordinary.runtime.isEnabled())
        try await ordinary.close()
    }

    func testRecoveryCancellationClosesOnlyNewlyReturnedOwnership() async throws {
        let fixture = try recoveryFixture()
        let folder = try storeDirectory(); defer { removeStoreDirectory(folder) }
        let path = folder.appendingPathComponent("policy.redb").path
        let original = try await recoverableStore(fixture, at: path)
        let authorization = try fixture.authorization()
        let policy = try fixture.bytes("next_policy")
        let signature = try fixture.bytes("next_signature")
        // First cancel after a real newly committed recovery, then cancel a
        // later replay. Only the first result owns a successor to dispose.
        for replay in [false, true] {
            let owner: QPeriaptPersistentRuntime
            if replay {
                let reopened = try await QPeriaptPersistentRuntime.openRecovering(at: path,
                    policy: policy, signature: signature, trust: fixture.trust(), authorization: authorization)
                XCTAssertEqual(reopened.disposition, .alreadyApplied)
                owner = try await reopened.runtime.update(policy: fixture.bytes("current_policy"), signature: fixture.bytes("current_signature"))
            } else { owner = original }
            let liveKey = replay ? try owner.runtime.generateKey() : nil
            let livePublic = try liveKey?.publicKey().bytes
            let committed = DispatchSemaphore(value: 0)
            let resume = DispatchSemaphore(value: 0)
            let task = Task {
                try await runPersistentOperation({
                    let result = try owner.recoverAuthoritySynchronously(authorization, policy: policy, signature: signature)
                    committed.signal()
                    guard resume.wait(timeout: .now() + 10) == .success else {
                        try result.discardSynchronouslyForTest()
                        throw QPeriaptSDKError(operation: "test release deadline", code: -15)
                    }
                    return result
                }, discard: { try await $0.discardReturnedOwner() })
            }
            let ready = await withCheckedContinuation { continuation in
                DispatchQueue.global().async { continuation.resume(returning: committed.wait(timeout: .now() + 10) == .success) }
            }
            XCTAssertTrue(ready)
            task.cancel(); resume.signal()
            do {
                let unexpected = try await task.value
                try await unexpected.discardReturnedOwner()
                XCTFail("cancelled recovery returned a result")
            } catch is CancellationError { /* Persistence is not rolled back by cancellation. */ }
            if replay {
                XCTAssertTrue(try owner.runtime.isEnabled())
                XCTAssertEqual(try liveKey?.publicKey().bytes, livePublic)
                try await owner.close()
            } else { XCTAssertThrowsError(try original.runtime.isEnabled()) }
        }
        let recovered = try await QPeriaptPersistentRuntime.openRecovering(at: path,
            policy: policy, signature: signature, trust: fixture.trust(), authorization: authorization)
        XCTAssertEqual(recovered.disposition, .appliedThenAdvanced)
        try await recovered.runtime.close()
        try await original.close()
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
private extension QPeriaptPolicyRecoveryResult {
    func discardSynchronouslyForTest() throws {
        if case let .applied(owner) = self { try owner.runtime.close() }
    }
}
