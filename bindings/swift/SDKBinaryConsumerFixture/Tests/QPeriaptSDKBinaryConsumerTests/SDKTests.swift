// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import Darwin
import XCTest
import QPeriaptHybrid
import QPeriaptSDK

private struct Fixture: Decodable {
    let policy_toml: String
    let signature: String
    let verification_key: String
}
private enum FixtureError: Error { case resource, hex, path }

final class QPeriaptSDKBinaryConsumerTests: XCTestCase {
    private func fixture(_ name: String = "signed-policy-vectors.json") throws -> Fixture {
        guard let url = Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Resources")
        else { throw FixtureError.resource }
        return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    }
    private func hex(_ text: String) throws -> [UInt8] {
        let bytes = Array(text.utf8)
        guard bytes.count.isMultiple(of: 2) else { throw FixtureError.hex }
        return try stride(from: 0, to: bytes.count, by: 2).map { offset in
            guard let value = UInt8(String(decoding: bytes[offset..<(offset + 2)], as: UTF8.self), radix: 16)
            else { throw FixtureError.hex }
            return value
        }
    }
    private func runtime() throws -> QPeriaptRuntime {
        let f = try fixture()
        return try QPeriaptRuntime(policy: Array(f.policy_toml.utf8), signature: hex(f.signature),
                                   trustRoot: hex(f.verification_key), maxLiveKeys: 2, maxInFlight: 2)
    }

    func testInstalledPolicyAuthorityRecoveryAndAdvancedReplay() async throws {
        try await exerciseInstalledAuthorityRecovery(enrollLegacy: false)
    }

    func testInstalledLegacyEnrollmentAndAuthorityRecovery() async throws {
        try await exerciseInstalledAuthorityRecovery(enrollLegacy: true)
    }

    private func exerciseInstalledAuthorityRecovery(enrollLegacy: Bool) async throws {
        guard let resource = Bundle.module.url(forResource: "sdk-policy-recovery-vectors.json",
            withExtension: nil, subdirectory: "Resources") else { throw FixtureError.resource }
        let fields = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: resource))
        func bytes(_ name: String) throws -> [UInt8] {
            guard let value = fields[name] else { throw FixtureError.resource }
            return try hex(value)
        }
        let trust = try QPeriaptPolicyRecoveryTrust(scope: bytes("scope"),
            initialRoot: bytes("initial_root"), recoveryRoot: bytes("recovery_root"))
        XCTAssertEqual(trust.enrollmentMessage, try bytes("enrollment_message"))
        let authorization = try QPeriaptPolicyRecoveryAuthorization(encoded: bytes("authorization"))
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("qperiapt-root-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer {
            do { try FileManager.default.removeItem(at: folder) }
            catch { XCTFail("owned recovery directory cleanup failed: \(error)") }
        }
        guard let canonical = folder.path.withCString({ realpath($0, nil) }) else { throw FixtureError.path }
        defer { free(canonical) }
        let path = String(cString: canonical) + "/policy.redb"
        let original: QPeriaptPersistentRuntime
        if enrollLegacy {
            let legacy = try await QPeriaptPersistentRuntime.provision(at: path,
                policy: bytes("initial_policy"), signature: bytes("initial_signature"),
                trustRoot: trust.initialRoot)
            let expected = try legacy.runtime.trustedState()
            try await legacy.close()
            let enrolled = try await QPeriaptPersistentRuntime.enrollRecovery(at: path,
                policy: bytes("initial_policy"), signature: bytes("initial_signature"), trust: trust,
                enrollmentSignature: bytes("enrollment_signature"))
            XCTAssertEqual(try enrolled.runtime.trustedState(), expected)
            try await enrolled.close()
            original = try await QPeriaptPersistentRuntime.enrollRecovery(at: path,
                policy: bytes("initial_policy"), signature: bytes("initial_signature"), trust: trust,
                enrollmentSignature: bytes("enrollment_signature"))
            XCTAssertEqual(try original.runtime.trustedState(), expected)
        } else {
            original = try await QPeriaptPersistentRuntime.provisionRecoverable(at: path,
                policy: bytes("initial_policy"), signature: bytes("initial_signature"), trust: trust,
                enrollmentSignature: bytes("enrollment_signature"))
        }
        let oldKey = try original.runtime.generateKey()
        let request = try await original.prepareAuthorityRecovery(operation: bytes("operation"),
            policy: bytes("next_policy"), signature: bytes("next_signature"), incomingRoot: bytes("incoming_root"))
        XCTAssertEqual(request.encoded, try bytes("request"))
        let applied = try await original.recoverAuthority(authorization,
            policy: bytes("next_policy"), signature: bytes("next_signature"))
        guard case let .applied(disabled) = applied else { XCTFail("expected applied owner"); return }
        XCTAssertFalse(try disabled.runtime.isEnabled())
        XCTAssertThrowsError(try oldKey.publicKey())
        let current = try await disabled.update(policy: bytes("current_policy"), signature: bytes("current_signature"))
        let key = try current.runtime.generateKey()
        let publicKey = try key.publicKey().bytes
        let replay = try await current.recoverAuthority(authorization,
            policy: bytes("next_policy"), signature: bytes("next_signature"))
        switch replay {
        case .applied(let unexpected):
            try await unexpected.close(); XCTFail("advanced replay returned a replacement owner")
        case .alreadyApplied: XCTFail("advanced replay lost later policy")
        case .appliedThenAdvanced: break
        }
        XCTAssertEqual(try key.publicKey().bytes, publicKey)
        try await current.close()
        let reopened = try await QPeriaptPersistentRuntime.openRecovering(at: path,
            policy: bytes("next_policy"), signature: bytes("next_signature"), trust: trust, authorization: authorization)
        XCTAssertEqual(reopened.disposition, .appliedThenAdvanced)
        XCTAssertEqual(try reopened.runtime.runtime.trustedState().prefix(4), [0, 0, 0, 2])
        try await reopened.runtime.close()
        try await original.close()
        try await disabled.close()
    }

    func testInstalledMetadataOwnersDerivationAndRevocation() throws {
        XCTAssertEqual(QPeriaptHybrid.runtimeAbiVersion, 2)
        XCTAssertEqual(QPeriaptHybrid.runtimeVersion, "0.2.0")
        let runtime = try runtime()
        let key = try runtime.generateKey()
        let context: [UInt8] = [1, 2, 3]
        let encapsulated = try runtime.encapsulate(to: key.publicKey(), applicationContext: context)
        let recovered = try key.decapsulate(encapsulated.ciphertext, applicationContext: context)
        let a = try encapsulated.secret.deriveKey(purpose: .initiatorTraffic,
            protocolLabel: Array("installed-sdk/v1".utf8), context: context)
        let b = try recovered.deriveKey(purpose: .initiatorTraffic,
            protocolLabel: Array("installed-sdk/v1".utf8), context: context)
        var left = try a.exportForProtocol(), right = try b.exportForProtocol()
        defer { QPeriaptHybrid.wipe(&left); QPeriaptHybrid.wipe(&right) }
        XCTAssertEqual(left, right)
        try runtime.close()
        XCTAssertThrowsError(try key.publicKey())
        XCTAssertThrowsError(try recovered.exportForProtocol())
        XCTAssertThrowsError(try a.exportForProtocol())
        try runtime.close()
    }

    func testInstalledExpertTransferAndSignedPolicyTransition() throws {
        let runtime = try runtime()
        let key = try runtime.generateKey()
        var transfer = try QPeriaptExpert.exportExpanded(key)
        defer { QPeriaptHybrid.wipe(&transfer) }
        let imported = try QPeriaptExpert.importExpanded(transfer, into: runtime)
        XCTAssertEqual(try key.publicKey().bytes, try imported.publicKey().bytes)
        let revoked = try fixture("sdk-policy-revocation-vectors.json")
        let update = try runtime.preparePolicyUpdate(policy: Array(revoked.policy_toml.utf8),
                                                     signature: hex(revoked.signature))
        let states = try update.states()
        XCTAssertEqual(states.previous, try runtime.trustedState())
        XCTAssertEqual(states.next.prefix(4), [0, 0, 0, 3])
        // This consumer test is explicitly in-memory; the next test exercises disk.
        let disabled = try update.activateAfterPersisting()
        XCTAssertFalse(try disabled.isEnabled())
        XCTAssertThrowsError(try disabled.generateKey())
        XCTAssertThrowsError(try imported.publicKey())
        try runtime.close()
        try disabled.close()
    }

    func testInstalledConnectionRejectsInvalidIdentity() throws {
        let runtime = try runtime()
        XCTAssertThrowsError(try QPeriaptClient(runtime: runtime, certificateDER: [], privateKeyDER: [],
            peerCertificateDER: [], applicationContext: [1])) { error in
            XCTAssertEqual((error as? QPeriaptSDKError)?.code, -2)
        }
        try runtime.close()
    }

    func testInstalledPersistentPolicyRestart() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("qperiapt-installed-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer {
            do { try FileManager.default.removeItem(at: url) }
            catch { XCTFail("owned test directory cleanup failed: \(error)") }
        }
        guard let resolved = url.path.withCString({ realpath($0, nil) }) else { throw FixtureError.path }
        defer { free(resolved) }
        let path = String(cString: resolved) + "/policy.redb"
        let initial = try fixture()
        let root = try hex(initial.verification_key)
        let policy = Array(initial.policy_toml.utf8), signature = try hex(initial.signature)
        let store = try await QPeriaptPersistentRuntime.provision(at: path, policy: policy,
                                                               signature: signature, trustRoot: root)
        let key = try store.runtime.generateKey()
        let revoked = try fixture("sdk-policy-revocation-vectors.json")
        let disabled = try await store.update(policy: Array(revoked.policy_toml.utf8), signature: hex(revoked.signature))
        XCTAssertThrowsError(try key.publicKey())
        try await store.close()
        XCTAssertFalse(try disabled.runtime.isEnabled())
        try await disabled.close()
        do {
            let unexpected = try await QPeriaptPersistentRuntime.open(at: path, policy: policy,
                signature: signature, trustRoot: root)
            try await unexpected.close()
            XCTFail("installed SDK accepted rollback after restart")
        } catch let error as QPeriaptSDKError { XCTAssertEqual(error.code, -3) }
        let enabled = try fixture("sdk-policy-update-vectors.json")
        let reopened = try await QPeriaptPersistentRuntime.open(at: path, policy: Array(enabled.policy_toml.utf8),
                                                              signature: hex(enabled.signature), trustRoot: root)
        XCTAssertTrue(try reopened.runtime.isEnabled())
        try await reopened.close()
    }
}
