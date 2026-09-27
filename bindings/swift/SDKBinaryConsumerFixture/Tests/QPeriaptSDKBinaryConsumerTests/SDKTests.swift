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

    func testInstalledMetadataOwnersDerivationAndRevocation() throws {
        XCTAssertEqual(QPeriaptHybrid.runtimeAbiVersion, 2)
        XCTAssertEqual(QPeriaptHybrid.runtimeVersion, "0.2.0-alpha.1")
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
