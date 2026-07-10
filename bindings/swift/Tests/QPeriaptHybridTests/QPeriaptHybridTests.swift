import XCTest

@testable import QPeriaptHybrid

/// Cross-platform consistency: decapsulate the shared Rust-generated vector and
/// assert the secret matches byte-for-byte. See bindings/shared-test-vectors.json.
final class QPeriaptHybridTests: XCTestCase {
    func hex(_ s: String) -> [UInt8] {
        var out = [UInt8]()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    func sharedVector() throws -> [String: Any] {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("shared-test-vectors.json")
        let data = try Data(contentsOf: url)
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func signedPolicyVector() throws -> [String: Any] {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("signed-policy-vectors.json")
        let data = try Data(contentsOf: url)
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func testRuntimeMetadataMatchesCompiledHeader() throws {
        XCTAssertEqual(QPeriaptHybrid.runtimeAbiVersion, QPeriaptHybrid.abiVersion)
        XCTAssertEqual(QPeriaptHybrid.runtimeVersion, "0.0.1")
        XCTAssertEqual(QPeriaptHybrid.fixedSuiteId, Array("ML-KEM-768+X25519".utf8))
        XCTAssertEqual(QPeriaptHybrid.fixedSuiteIdLen, "ML-KEM-768+X25519".utf8.count)
        XCTAssertEqual(QPeriaptHybrid.statusName(QPeriaptError.policyCode), "ERR_POLICY")
        XCTAssertEqual(QPeriaptHybrid.statusName(12345), "UNKNOWN_STATUS")
    }

    func testSharedVectorDecapsulates() throws {
        // Path to the repo-root shared vector, relative to this source file.
        let v = try sharedVector()

        let secret = try QPeriaptHybrid.decapsulate(
            profile: .contextBound,
            suiteId: hex(v["suite_id"] as! String),
            policyVersion: UInt32(v["policy_version"] as! Int),
            skPq: hex(v["sk_pq"] as! String),
            ctPq: hex(v["ct_pq"] as! String),
            pkPq: hex(v["pk_pq"] as! String),
            skTrad: hex(v["sk_trad"] as! String),
            ctTrad: hex(v["ct_trad"] as! String),
            pkTrad: hex(v["pk_trad"] as! String),
            context: hex(v["context"] as! String))

        XCTAssertEqual(secret, hex(v["secret"] as! String),
                       "Swift decapsulation must match the Rust core byte-for-byte")
    }

    func testSharedVectorEncapsulates() throws {
        let v = try sharedVector()

        let enc = try QPeriaptHybrid.encapsulate(
            profile: .contextBound,
            suiteId: hex(v["suite_id"] as! String),
            policyVersion: UInt32(v["policy_version"] as! Int),
            pkPq: hex(v["pk_pq"] as! String),
            pkTrad: hex(v["pk_trad"] as! String),
            context: hex(v["context"] as! String),
            randPq: hex(v["rand_pq"] as! String),
            randTrad: hex(v["rand_trad"] as! String))

        XCTAssertEqual(enc.ctPq, hex(v["ct_pq"] as! String),
                       "Swift encapsulated ML-KEM ciphertext must match the Rust vector")
        XCTAssertEqual(enc.ctTrad, hex(v["ct_trad"] as! String),
                       "Swift encapsulated X25519 ciphertext must match the Rust vector")
        XCTAssertEqual(enc.secret, hex(v["secret"] as! String),
                       "Swift encapsulated secret must match the Rust vector")
    }

    func testContextBoundRejectsEmptyContext() throws {
        let v = try sharedVector()
        XCTAssertThrowsError(try QPeriaptHybrid.encapsulate(
            profile: .contextBound,
            suiteId: hex(v["suite_id"] as! String),
            policyVersion: UInt32(v["policy_version"] as! Int),
            pkPq: hex(v["pk_pq"] as! String),
            pkTrad: hex(v["pk_trad"] as! String),
            context: [],
            randPq: hex(v["rand_pq"] as! String),
            randTrad: hex(v["rand_trad"] as! String))) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.lengthCode)
        }
    }

    func testCompatXWingSeedKeypairRoundtrip() throws {
        let pq = try QPeriaptHybrid.mlkem768XWingKeypair(
            seed: [UInt8](repeating: 7, count: QPeriaptHybrid.mlkemXWingSeedLen))
        let x = try QPeriaptHybrid.x25519Keypair(
            secret: [UInt8](repeating: 9, count: QPeriaptHybrid.x25519Len))

        let enc = try QPeriaptHybrid.encapsulate(
            profile: .compatXWing,
            suiteId: Array("ML-KEM-768+X25519".utf8),
            policyVersion: 1,
            pkPq: pq.pk,
            pkTrad: x.pk,
            context: [],
            randPq: [UInt8](repeating: 3, count: 32),
            randTrad: [UInt8](repeating: 5, count: 32))

        let dec = try QPeriaptHybrid.decapsulate(
            profile: .compatXWing,
            suiteId: Array("ML-KEM-768+X25519".utf8),
            policyVersion: 1,
            skPq: pq.skSeed,
            ctPq: enc.ctPq,
            pkPq: pq.pk,
            skTrad: x.sk,
            ctTrad: enc.ctTrad,
            pkTrad: x.pk,
            context: [])

        XCTAssertEqual(enc.secret, dec,
                       "Swift CompatXWing seed-dk roundtrip must match")
    }

    /// Cross-platform combiner reference vectors: feed each `input` blob to the C ABI
    /// `combine` and assert the 32-byte key matches (bindings/contextbound-vectors.txt).
    func testCombineReferenceVectors() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("contextbound-vectors.txt")
        let text = try String(contentsOf: url, encoding: .utf8)
        var n = 0
        for line in text.split(separator: "\n") {
            let p = line.split(separator: " ")
            if p.count != 3 { continue }
            let profile = QPeriaptProfile(rawValue: UInt8(p[0])!)!
            let got = try QPeriaptHybrid.combine(profile: profile, input: hex(String(p[1])))
            XCTAssertEqual(got, hex(String(p[2])),
                           "Swift combine must match the Rust core byte-for-byte")
            n += 1
        }
        XCTAssertEqual(n, 6, "expected 6 reference vectors")
    }

    func testSignedPolicyVectorSelectsProfileAndRejectsRollbackAndTamper() throws {
        let v = try signedPolicyVector()
        XCTAssertEqual(v["algorithm"] as? String, "ML-DSA-65")
        let policyToml = Array((v["policy_toml"] as! String).utf8)
        let signature = hex(v["signature"] as! String)
        let verificationKey = hex(v["verification_key"] as! String)
        let expectedCode = UInt8(v["selected_profile_code"] as! Int)

        let profile = try QPeriaptHybrid.profileFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedVersion: UInt32(v["last_trusted_version_accept"] as! Int))
        XCTAssertEqual(profile.rawValue, expectedCode)

        XCTAssertThrowsError(try QPeriaptHybrid.profileFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedVersion: UInt32(v["last_trusted_version_reject"] as! Int))) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.policyCode)
        }

        var tampered = signature
        let tamperByte = v["tamper_signature_byte"] as! Int
        XCTAssertLessThan(tamperByte, tampered.count)
        tampered[tamperByte] ^= 1
        XCTAssertThrowsError(try QPeriaptHybrid.profileFromSignedPolicy(
            toml: policyToml,
            signature: tampered,
            verificationKey: verificationKey,
            lastTrustedVersion: 0)) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.policyCode)
        }
    }
}
