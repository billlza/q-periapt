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
        XCTAssertEqual(QPeriaptHybrid.runtimeVersion, "0.1.0-alpha.1")
        XCTAssertEqual(QPeriaptHybrid.fixedSuiteId, Array("ML-KEM-768+X25519".utf8))
        XCTAssertEqual(QPeriaptHybrid.fixedSuiteIdLen, "ML-KEM-768+X25519".utf8.count)
        XCTAssertEqual(QPeriaptHybrid.maxSignedPolicyBytes, 65_536)
        XCTAssertEqual(QPeriaptHybrid.maxApplicationContextBytes, 65_536)
        XCTAssertEqual(QPeriaptHybrid.statusName(QPeriaptError.policyCode), "ERR_POLICY")
        XCTAssertEqual(QPeriaptHybrid.statusName(12345), "UNKNOWN_STATUS")
    }

    func testSignedPolicyVectorResolvesAtomicDecisionAndRejectsRollbackAndTamper() throws {
        let v = try signedPolicyVector()
        XCTAssertEqual(v["algorithm"] as? String, "ML-DSA-65")
        let policyToml = Array((v["policy_toml"] as! String).utf8)
        let signature = hex(v["signature"] as! String)
        let verificationKey = hex(v["verification_key"] as! String)
        let expectedCode = UInt8(v["selected_profile_code"] as! Int)

        let decision = try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey)
        XCTAssertEqual(decision.profile.rawValue, expectedCode)
        XCTAssertEqual(decision.suiteCode, QPeriaptHybrid.fixedSuiteCode)
        XCTAssertEqual(decision.policyVersion, UInt32(v["policy_version"] as! Int))
        XCTAssertEqual(decision.policyDigest, hex(v["policy_digest"] as! String))
        XCTAssertEqual(decision.trustedState.count, QPeriaptHybrid.trustedPolicyStateLen)

        let reapplied = try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedState: decision.trustedState)
        XCTAssertEqual(reapplied.policyDigest, decision.policyDigest)

        XCTAssertThrowsError(try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedState: Array(UInt32(2).bigEndianBytesForTest))) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.lengthCode)
        }

        var policyKeys = try QPeriaptHybrid.generateKeypair(decision: decision)
        let applicationContext = Array("swift-policy-context".utf8)
        var maximumContextEnc = try QPeriaptHybrid.encapsulate(
            decision: decision,
            pkPq: policyKeys.pkPq,
            pkTrad: policyKeys.pkTrad,
            applicationContext: [UInt8](
                repeating: 1, count: QPeriaptHybrid.maxApplicationContextBytes))
        maximumContextEnc.wipeSecret()
        XCTAssertEqual(
            maximumContextEnc.secret,
            [UInt8](repeating: 0, count: QPeriaptHybrid.secretLen))
        XCTAssertThrowsError(try QPeriaptHybrid.encapsulate(
            decision: decision,
            pkPq: policyKeys.pkPq,
            pkTrad: policyKeys.pkTrad,
            applicationContext: [UInt8](
                repeating: 0, count: QPeriaptHybrid.maxApplicationContextBytes + 1))) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.lengthCode)
        }
        let policyEnc = try QPeriaptHybrid.encapsulate(
            decision: decision,
            pkPq: policyKeys.pkPq,
            pkTrad: policyKeys.pkTrad,
            applicationContext: applicationContext)
        let policyDec = try QPeriaptHybrid.decapsulate(
            decision: decision,
            skPq: policyKeys.skPq,
            ctPq: policyEnc.ctPq,
            pkPq: policyKeys.pkPq,
            skTrad: policyKeys.skTrad,
            ctTrad: policyEnc.ctTrad,
            pkTrad: policyKeys.pkTrad,
            applicationContext: applicationContext)
        XCTAssertEqual(policyEnc.secret, policyDec)
        let wrongContextSecret = try QPeriaptHybrid.decapsulate(
            decision: decision,
            skPq: policyKeys.skPq,
            ctPq: policyEnc.ctPq,
            pkPq: policyKeys.pkPq,
            skTrad: policyKeys.skTrad,
            ctTrad: policyEnc.ctTrad,
            pkTrad: policyKeys.pkTrad,
            applicationContext: Array("wrong-context".utf8))
        XCTAssertNotEqual(policyDec, wrongContextSecret)

        var newerState = decision.trustedState
        newerState.replaceSubrange(0..<4, with: UInt32(3).bigEndianBytesForTest)
        XCTAssertThrowsError(try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedState: newerState)) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.policyCode)
        }

        policyKeys.wipeSecrets()
        XCTAssertEqual(policyKeys.skPq, [UInt8](repeating: 0, count: QPeriaptHybrid.mlkemSkLen))
        XCTAssertEqual(policyKeys.skTrad, [UInt8](repeating: 0, count: QPeriaptHybrid.x25519Len))

        var tampered = signature
        let tamperByte = v["tamper_signature_byte"] as! Int
        XCTAssertLessThan(tamperByte, tampered.count)
        tampered[tamperByte] ^= 1
        XCTAssertThrowsError(try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: policyToml,
            signature: tampered,
            verificationKey: verificationKey)) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.policyCode)
        }
    }
}

private extension UInt32 {
    var bigEndianBytesForTest: [UInt8] {
        let value = bigEndian
        return withUnsafeBytes(of: value) { Array($0) }
    }
}
