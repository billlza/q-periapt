import Foundation
import XCTest

@testable import QPeriaptHybrid

final class QPeriaptHybridBinaryConsumerTests: XCTestCase {
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

    func resourceData(_ name: String) throws -> Data {
        guard let url = Bundle.module.url(
            forResource: name,
            withExtension: nil,
            subdirectory: "Resources"
        ) else {
            throw NSError(domain: "QPeriaptBinaryConsumerTests", code: 1)
        }
        return try Data(contentsOf: url)
    }

    func signedPolicyVector() throws -> [String: Any] {
        let data = try resourceData("signed-policy-vectors.json")
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func uint32Bytes(_ value: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ]
    }

    func testRuntimeMetadataMatchesCompiledHeader() throws {
        XCTAssertEqual(QPeriaptHybrid.runtimeAbiVersion, QPeriaptHybrid.abiVersion)
        XCTAssertEqual(QPeriaptHybrid.runtimeVersion, "0.1.0-alpha.2")
        XCTAssertEqual(QPeriaptHybrid.fixedSuiteId, Array("ML-KEM-768+X25519".utf8))
        XCTAssertEqual(QPeriaptHybrid.fixedSuiteIdLen, "ML-KEM-768+X25519".utf8.count)
        XCTAssertEqual(QPeriaptHybrid.statusName(QPeriaptError.policyCode), "ERR_POLICY")
        XCTAssertEqual(QPeriaptHybrid.statusName(12345), "UNKNOWN_STATUS")
    }

    func testSignedPolicyDecisionIsExactAndFailClosed() throws {
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
        let expectedVersion = UInt32(v["policy_version"] as! Int)
        XCTAssertEqual(decision.profile.rawValue, expectedCode)
        XCTAssertEqual(decision.suiteCode, QPeriaptHybrid.fixedSuiteCode)
        XCTAssertEqual(decision.policyVersion, expectedVersion)
        XCTAssertEqual(decision.policyDigest, hex(v["policy_digest"] as! String))
        XCTAssertEqual(decision.trustedState.count, QPeriaptHybrid.trustedPolicyStateLen)
        XCTAssertEqual(Array(decision.trustedState.dropFirst(4)), decision.policyDigest)

        XCTAssertThrowsError(try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedState: uint32Bytes(expectedVersion))) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.lengthCode)
        }

        let reapplied = try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedState: decision.trustedState)
        XCTAssertEqual(reapplied.policyDigest, decision.policyDigest)

        var newerState = decision.trustedState
        let rejectVersion = UInt32(v["last_trusted_version_reject"] as! Int)
        newerState.replaceSubrange(0..<4, with: uint32Bytes(rejectVersion))
        XCTAssertThrowsError(try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedState: newerState)) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.policyCode)
        }

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

    func testOSRandomPolicyRoundtripAndWipes() throws {
        let v = try signedPolicyVector()
        let decision = try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: Array((v["policy_toml"] as! String).utf8),
            signature: hex(v["signature"] as! String),
            verificationKey: hex(v["verification_key"] as! String))
        var keys = try QPeriaptHybrid.generateKeypair(decision: decision)
        var encapsulation = try QPeriaptHybrid.encapsulate(
            decision: decision,
            pkPq: keys.pkPq,
            pkTrad: keys.pkTrad,
            applicationContext: Array("swift-binary-consumer".utf8))
        var decapsulated = try QPeriaptHybrid.decapsulate(
            decision: decision,
            skPq: keys.skPq,
            ctPq: encapsulation.ctPq,
            pkPq: keys.pkPq,
            skTrad: keys.skTrad,
            ctTrad: encapsulation.ctTrad,
            pkTrad: keys.pkTrad,
            applicationContext: Array("swift-binary-consumer".utf8))
        var wrongContext = try QPeriaptHybrid.decapsulate(
            decision: decision,
            skPq: keys.skPq,
            ctPq: encapsulation.ctPq,
            pkPq: keys.pkPq,
            skTrad: keys.skTrad,
            ctTrad: encapsulation.ctTrad,
            pkTrad: keys.pkTrad,
            applicationContext: Array("wrong-context".utf8))
        defer {
            encapsulation.wipeSecret()
            QPeriaptHybrid.wipe(&decapsulated)
            QPeriaptHybrid.wipe(&wrongContext)
            keys.wipeSecrets()
        }

        XCTAssertEqual(encapsulation.secret, decapsulated)
        XCTAssertNotEqual(decapsulated, wrongContext)

        var maximumContext = try QPeriaptHybrid.encapsulate(
            decision: decision,
            pkPq: keys.pkPq,
            pkTrad: keys.pkTrad,
            applicationContext: [UInt8](
                repeating: 1, count: QPeriaptHybrid.maxApplicationContextBytes))
        maximumContext.wipeSecret()
        XCTAssertEqual(
            maximumContext.secret,
            [UInt8](repeating: 0, count: QPeriaptHybrid.secretLen))
        XCTAssertThrowsError(try QPeriaptHybrid.encapsulate(
            decision: decision,
            pkPq: keys.pkPq,
            pkTrad: keys.pkTrad,
            applicationContext: [UInt8](
                repeating: 0, count: QPeriaptHybrid.maxApplicationContextBytes + 1))) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.lengthCode)
        }

        encapsulation.wipeSecret()
        QPeriaptHybrid.wipe(&decapsulated)
        QPeriaptHybrid.wipe(&wrongContext)
        keys.wipeSecrets()
        XCTAssertEqual(
            encapsulation.secret,
            [UInt8](repeating: 0, count: QPeriaptHybrid.secretLen))
        XCTAssertTrue(decapsulated.allSatisfy { $0 == 0 })
        XCTAssertTrue(wrongContext.allSatisfy { $0 == 0 })
        XCTAssertTrue(keys.skPq.allSatisfy { $0 == 0 })
        XCTAssertTrue(keys.skTrad.allSatisfy { $0 == 0 })
    }
}
