import Foundation

enum DeviceSmokeError: Error, CustomStringConvertible {
    case missingResource(String)
    case invalidVector(String)
    case mismatch(String)
    case expectedFailureMissing(String)

    var description: String {
        switch self {
        case let .missingResource(name):
            return "missing resource: \(name)"
        case let .invalidVector(message):
            return "invalid vector: \(message)"
        case let .mismatch(message):
            return "mismatch: \(message)"
        case let .expectedFailureMissing(message):
            return "expected failure missing: \(message)"
        }
    }
}

enum DeviceSmoke {
    static func run() throws {
        try assertSignedPolicyVector()
    }

    private static func assertSignedPolicyVector() throws {
        guard QPeriaptHybrid.runtimeAbiVersion == QPeriaptHybrid.abiVersion,
              QPeriaptHybrid.runtimeVersion == "0.1.0-alpha.2"
        else {
            throw DeviceSmokeError.mismatch("ABI2 runtime metadata")
        }
        guard let url = Bundle.main.url(forResource: "signed-policy-vectors", withExtension: "json") else {
            throw DeviceSmokeError.missingResource("signed-policy-vectors.json")
        }
        let data = try Data(contentsOf: url)
        guard let vector = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw DeviceSmokeError.invalidVector("signed-policy-vectors.json is not an object")
        }
        guard try stringField(vector, "algorithm") == "ML-DSA-65" else {
            throw DeviceSmokeError.invalidVector("signed policy algorithm")
        }

        let policyToml = Array(try stringField(vector, "policy_toml").utf8)
        let verificationKey = try hexField(vector, "verification_key")
        let signature = try hexField(vector, "signature")
        let expectedCode = try profileCode(vector)
        let expectedPolicyVersion = try uint32Field(vector, "policy_version")
        let accepted = try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey)
        guard accepted.profile.rawValue == expectedCode,
              accepted.suiteCode == QPeriaptHybrid.fixedSuiteCode,
              accepted.policyVersion == expectedPolicyVersion,
              accepted.policyDigest == (try hexField(vector, "policy_digest"))
        else {
            throw DeviceSmokeError.mismatch("signed policy atomic decision")
        }

        let reapplied = try QPeriaptHybrid.decisionFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedState: accepted.trustedState)
        guard reapplied.policyDigest == accepted.policyDigest else {
            throw DeviceSmokeError.mismatch("signed policy trusted state")
        }

        try expectLengthRejection("legacy ABI 1 version-only state") {
            _ = try QPeriaptHybrid.decisionFromSignedPolicy(
                toml: policyToml,
                signature: signature,
                verificationKey: verificationKey,
                lastTrustedState: uint32Bytes(expectedPolicyVersion))
        }

        var policyKeys = try QPeriaptHybrid.generateKeypair(decision: accepted)
        defer { policyKeys.wipeSecrets() }
        let applicationContext = Array("device-policy-context".utf8)
        var maximumContextEnc = try QPeriaptHybrid.encapsulate(
            decision: accepted,
            pkPq: policyKeys.pkPq,
            pkTrad: policyKeys.pkTrad,
            applicationContext: [UInt8](
                repeating: 1, count: QPeriaptHybrid.maxApplicationContextBytes))
        maximumContextEnc.wipeSecret()
        try assertEqual(
            maximumContextEnc.secret,
            [UInt8](repeating: 0, count: QPeriaptHybrid.secretLen),
            "maximum application context secret wipe")
        do {
            _ = try QPeriaptHybrid.encapsulate(
                decision: accepted,
                pkPq: policyKeys.pkPq,
                pkTrad: policyKeys.pkTrad,
                applicationContext: [UInt8](
                    repeating: 0, count: QPeriaptHybrid.maxApplicationContextBytes + 1))
            throw DeviceSmokeError.expectedFailureMissing(
                "oversized policy-bound application context was accepted")
        } catch let error as QPeriaptError where error.code == QPeriaptError.lengthCode {
            // Expected fail-closed resource bound.
        }
        var policyEnc = try QPeriaptHybrid.encapsulate(
            decision: accepted,
            pkPq: policyKeys.pkPq,
            pkTrad: policyKeys.pkTrad,
            applicationContext: applicationContext)
        var policyDec = [UInt8]()
        var wrongContextSecret = [UInt8]()
        defer {
            policyEnc.wipeSecret()
            QPeriaptHybrid.wipe(&policyDec)
            QPeriaptHybrid.wipe(&wrongContextSecret)
        }
        policyDec = try QPeriaptHybrid.decapsulate(
            decision: accepted,
            skPq: policyKeys.skPq,
            ctPq: policyEnc.ctPq,
            pkPq: policyKeys.pkPq,
            skTrad: policyKeys.skTrad,
            ctTrad: policyEnc.ctTrad,
            pkTrad: policyKeys.pkTrad,
            applicationContext: applicationContext)
        guard policyEnc.secret == policyDec else {
            throw DeviceSmokeError.mismatch("signed policy-bound roundtrip")
        }
        wrongContextSecret = try QPeriaptHybrid.decapsulate(
            decision: accepted,
            skPq: policyKeys.skPq,
            ctPq: policyEnc.ctPq,
            pkPq: policyKeys.pkPq,
            skTrad: policyKeys.skTrad,
            ctTrad: policyEnc.ctTrad,
            pkTrad: policyKeys.pkTrad,
            applicationContext: Array("wrong-context".utf8))
        guard wrongContextSecret != policyDec else {
            throw DeviceSmokeError.mismatch("signed policy application context binding")
        }
        policyEnc.wipeSecret()
        QPeriaptHybrid.wipe(&policyDec)
        QPeriaptHybrid.wipe(&wrongContextSecret)
        policyKeys.wipeSecrets()
        try assertEqual(
            policyEnc.secret,
            [UInt8](repeating: 0, count: QPeriaptHybrid.secretLen),
            "encapsulation secret wipe")
        try assertEqual(
            policyDec,
            [UInt8](repeating: 0, count: QPeriaptHybrid.secretLen),
            "decapsulation secret wipe")
        try assertEqual(
            wrongContextSecret,
            [UInt8](repeating: 0, count: QPeriaptHybrid.secretLen),
            "wrong-context secret wipe")
        try assertEqual(
            policyKeys.skPq,
            [UInt8](repeating: 0, count: QPeriaptHybrid.mlkemSkLen),
            "ML-KEM secret-key wipe")
        try assertEqual(
            policyKeys.skTrad,
            [UInt8](repeating: 0, count: QPeriaptHybrid.x25519Len),
            "X25519 secret-key wipe")

        var newerState = accepted.trustedState
        newerState.replaceSubrange(
            0..<4,
            with: uint32Bytes(try uint32Field(vector, "last_trusted_version_reject")))
        try expectPolicyRejection("signed policy rollback") {
            _ = try QPeriaptHybrid.decisionFromSignedPolicy(
                toml: policyToml,
                signature: signature,
                verificationKey: verificationKey,
                lastTrustedState: newerState)
        }

        var tampered = signature
        let byteIndex = try intField(vector, "tamper_signature_byte")
        guard byteIndex >= 0 && byteIndex < tampered.count else {
            throw DeviceSmokeError.invalidVector("tamper_signature_byte")
        }
        tampered[byteIndex] ^= 1
        try expectPolicyRejection("signed policy tamper") {
            _ = try QPeriaptHybrid.decisionFromSignedPolicy(
                toml: policyToml,
                signature: tampered,
                verificationKey: verificationKey)
        }
    }

    private static func expectPolicyRejection(_ label: String, _ operation: () throws -> Void) throws {
        do {
            try operation()
        } catch let error as QPeriaptError where error.code == QPeriaptError.policyCode {
            return
        }
        throw DeviceSmokeError.expectedFailureMissing(label)
    }

    private static func expectLengthRejection(_ label: String, _ operation: () throws -> Void) throws {
        do {
            try operation()
        } catch let error as QPeriaptError where error.code == QPeriaptError.lengthCode {
            return
        }
        throw DeviceSmokeError.expectedFailureMissing(label)
    }

    private static func intField(_ v: [String: Any], _ name: String) throws -> Int {
        guard let n = v[name] as? Int else {
            throw DeviceSmokeError.invalidVector(name)
        }
        return n
    }

    private static func uint32Field(_ v: [String: Any], _ name: String) throws -> UInt32 {
        let n = try intField(v, name)
        guard n >= 0 && n <= Int(UInt32.max) else {
            throw DeviceSmokeError.invalidVector(name)
        }
        return UInt32(n)
    }

    private static func uint32Bytes(_ value: UInt32) -> [UInt8] {
        let bigEndian = value.bigEndian
        return withUnsafeBytes(of: bigEndian) { Array($0) }
    }

    private static func profileCode(_ v: [String: Any]) throws -> UInt8 {
        let n = try intField(v, "selected_profile_code")
        guard n >= 0 && n <= Int(UInt8.max) else {
            throw DeviceSmokeError.invalidVector("selected_profile_code")
        }
        return UInt8(n)
    }

    private static func hexField(_ v: [String: Any], _ name: String) throws -> [UInt8] {
        guard let s = v[name] as? String else {
            throw DeviceSmokeError.invalidVector(name)
        }
        return try hex(s)
    }

    private static func stringField(_ v: [String: Any], _ name: String) throws -> String {
        guard let s = v[name] as? String else {
            throw DeviceSmokeError.invalidVector(name)
        }
        return s
    }

    private static func hex(_ s: String) throws -> [UInt8] {
        if s.count % 2 != 0 {
            throw DeviceSmokeError.invalidVector("odd hex length")
        }
        var out = [UInt8]()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            guard let byte = UInt8(s[i..<j], radix: 16) else {
                throw DeviceSmokeError.invalidVector("non-hex byte")
            }
            out.append(byte)
            i = j
        }
        return out
    }

    private static func assertEqual(_ lhs: [UInt8], _ rhs: [UInt8], _ label: String) throws {
        if lhs != rhs {
            throw DeviceSmokeError.mismatch(label)
        }
    }
}
