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
        let vector = try sharedVector()
        try assertSharedVectorDecapsulates(vector)
        try assertSharedVectorEncapsulates(vector)
        try assertContextBoundRejectsEmptyContext(vector)
        try assertCompatXWingSeedKeypairRoundtrips()
        try assertCombinerVectors()
        try assertSignedPolicyVector()
    }

    private static func sharedVector() throws -> [String: Any] {
        guard let url = Bundle.main.url(forResource: "shared-test-vectors", withExtension: "json") else {
            throw DeviceSmokeError.missingResource("shared-test-vectors.json")
        }
        let data = try Data(contentsOf: url)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw DeviceSmokeError.invalidVector("shared-test-vectors.json is not an object")
        }
        return json
    }

    private static func assertSharedVectorDecapsulates(_ v: [String: Any]) throws {
        let secret = try QPeriaptHybrid.decapsulate(
            profile: .contextBound,
            suiteId: try hexField(v, "suite_id"),
            policyVersion: try policyVersion(v),
            skPq: try hexField(v, "sk_pq"),
            ctPq: try hexField(v, "ct_pq"),
            pkPq: try hexField(v, "pk_pq"),
            skTrad: try hexField(v, "sk_trad"),
            ctTrad: try hexField(v, "ct_trad"),
            pkTrad: try hexField(v, "pk_trad"),
            context: try hexField(v, "context"))
        try assertEqual(secret, try hexField(v, "secret"), "shared vector decapsulation")
    }

    private static func assertSharedVectorEncapsulates(_ v: [String: Any]) throws {
        let enc = try QPeriaptHybrid.encapsulate(
            profile: .contextBound,
            suiteId: try hexField(v, "suite_id"),
            policyVersion: try policyVersion(v),
            pkPq: try hexField(v, "pk_pq"),
            pkTrad: try hexField(v, "pk_trad"),
            context: try hexField(v, "context"),
            randPq: try hexField(v, "rand_pq"),
            randTrad: try hexField(v, "rand_trad"))
        try assertEqual(enc.ctPq, try hexField(v, "ct_pq"), "shared vector ML-KEM ciphertext")
        try assertEqual(enc.ctTrad, try hexField(v, "ct_trad"), "shared vector X25519 ciphertext")
        try assertEqual(enc.secret, try hexField(v, "secret"), "shared vector encapsulation secret")
    }

    private static func assertContextBoundRejectsEmptyContext(_ v: [String: Any]) throws {
        do {
            _ = try QPeriaptHybrid.encapsulate(
                profile: .contextBound,
                suiteId: try hexField(v, "suite_id"),
                policyVersion: try policyVersion(v),
                pkPq: try hexField(v, "pk_pq"),
                pkTrad: try hexField(v, "pk_trad"),
                context: [],
                randPq: try hexField(v, "rand_pq"),
                randTrad: try hexField(v, "rand_trad"))
        } catch let error as QPeriaptError where error.code == QPeriaptError.lengthCode {
            return
        }
        throw DeviceSmokeError.expectedFailureMissing("empty ContextBound context was accepted")
    }

    private static func assertCompatXWingSeedKeypairRoundtrips() throws {
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
        try assertEqual(enc.secret, dec, "CompatXWing seed-dk roundtrip")
    }

    private static func assertCombinerVectors() throws {
        guard let url = Bundle.main.url(forResource: "contextbound-vectors", withExtension: "txt") else {
            throw DeviceSmokeError.missingResource("contextbound-vectors.txt")
        }
        let text = try String(contentsOf: url, encoding: .utf8)
        var count = 0
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: " ")
            if parts.isEmpty || parts[0].hasPrefix("#") {
                continue
            }
            guard parts.count == 3,
                  let rawProfile = UInt8(parts[0]),
                  let profile = QPeriaptProfile(rawValue: rawProfile) else {
                throw DeviceSmokeError.invalidVector("bad combiner line: \(line)")
            }
            let got = try QPeriaptHybrid.combine(profile: profile, input: try hex(String(parts[1])))
            try assertEqual(got, try hex(String(parts[2])), "combiner vector \(count)")
            count += 1
        }
        if count != 6 {
            throw DeviceSmokeError.invalidVector("expected 6 combiner vectors, found \(count)")
        }
    }

    private static func assertSignedPolicyVector() throws {
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
        let accepted = try QPeriaptHybrid.profileFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedVersion: try uint32Field(vector, "last_trusted_version_accept"))
        guard accepted.rawValue == expectedCode else {
            throw DeviceSmokeError.mismatch("signed policy selected profile")
        }

        try expectPolicyRejection("signed policy rollback") {
            _ = try QPeriaptHybrid.profileFromSignedPolicy(
                toml: policyToml,
                signature: signature,
                verificationKey: verificationKey,
                lastTrustedVersion: try uint32Field(vector, "last_trusted_version_reject"))
        }

        var tampered = signature
        let byteIndex = try intField(vector, "tamper_signature_byte")
        guard byteIndex >= 0 && byteIndex < tampered.count else {
            throw DeviceSmokeError.invalidVector("tamper_signature_byte")
        }
        tampered[byteIndex] ^= 1
        try expectPolicyRejection("signed policy tamper") {
            _ = try QPeriaptHybrid.profileFromSignedPolicy(
                toml: policyToml,
                signature: tampered,
                verificationKey: verificationKey,
                lastTrustedVersion: 0)
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

    private static func policyVersion(_ v: [String: Any]) throws -> UInt32 {
        guard let n = v["policy_version"] as? Int, n >= 0, n <= Int(UInt32.max) else {
            throw DeviceSmokeError.invalidVector("policy_version")
        }
        return UInt32(n)
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
