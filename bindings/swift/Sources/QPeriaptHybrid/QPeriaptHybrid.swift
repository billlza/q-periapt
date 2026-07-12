// SwiftPM imports the C ABI through the CQPeriapt system-library target. The iOS/macOS device
// runner imports the same generated C header through a bridging header, where this module is not
// present but the declarations are already in scope.
#if canImport(CQPeriapt)
import CQPeriapt
#endif
import Foundation

/// Combiner profile selector (mirrors `Q_PERIAPT_PROFILE_*`).
public enum QPeriaptProfile: UInt8 {
    case contextBound = 2
}

/// Atomic decision produced by a verified signed policy for the fixed native suite.
/// Fields are read-only so Swift callers cannot accidentally mix a profile from one
/// policy with a suite/version from another.
public struct QPeriaptPolicyDecision {
    public let suiteCode: UInt8
    public let profile: QPeriaptProfile
    public let keyFormatCode: UInt8
    public let policyVersion: UInt32
    public let policyDigest: [UInt8]
    fileprivate let encoded: [UInt8]

    /// Persist this exact value atomically after accepting the policy and pass it
    /// to the next ``QPeriaptHybrid/decisionFromSignedPolicy`` call.
    public var trustedState: [UInt8] {
        var state = Array(policyVersion.bigEndianBytes)
        state.append(contentsOf: policyDigest)
        return state
    }

    fileprivate init(encoded: [UInt8]) throws {
        guard encoded.count == Int(Q_PERIAPT_POLICY_DECISION_LEN),
              encoded[0] == UInt8(Q_PERIAPT_POLICY_DECISION_VERSION),
              encoded[1] == UInt8(Q_PERIAPT_SUITE_MLKEM768_X25519),
              let profile = QPeriaptProfile(rawValue: encoded[2]),
              encoded[3] == UInt8(Q_PERIAPT_KEY_FORMAT_EXPANDED)
        else {
            throw QPeriaptError(code: Q_PERIAPT_ERR_POLICY)
        }
        let version = encoded[4..<8].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard version != 0 else { throw QPeriaptError(code: Q_PERIAPT_ERR_POLICY) }
        let keyFormat = encoded[3]
        guard profile == .contextBound,
              keyFormat == UInt8(Q_PERIAPT_KEY_FORMAT_EXPANDED) else {
            throw QPeriaptError(code: Q_PERIAPT_ERR_POLICY)
        }
        self.suiteCode = encoded[1]
        self.profile = profile
        self.keyFormatCode = keyFormat
        self.policyVersion = version
        self.policyDigest = Array(encoded[8...])
        self.encoded = encoded
    }
}

private extension UInt32 {
    var bigEndianBytes: [UInt8] {
        let value = bigEndian
        return withUnsafeBytes(of: value) { Array($0) }
    }
}

/// Errors mirroring the C status codes.
public struct QPeriaptError: Error {
    public static let lengthCode = Int32(Q_PERIAPT_ERR_LENGTH)
    public static let policyCode = Int32(Q_PERIAPT_ERR_POLICY)

    public let code: Int32
}

/// Result of hybrid encapsulation.
public struct QPeriaptEncapsulation {
    public let ctPq: [UInt8]
    public let ctTrad: [UInt8]
    public private(set) var secret: [UInt8]

    /// Best-effort destruction of this value's current secret buffer.
    ///
    /// Swift arrays use copy-on-write. Callers must also wipe every independent
    /// copy they created; this method cannot erase copies held elsewhere or by
    /// the operating system.
    public mutating func wipeSecret() {
        QPeriaptHybrid.wipe(&secret)
    }
}

/// One atomically generated fixed-suite key pair. Secret-key buffers are
/// caller-owned and must be wiped when no longer needed.
public struct QPeriaptKeyPair {
    public private(set) var skPq: [UInt8]
    public let pkPq: [UInt8]
    public private(set) var skTrad: [UInt8]
    public let pkTrad: [UInt8]

    public mutating func wipeSecrets() {
        QPeriaptHybrid.wipe(&skPq)
        QPeriaptHybrid.wipe(&skTrad)
    }
}

/// Swift face of the PQ/T hybrid suite (ML-KEM-768 + X25519), over the C ABI.
///
/// Secret hygiene: returned secrets (`sk`, the decapsulated/combined secret) are caller-owned
/// Swift `[UInt8]` value arrays. Because Swift arrays are copy-on-write, the binding cannot zero
/// them after `return` without corrupting the value it hands back, so wiping is the caller's
/// responsibility — call ``wipe(_:)`` on each returned array and ``QPeriaptEncapsulation/wipeSecret()``
/// on every encapsulation value when finished with it. These APIs are best-effort: they cannot erase
/// independent copy-on-write buffers or operating-system copies.
public enum QPeriaptHybrid {
    public static let abiVersion = UInt32(Q_PERIAPT_ABI_VERSION)
    public static let secretLen = Int(Q_PERIAPT_SECRET_LEN)
    public static let mlkemPkLen = Int(Q_PERIAPT_MLKEM768_PK_LEN)
    public static let mlkemSkLen = Int(Q_PERIAPT_MLKEM768_SK_LEN)
    public static let mlkemCtLen = Int(Q_PERIAPT_MLKEM768_CT_LEN)
    public static let x25519Len = Int(Q_PERIAPT_X25519_LEN)
    public static let policyDecisionLen = Int(Q_PERIAPT_POLICY_DECISION_LEN)
    public static let trustedPolicyStateLen = Int(Q_PERIAPT_TRUSTED_POLICY_STATE_LEN)
    public static let maxSignedPolicyBytes = Int(Q_PERIAPT_MAX_SIGNED_POLICY_BYTES)
    public static let maxApplicationContextBytes = Int(Q_PERIAPT_MAX_APPLICATION_CONTEXT_BYTES)
    public static let fixedSuiteCode = UInt8(Q_PERIAPT_SUITE_MLKEM768_X25519)

    public static var runtimeAbiVersion: UInt32 {
        q_periapt_abi_version()
    }

    public static var runtimeVersion: String {
        String(cString: q_periapt_version())
    }

    public static var fixedSuiteId: [UInt8] {
        Array(String(cString: q_periapt_fixed_suite_id()).utf8)
    }

    public static var fixedSuiteIdLen: Int {
        Int(q_periapt_fixed_suite_id_len())
    }

    public static func statusName(_ code: Int32) -> String {
        String(cString: q_periapt_status_name(code))
    }

    public static func decisionFromSignedPolicy(
        toml: [UInt8], signature: [UInt8], verificationKey: [UInt8],
        lastTrustedState: [UInt8] = []
    ) throws -> QPeriaptPolicyDecision {
        guard lastTrustedState.isEmpty
                || lastTrustedState.count == Int(Q_PERIAPT_TRUSTED_POLICY_STATE_LEN)
        else {
            throw QPeriaptError(code: Q_PERIAPT_ERR_LENGTH)
        }
        var encoded = [UInt8](
            repeating: 0, count: Int(Q_PERIAPT_POLICY_DECISION_LEN))
        let rc = q_periapt_decision_from_signed_policy(
            toml, UInt(toml.count), signature, UInt(signature.count),
            verificationKey, UInt(verificationKey.count),
            lastTrustedState, UInt(lastTrustedState.count),
            &encoded, UInt(encoded.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        return try QPeriaptPolicyDecision(encoded: encoded)
    }

    public static func generateKeypair(
        decision: QPeriaptPolicyDecision
    ) throws -> QPeriaptKeyPair {
        var skPq = [UInt8](repeating: 0, count: mlkemSkLen)
        var pkPq = [UInt8](repeating: 0, count: mlkemPkLen)
        var skTrad = [UInt8](repeating: 0, count: x25519Len)
        var pkTrad = [UInt8](repeating: 0, count: x25519Len)
        let rc = q_periapt_generate_keypair(
            decision.encoded, UInt(decision.encoded.count),
            &skPq, UInt(skPq.count), &pkPq, UInt(pkPq.count),
            &skTrad, UInt(skTrad.count), &pkTrad, UInt(pkTrad.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        return QPeriaptKeyPair(skPq: skPq, pkPq: pkPq, skTrad: skTrad, pkTrad: pkTrad)
    }

    /// Encapsulate under one authenticated policy decision. The native core
    /// canonically commits the exact policy digest and `applicationContext`;
    /// a CompatXWing decision is rejected because that profile ignores context.
    public static func encapsulate(
        decision: QPeriaptPolicyDecision,
        pkPq: [UInt8], pkTrad: [UInt8], applicationContext: [UInt8]
    ) throws -> QPeriaptEncapsulation {
        var ctPq = [UInt8](repeating: 0, count: mlkemCtLen)
        var ctTrad = [UInt8](repeating: 0, count: x25519Len)
        var secret = [UInt8](repeating: 0, count: secretLen)
        let rc = q_periapt_encapsulate(
            decision.encoded, UInt(decision.encoded.count),
            pkPq, UInt(pkPq.count), pkTrad, UInt(pkTrad.count),
            applicationContext, UInt(applicationContext.count),
            &ctPq, UInt(ctPq.count), &ctTrad, UInt(ctTrad.count),
            &secret, UInt(secret.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        return QPeriaptEncapsulation(ctPq: ctPq, ctTrad: ctTrad, secret: secret)
    }

    /// Decapsulate under the same authenticated decision and application context
    /// used by the policy-controlled encapsulation path.
    public static func decapsulate(
        decision: QPeriaptPolicyDecision,
        skPq: [UInt8], ctPq: [UInt8], pkPq: [UInt8],
        skTrad: [UInt8], ctTrad: [UInt8], pkTrad: [UInt8],
        applicationContext: [UInt8]
    ) throws -> [UInt8] {
        var secret = [UInt8](repeating: 0, count: secretLen)
        let rc = q_periapt_decapsulate(
            decision.encoded, UInt(decision.encoded.count),
            skPq, UInt(skPq.count), ctPq, UInt(ctPq.count), pkPq, UInt(pkPq.count),
            skTrad, UInt(skTrad.count), ctTrad, UInt(ctTrad.count),
            pkTrad, UInt(pkTrad.count),
            applicationContext, UInt(applicationContext.count),
            &secret, UInt(secret.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        return secret
    }

    /// Securely zero a buffer that held secret material. Uses `memset_s`, which (unlike a plain
    /// `memset` of a soon-to-be-freed buffer) the compiler is not permitted to elide as a dead
    /// store. Call this on any `sk` or session secret once it is no longer needed.
    public static func wipe(_ buffer: inout [UInt8]) {
        buffer.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress, raw.count > 0 else { return }
            memset_s(base, raw.count, 0, raw.count)
        }
    }
}
