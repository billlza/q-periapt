// SwiftPM imports the C ABI through the CQPeriapt system-library target. The iOS/macOS device
// runner imports the same generated C header through a bridging header, where this module is not
// present but the declarations are already in scope.
#if canImport(CQPeriapt)
import CQPeriapt
#endif
import Foundation

/// Combiner profile selector (mirrors `Q_PERIAPT_PROFILE_*`).
public enum QPeriaptProfile: UInt8 {
    case compatXWing = 1
    case contextBound = 2
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
    public let secret: [UInt8]
}

/// Swift face of the PQ/T hybrid suite (ML-KEM-768 + X25519), over the C ABI.
///
/// Secret hygiene: returned secrets (`sk`, the decapsulated/combined secret) are caller-owned
/// Swift `[UInt8]` value arrays. Because Swift arrays are copy-on-write, the binding cannot zero
/// them after `return` without corrupting the value it hands back, so wiping is the caller's
/// responsibility — call ``wipe(_:)`` on each secret buffer when finished with it.
public enum QPeriaptHybrid {
    public static let abiVersion = UInt32(Q_PERIAPT_ABI_VERSION)
    public static let secretLen = Int(Q_PERIAPT_SECRET_LEN)
    public static let mlkemPkLen = Int(Q_PERIAPT_MLKEM768_PK_LEN)
    public static let mlkemSkLen = Int(Q_PERIAPT_MLKEM768_SK_LEN)
    public static let mlkemXWingSeedLen = Int(Q_PERIAPT_MLKEM768_XWING_SEED_LEN)
    public static let mlkemCtLen = Int(Q_PERIAPT_MLKEM768_CT_LEN)
    public static let x25519Len = Int(Q_PERIAPT_X25519_LEN)

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

    public static func profileFromSignedPolicy(
        toml: [UInt8], signature: [UInt8], verificationKey: [UInt8], lastTrustedVersion: UInt32
    ) throws -> QPeriaptProfile {
        var code = [UInt8](repeating: 0, count: 1)
        let rc = q_periapt_profile_from_signed_policy(
            toml, UInt(toml.count), signature, UInt(signature.count),
            verificationKey, UInt(verificationKey.count), lastTrustedVersion,
            &code, UInt(code.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        guard let profile = QPeriaptProfile(rawValue: code[0]) else {
            throw QPeriaptError(code: Q_PERIAPT_ERR_POLICY)
        }
        return profile
    }

    public static func mlkem768Keypair(seed: [UInt8]) throws -> (sk: [UInt8], pk: [UInt8]) {
        var sk = [UInt8](repeating: 0, count: mlkemSkLen)
        var pk = [UInt8](repeating: 0, count: mlkemPkLen)
        let rc = q_periapt_mlkem768_keypair(
            seed, UInt(seed.count), &sk, UInt(sk.count), &pk, UInt(pk.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        return (sk, pk)
    }

    public static func mlkem768XWingKeypair(seed: [UInt8]) throws -> (skSeed: [UInt8], pk: [UInt8]) {
        var skSeed = [UInt8](repeating: 0, count: mlkemXWingSeedLen)
        var pk = [UInt8](repeating: 0, count: mlkemPkLen)
        let rc = q_periapt_mlkem768_xwing_keypair(
            seed, UInt(seed.count), &skSeed, UInt(skSeed.count), &pk, UInt(pk.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        return (skSeed, pk)
    }

    public static func x25519Keypair(secret: [UInt8]) throws -> (sk: [UInt8], pk: [UInt8]) {
        var sk = [UInt8](repeating: 0, count: x25519Len)
        var pk = [UInt8](repeating: 0, count: x25519Len)
        let rc = q_periapt_x25519_keypair(
            secret, UInt(secret.count), &sk, UInt(sk.count), &pk, UInt(pk.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        return (sk, pk)
    }

    public static func decapsulate(
        profile: QPeriaptProfile, suiteId: [UInt8], policyVersion: UInt32,
        skPq: [UInt8], ctPq: [UInt8], pkPq: [UInt8],
        skTrad: [UInt8], ctTrad: [UInt8], pkTrad: [UInt8],
        context: [UInt8]
    ) throws -> [UInt8] {
        var secret = [UInt8](repeating: 0, count: secretLen)
        let rc = q_periapt_hybrid_decapsulate(
            profile.rawValue, suiteId, UInt(suiteId.count), policyVersion,
            skPq, UInt(skPq.count), ctPq, UInt(ctPq.count), pkPq, UInt(pkPq.count),
            skTrad, UInt(skTrad.count), ctTrad, UInt(ctTrad.count), pkTrad, UInt(pkTrad.count),
            context, UInt(context.count), &secret, UInt(secret.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        return secret
    }

    public static func encapsulate(
        profile: QPeriaptProfile, suiteId: [UInt8], policyVersion: UInt32,
        pkPq: [UInt8], pkTrad: [UInt8], context: [UInt8],
        randPq: [UInt8], randTrad: [UInt8]
    ) throws -> QPeriaptEncapsulation {
        var ctPq = [UInt8](repeating: 0, count: mlkemCtLen)
        var ctTrad = [UInt8](repeating: 0, count: x25519Len)
        var secret = [UInt8](repeating: 0, count: secretLen)
        let rc = q_periapt_hybrid_encapsulate(
            profile.rawValue, suiteId, UInt(suiteId.count), policyVersion,
            pkPq, UInt(pkPq.count), pkTrad, UInt(pkTrad.count),
            context, UInt(context.count), randPq, UInt(randPq.count), randTrad, UInt(randTrad.count),
            &ctPq, UInt(ctPq.count), &ctTrad, UInt(ctTrad.count), &secret, UInt(secret.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        return QPeriaptEncapsulation(ctPq: ctPq, ctTrad: ctTrad, secret: secret)
    }

    /// Derive a combined secret directly from the serialized combiner inputs (the
    /// cross-platform reference-vector entry point). `input` is the nine 8-byte
    /// big-endian length-prefixed fields consumed by `q_periapt_combine`.
    public static func combine(profile: QPeriaptProfile, input: [UInt8]) throws -> [UInt8] {
        var secret = [UInt8](repeating: 0, count: secretLen)
        let rc = q_periapt_combine(
            profile.rawValue, input, UInt(input.count), &secret, UInt(secret.count))
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
