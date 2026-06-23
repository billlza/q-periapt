import CPQT
import Foundation

/// Combiner profile selector (mirrors `PQT_PROFILE_*`).
public enum PQTProfile: UInt8 {
    case compatXWing = 1
    case contextBound = 2
}

/// Errors mirroring the C status codes.
public struct PQTError: Error { public let code: Int32 }

/// Swift face of the PQ/T hybrid suite (ML-KEM-768 + X25519), over the C ABI.
public enum PQTHybrid {
    public static let secretLen = Int(PQT_SECRET_LEN)
    public static let mlkemPkLen = Int(PQT_MLKEM768_PK_LEN)
    public static let mlkemSkLen = Int(PQT_MLKEM768_SK_LEN)
    public static let mlkemCtLen = Int(PQT_MLKEM768_CT_LEN)
    public static let x25519Len = Int(PQT_X25519_LEN)

    public static func mlkem768Keypair(seed: [UInt8]) throws -> (sk: [UInt8], pk: [UInt8]) {
        var sk = [UInt8](repeating: 0, count: mlkemSkLen)
        var pk = [UInt8](repeating: 0, count: mlkemPkLen)
        let rc = pqt_mlkem768_keypair(
            seed, UInt(seed.count), &sk, UInt(sk.count), &pk, UInt(pk.count))
        guard rc == PQT_OK else { throw PQTError(code: rc) }
        return (sk, pk)
    }

    public static func x25519Keypair(secret: [UInt8]) throws -> (sk: [UInt8], pk: [UInt8]) {
        var sk = [UInt8](repeating: 0, count: x25519Len)
        var pk = [UInt8](repeating: 0, count: x25519Len)
        let rc = pqt_x25519_keypair(
            secret, UInt(secret.count), &sk, UInt(sk.count), &pk, UInt(pk.count))
        guard rc == PQT_OK else { throw PQTError(code: rc) }
        return (sk, pk)
    }

    public static func decapsulate(
        profile: PQTProfile, suiteId: [UInt8], policyVersion: UInt32,
        skPq: [UInt8], ctPq: [UInt8], pkPq: [UInt8],
        skTrad: [UInt8], ctTrad: [UInt8], pkTrad: [UInt8],
        context: [UInt8]
    ) throws -> [UInt8] {
        var secret = [UInt8](repeating: 0, count: secretLen)
        let rc = pqt_hybrid_decapsulate(
            profile.rawValue, suiteId, UInt(suiteId.count), policyVersion,
            skPq, UInt(skPq.count), ctPq, UInt(ctPq.count), pkPq, UInt(pkPq.count),
            skTrad, UInt(skTrad.count), ctTrad, UInt(ctTrad.count), pkTrad, UInt(pkTrad.count),
            context, UInt(context.count), &secret, UInt(secret.count))
        guard rc == PQT_OK else { throw PQTError(code: rc) }
        return secret
    }
}
