import CQPeriapt
import Foundation

/// Combiner profile selector (mirrors `Q_PERIAPT_PROFILE_*`).
public enum QPeriaptProfile: UInt8 {
    case compatXWing = 1
    case contextBound = 2
}

/// Errors mirroring the C status codes.
public struct QPeriaptError: Error { public let code: Int32 }

/// Swift face of the PQ/T hybrid suite (ML-KEM-768 + X25519), over the C ABI.
public enum QPeriaptHybrid {
    public static let secretLen = Int(Q_PERIAPT_SECRET_LEN)
    public static let mlkemPkLen = Int(Q_PERIAPT_MLKEM768_PK_LEN)
    public static let mlkemSkLen = Int(Q_PERIAPT_MLKEM768_SK_LEN)
    public static let mlkemCtLen = Int(Q_PERIAPT_MLKEM768_CT_LEN)
    public static let x25519Len = Int(Q_PERIAPT_X25519_LEN)

    public static func mlkem768Keypair(seed: [UInt8]) throws -> (sk: [UInt8], pk: [UInt8]) {
        var sk = [UInt8](repeating: 0, count: mlkemSkLen)
        var pk = [UInt8](repeating: 0, count: mlkemPkLen)
        let rc = q_periapt_mlkem768_keypair(
            seed, UInt(seed.count), &sk, UInt(sk.count), &pk, UInt(pk.count))
        guard rc == Q_PERIAPT_OK else { throw QPeriaptError(code: rc) }
        return (sk, pk)
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
}
