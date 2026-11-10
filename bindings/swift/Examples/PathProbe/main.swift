// SPDX-License-Identifier: Apache-2.0 OR MIT
// Paired calls through the real public Swift compatibility and owner bindings.
import Foundation
import QPeriaptHybrid
import QPeriaptSDK

private enum ProbeError: Error { case arguments, fixture, correspondence, clock }
private struct Fixture: Decodable {
    let policy_toml: String
    let signature: String
    let verification_key: String
}
private struct Samples: Encodable {
    let schema = 1
    let surface = "swift_dynamic"
    let operation: String
    let context_bytes: Int
    let phase: Int
    let warmup_pairs = 64
    let legacy_raw_ns: [UInt64]
    let owner_raw_ns: [UInt64]
}

private func hex(_ text: String, count: Int) throws -> [UInt8] {
    let chars = Array(text.utf8)
    guard chars.count == 2 * count else { throw ProbeError.fixture }
    return try stride(from: 0, to: chars.count, by: 2).map { i in
        guard let byte = UInt8(String(decoding: chars[i..<(i + 2)], as: UTF8.self), radix: 16)
        else { throw ProbeError.fixture }
        return byte
    }
}
private func time(_ body: () throws -> Void) throws -> UInt64 {
    let started = DispatchTime.now().uptimeNanoseconds
    try body()
    let ended = DispatchTime.now().uptimeNanoseconds
    guard ended > started else { throw ProbeError.clock }
    return ended - started
}
@available(macOS 13.0, *)
private func pairs(_ operation: String, context: Int, count: Int, phase: Int,
                   legacy: () throws -> Void, owner: () throws -> Void) throws {
    for i in 0..<64 {
        if (i + phase).isMultiple(of: 2) { try legacy(); try owner() }
        else { try owner(); try legacy() }
    }
    var old: [UInt64] = [], new: [UInt64] = []
    old.reserveCapacity(count); new.reserveCapacity(count)
    for i in 0..<count {
        if (i + phase).isMultiple(of: 2) {
            old.append(try time(legacy)); new.append(try time(owner))
        } else {
            new.append(try time(owner)); old.append(try time(legacy))
        }
    }
    let record = Samples(operation: operation, context_bytes: context, phase: phase,
                         legacy_raw_ns: old, owner_raw_ns: new)
    let line = try JSONEncoder().encode(record) + Data([10])
    try FileHandle.standardOutput.write(contentsOf: line)
}
private func consume(_ secret: QPeriaptSecret) throws {
    var bytes = try secret.exportForProtocol()
    defer { QPeriaptHybrid.wipe(&bytes) }
    try secret.close()
}

@available(macOS 13.0, *)
private func run() throws {
    let args = CommandLine.arguments
    guard args.count == 4, let count = Int(args[2]), (200...5000).contains(count),
          count.isMultiple(of: 2), let phase = Int(args[3]), (0...1).contains(phase)
    else { throw ProbeError.arguments }
    let data = try Data(contentsOf: URL(fileURLWithPath: args[1]))
    guard data.count <= 32768 else { throw ProbeError.fixture }
    let fixture = try JSONDecoder().decode(Fixture.self, from: data)
    let policy = Array(fixture.policy_toml.utf8)
    let signature = try hex(fixture.signature, count: 3309)
    let root = try hex(fixture.verification_key, count: 1952)
    let decision = try QPeriaptHybrid.decisionFromSignedPolicy(
        toml: policy, signature: signature, verificationKey: root)
    let runtime = try QPeriaptRuntime(policy: policy, signature: signature, trustRoot: root,
                                     maxLiveKeys: 2, maxInFlight: 1)
    var legacyKey = try QPeriaptHybrid.generateKeypair(decision: decision)
    defer { legacyKey.wipeSecrets() }
    var transfer: [UInt8] = [0x51, 0x50, 0x4b, 1, 1, 2, 1, 0] + legacyKey.skPq + legacyKey.skTrad
    let key: QPeriaptKey
    do {
        defer { QPeriaptHybrid.wipe(&transfer) }
        key = try QPeriaptExpert.importExpanded(transfer, into: runtime)
    }
    let publicKey = try key.publicKey()
    guard publicKey.bytes == legacyKey.pkPq + legacyKey.pkTrad,
          try runtime.trustedState() == decision.trustedState else { throw ProbeError.correspondence }

    try pairs("generate_key", context: 0, count: count, phase: phase) {
        var created = try QPeriaptHybrid.generateKeypair(decision: decision)
        created.wipeSecrets()
    } owner: {
        let created = try runtime.generateKey()
        _ = try created.publicKey()
        try created.close()
    }
    for length in [32, 4096, 65536] {
        let context = [UInt8](repeating: 0x51, count: length)
        func legacyDecapsulate(_ ciphertext: [UInt8]) throws -> [UInt8] {
            try QPeriaptHybrid.decapsulate(decision: decision, skPq: legacyKey.skPq,
                ctPq: Array(ciphertext.prefix(1088)), pkPq: legacyKey.pkPq,
                skTrad: legacyKey.skTrad, ctTrad: Array(ciphertext.suffix(32)),
                pkTrad: legacyKey.pkTrad, applicationContext: context)
        }
        func validate() throws {
            var legacy = try QPeriaptHybrid.encapsulate(decision: decision,
                pkPq: legacyKey.pkPq, pkTrad: legacyKey.pkTrad, applicationContext: context)
            defer { legacy.wipeSecret() }
            let recovered = try key.decapsulate(QPeriaptCiphertext(bytes: legacy.ctPq + legacy.ctTrad),
                                                applicationContext: context)
            var right = try recovered.exportForProtocol()
            defer { QPeriaptHybrid.wipe(&right) }
            try recovered.close()
            guard legacy.secret == right else { throw ProbeError.correspondence }
            let owned = try runtime.encapsulate(to: publicKey, applicationContext: context)
            var left = try owned.secret.exportForProtocol()
            defer { QPeriaptHybrid.wipe(&left) }
            try owned.secret.close()
            var recoveredLegacy = try legacyDecapsulate(owned.ciphertext.bytes)
            defer { QPeriaptHybrid.wipe(&recoveredLegacy) }
            guard left == recoveredLegacy else { throw ProbeError.correspondence }
        }
        try validate()
        // Both decapsulation paths receive the same pre-split ciphertext. The
        // compatibility API does not pay for diagnostic split/join conversions.
        var sample = try QPeriaptHybrid.encapsulate(decision: decision, pkPq: legacyKey.pkPq,
            pkTrad: legacyKey.pkTrad, applicationContext: context)
        sample.wipeSecret()
        let ciphertext = try QPeriaptCiphertext(bytes: sample.ctPq + sample.ctTrad)
        try pairs("encapsulate", context: length, count: count, phase: phase) {
            var result = try QPeriaptHybrid.encapsulate(decision: decision, pkPq: legacyKey.pkPq,
                pkTrad: legacyKey.pkTrad, applicationContext: context)
            result.wipeSecret()
        } owner: {
            try consume(runtime.encapsulate(to: publicKey, applicationContext: context).secret)
        }
        try pairs("decapsulate", context: length, count: count, phase: phase) {
            var result = try QPeriaptHybrid.decapsulate(decision: decision, skPq: legacyKey.skPq,
                ctPq: sample.ctPq, pkPq: legacyKey.pkPq, skTrad: legacyKey.skTrad,
                ctTrad: sample.ctTrad, pkTrad: legacyKey.pkTrad, applicationContext: context)
            QPeriaptHybrid.wipe(&result)
        } owner: {
            try consume(key.decapsulate(ciphertext, applicationContext: context))
        }
        try validate()
    }
    try key.close()
    try runtime.close()
}

if #available(macOS 13.0, *) {
    do { try run() }
    catch {
        do { try FileHandle.standardError.write(contentsOf: Data("Swift SDK diagnostic failed: \(error)\n".utf8)) }
        catch { exit(2) }
        exit(1)
    }
} else {
    // This diagnostic follows the packaged SDK's macOS 13 minimum.
    exit(2)
}
