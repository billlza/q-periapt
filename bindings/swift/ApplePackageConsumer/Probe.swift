// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
#if PROBE_SDK
import QPeriaptSDK
#endif
#if PROBE_CONTINUITY
import QPeriaptContinuity
#endif

enum ProbeError: Error { case invalidFixture, keyMismatch, ownerState }

#if PROBE_SDK
private struct SignedPolicy: Decodable {
    let policy_toml: String
    let signature: String
    let verification_key: String
}

private func bytes(_ hex: String) throws -> [UInt8] {
    let digits = Array(hex.utf8)
    guard digits.count.isMultiple(of: 2) else { throw ProbeError.invalidFixture }
    return try stride(from: 0, to: digits.count, by: 2).map { i in
        let pair = String(decoding: digits[i..<i + 2], as: UTF8.self)
        guard let byte = UInt8(pair, radix: 16) else { throw ProbeError.invalidFixture }
        return byte
    }
}

private func checkSDK(in directory: URL) throws {
    guard let fixture = Bundle.main.url(forResource: "signed-policy-vectors", withExtension: "json") else {
        throw ProbeError.invalidFixture
    }
    let policy = try JSONDecoder().decode(SignedPolicy.self, from: Data(contentsOf: fixture))
    let runtime = try QPeriaptRuntime(policy: Array(policy.policy_toml.utf8),
                                      signature: bytes(policy.signature), trustRoot: bytes(policy.verification_key))
    try Data(runtime.trustedState()).write(to: directory.appendingPathComponent("trusted-state"), options: .atomic)
    let key = try runtime.generateKey()
    let context = Array("dual-package-probe".utf8)
    let sent = try runtime.encapsulate(to: key.publicKey(), applicationContext: context)
    let received = try key.decapsulate(sent.ciphertext, applicationContext: context)
    let label = Array("apple-consumer".utf8)
    let sender = try sent.secret.deriveKey(purpose: .exporter, protocolLabel: label, context: context)
    let receiver = try received.deriveKey(purpose: .exporter, protocolLabel: label, context: context)
    var left = try sender.exportForProtocol()
    var right = try receiver.exportForProtocol()
    defer {
        _ = left.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
        _ = right.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
    }
    guard left.count == 32, left == right else { throw ProbeError.keyMismatch }
    try sender.close()
    try receiver.close()
    try received.close()
    try sent.secret.close()
    try key.close()
    try runtime.close()
    print("SDK_KEM_KDF_PASS")
}
#endif

#if PROBE_CONTINUITY
private func requireCode(_ code: Int32, _ call: () throws -> Void) throws {
    do { try call() }
    catch let failure as ContinuityFailure {
        guard failure.code == code else { throw failure }
        return
    }
    throw ProbeError.ownerState
}

private func checkContinuity(in directory: URL) throws {
    let path = directory.appendingPathComponent("uncreated").path
    let owner = try ContinuityDevice.prepare(path: path)
    try owner.cancel()
    try requireCode(302) { try owner.finishOpen() }
    try owner.close()
    try requireCode(2) { _ = try owner.nextPublication() }
    guard !FileManager.default.fileExists(atPath: path) else { throw ProbeError.ownerState }
    print("CONTINUITY_NATIVE_OWNER_PASS")
}
#endif

@main
enum ApplePackageConsumer {
    static func main() throws {
        let directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        let result = Result {
            #if PROBE_SDK
            try checkSDK(in: directory)
            #endif
            #if PROBE_CONTINUITY
            try checkContinuity(in: directory)
            #endif
        }
        try FileManager.default.removeItem(at: directory)
        try result.get()
    }
}
