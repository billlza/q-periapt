// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptHybrid
import QPeriaptSDK

precondition(QPeriaptHybrid.runtimeAbiVersion == 2)
precondition(QPeriaptHybrid.runtimeVersion == "0.2.0-alpha.1")

// Keep the public owner/connection entry points in this real consumer's link
// graph without making a network connection during a link-only platform gate.
func checkOwnerAPI(policy: [UInt8], signature: [UInt8], root: [UInt8]) async throws {
    let runtime = try QPeriaptRuntime(policy: policy, signature: signature, trustRoot: root)
    let key = try await runtime.generateKeyAsync()
    let publicKey = try key.publicKey()
    let encapsulated = try await runtime.encapsulateAsync(to: publicKey, applicationContext: [1])
    let recovered = try await key.decapsulateAsync(encapsulated.ciphertext, applicationContext: [1])
    let derived = try recovered.deriveKey(purpose: .initiatorTraffic,
                                         protocolLabel: Array("link-probe/v1".utf8), context: [1])
    var bytes = try derived.exportForProtocol()
    QPeriaptHybrid.wipe(&bytes)
    try derived.close()
    try recovered.close()
    try encapsulated.secret.close()
    try key.close()
    try runtime.close()
}
if CommandLine.arguments.contains("--invalid-policy-rejection") {
    Task {
        do {
            try await checkOwnerAPI(policy: [], signature: [], root: [])
            exit(2)
        } catch let error as QPeriaptSDKError {
            exit(error.code == -2 ? 0 : 3)
        } catch { exit(4) }
    }
    dispatchMain()
}
