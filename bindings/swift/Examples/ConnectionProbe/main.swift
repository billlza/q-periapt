// SPDX-License-Identifier: Apache-2.0 OR MIT
// Local transport diagnostic with private test credentials and persisted policy
// on both peers. It is not installed cross-platform or power-loss qualification.
import Foundation
import Darwin
import QPeriaptSDK

enum ProbeError: Error { case usage, unexpectedResult, expectedFailureMissing }

@main
struct ConnectionProbe {
    struct SetupTiming: Encodable {
        let schema = 1
        let kind = "setup"
        let elapsed_ns: UInt64
    }

    struct ConnectionTiming: Encodable {
        let schema = 1
        let kind = "connection"
        let index: Int
        let phase: String
        let connect_ns: UInt64
        let payload_bytes: [Int]
        let request_ns: [UInt64]
        let shutdown_ns: UInt64
    }

    static func emit<T: Encodable>(_ value: T) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        var data = try encoder.encode(value)
        data.append(0x0a)
        try FileHandle.standardOutput.write(contentsOf: data)
    }

    static func measure(_ client: QPeriaptClient, port: UInt16, serverName: String,
                        reconnects: Int) async throws {
        let payloads = [0, 1, 65_536].map { [UInt8](repeating: 0x51, count: $0) }
        // A fresh process's first connection is retained separately. Reconnects
        // still perform full TLS authentication and policy confirmation.
        for index in 0...reconnects {
            let started = DispatchTime.now().uptimeNanoseconds
            let connection = try await client.connect(host: "127.0.0.1", port: port, serverName: serverName)
            let connected = DispatchTime.now().uptimeNanoseconds
            var requests: [UInt64] = []
            for payload in payloads {
                let before = DispatchTime.now().uptimeNanoseconds
                let reply = try await connection.request(payload)
                let after = DispatchTime.now().uptimeNanoseconds
                guard reply == payload else { throw ProbeError.unexpectedResult }
                requests.append(after - before)
            }
            let beforeShutdown = DispatchTime.now().uptimeNanoseconds
            try await connection.shutdown()
            let afterShutdown = DispatchTime.now().uptimeNanoseconds
            // Output follows successful disposal, outside the timed intervals.
            // A later failure preserves the already-emitted raw prefix.
            try emit(ConnectionTiming(index: index, phase: index == 0 ? "first" : "reconnect",
                connect_ns: connected - started, payload_bytes: payloads.map(\.count),
                request_ns: requests, shutdown_ns: afterShutdown - beforeShutdown))
        }
    }

    static func read(_ folder: URL, _ name: String, maximum: Int) throws -> [UInt8] {
        let file = try FileHandle(forReadingFrom: folder.appendingPathComponent(name))
        let data: Data
        do {
            data = try file.read(upToCount: maximum + 1) ?? Data()
            guard !data.isEmpty, data.count <= maximum else { throw ProbeError.unexpectedResult }
        } catch {
            try file.close()
            throw error
        }
        try file.close()
        return Array(data)
    }

    static func policyStore(_ folder: URL, action: String) async throws -> QPeriaptPersistentRuntime {
        let path = folder.appendingPathComponent("client.policy.redb").path
        let policy = try read(folder, "policy.toml", maximum: 65_536)
        let signature = try read(folder, "policy.sig", maximum: 3309)
        let root = try read(folder, "policy.vk", maximum: 1952)
        if action == "provision" {
            return try await .provision(at: path, policy: policy, signature: signature, trustRoot: root)
        }
        guard action == "open" else { throw ProbeError.usage }
        return try await .open(at: path, policy: policy, signature: signature, trustRoot: root)
    }

    static func main() async {
        do { try await run() }
        catch {
            do { try FileHandle.standardError.write(contentsOf: Data("PROBE_FAILURE: \(error)\n".utf8)) }
            catch { exit(2) }
            exit(1)
        }
    }

    static func run() async throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard (5...6).contains(arguments.count), let port = UInt16(arguments[1]) else { throw ProbeError.usage }
        let folder = URL(fileURLWithPath: arguments[0], isDirectory: true)
        let scenario = arguments[2]
        let serverName = arguments[3]
        let reconnects: Int
        if scenario == "measure" {
            guard arguments.count == 6, let count = Int(arguments[5]), (200...1000).contains(count) else {
                throw ProbeError.usage
            }
            reconnects = count
        } else {
            guard arguments.count == 5 else { throw ProbeError.usage }
            reconnects = 0 // Only the explicit measurement scenario consumes this count.
        }
        let setupStarted = DispatchTime.now().uptimeNanoseconds
        if scenario == "store-rollback" {
            do {
                let unexpected = try await policyStore(folder, action: arguments[4])
                try await unexpected.close()
                throw ProbeError.expectedFailureMissing
            } catch let error as QPeriaptSDKError where error.code == -3 {
                print("SWIFT_CONNECTION_PROBE_OK store-rollback")
                return
            }
        }
        let store = try await policyStore(folder, action: arguments[4])
        let runtime = store.runtime
        if scenario == "store-disabled" {
            guard try !runtime.isEnabled(), try runtime.trustedState().prefix(4) == [0, 0, 0, 3] else {
                throw ProbeError.unexpectedResult
            }
            do {
                let unexpected = try runtime.generateKey()
                try unexpected.close()
                throw ProbeError.expectedFailureMissing
            } catch let error as QPeriaptSDKError where error.code == -3 {
                try await store.close()
                print("SWIFT_CONNECTION_PROBE_OK store-disabled")
                return
            }
        }
        var key = try read(folder, "client.key.der", maximum: 16_384)
        defer { for index in key.indices { key[index] = 0 } }
        let limits = QPeriaptConnectionLimits(maxConnections: 1,
            handshakeMilliseconds: scenario == "timeout" ? 150 : 5000,
            requestMilliseconds: scenario == "request-timeout" ? 150 : 5000, idleMilliseconds: 5000)
        let client = try QPeriaptClient(runtime: runtime, certificateDER: read(folder, "client.der", maximum: 65_536),
            privateKeyDER: key, peerCertificateDER: read(folder, "server.der", maximum: 65_536),
            applicationContext: Array("reference-connection-test/v1".utf8), limits: limits)
        switch scenario {
        case "measure":
            try emit(SetupTiming(elapsed_ns: DispatchTime.now().uptimeNanoseconds - setupStarted))
            try await measure(client, port: port, serverName: serverName, reconnects: reconnects)
        case "roundtrip":
            for _ in 0..<2 {
                let connection = try await client.connect(host: "127.0.0.1", port: port, serverName: serverName)
                for count in [0, 1, 65_536] {
                    let payload = [UInt8](repeating: 0x51, count: count)
                    guard try await connection.request(payload) == payload else { throw ProbeError.unexpectedResult }
                }
                try await connection.shutdown()
            }
        case "concurrent":
            let connection = try await client.connect(host: "127.0.0.1", port: port, serverName: serverName)
            let replies = try await withThrowingTaskGroup(of: Bool.self) { group in
                for _ in 0..<2 {
                    group.addTask {
                        do {
                            guard try await connection.request([1, 2, 3]) == [1, 2, 3] else { throw ProbeError.unexpectedResult }
                            return true
                        } catch let error as QPeriaptSDKError where error.code == -17 { return false }
                    }
                }
                var success = 0
                for try await accepted in group { if accepted { success += 1 } }
                return success
            }
            guard replies == 1 else { throw ProbeError.unexpectedResult }
            guard try await connection.request([4]) == [4] else { throw ProbeError.unexpectedResult }
            try await connection.shutdown()
        case "timeout":
            do {
                let unexpected = try await client.connect(host: "127.0.0.1", port: port, serverName: serverName)
                try await unexpected.close()
                throw ProbeError.expectedFailureMissing
            } catch let error as QPeriaptSDKError where error.code == -15 { print("EXPECTED_TIMEOUT") }
        case "cancel":
            // Twice with capacity one: cancellation must release its native
            // connection before the task completes, including a silent peer.
            for _ in 0..<2 {
                let task = Task { try await client.connect(host: "127.0.0.1", port: port, serverName: serverName) }
                try await Task.sleep(nanoseconds: 40_000_000)
                task.cancel()
                do {
                    let unexpected = try await task.value
                    try await unexpected.close()
                    throw ProbeError.expectedFailureMissing
                } catch is CancellationError { print("EXPECTED_CANCELLATION") }
            }
        case "request-timeout":
            let connection = try await client.connect(host: "127.0.0.1", port: port, serverName: serverName)
            do {
                _ = try await connection.request([9])
                throw ProbeError.expectedFailureMissing
            } catch let error as QPeriaptSDKError where error.code == -15 { print("EXPECTED_REQUEST_TIMEOUT") }
            try await connection.close()
        case "request-cancel", "runtime-revoke":
            let connection = try await client.connect(host: "127.0.0.1", port: port, serverName: serverName)
            let task = Task { try await connection.request([9]) }
            try await Task.sleep(nanoseconds: 40_000_000)
            if scenario == "request-cancel" { task.cancel() }
            else { try await store.close() }
            do {
                _ = try await task.value
                throw ProbeError.expectedFailureMissing
            } catch is CancellationError where scenario == "request-cancel" {
                print("EXPECTED_REQUEST_CANCELLATION")
            } catch let error as QPeriaptSDKError where error.code == -9 && scenario == "runtime-revoke" {
                print("EXPECTED_RUNTIME_REVOCATION")
            }
            try await connection.close()
        case "mismatch":
            do {
                let unexpected = try await client.connect(host: "127.0.0.1", port: port, serverName: serverName)
                try await unexpected.close()
                throw ProbeError.expectedFailureMissing
            } catch let error as QPeriaptSDKError where error.code == -18 || error.code == -14 {
                // Driver separately requires the server's BindingMismatch.
                print("EXPECTED_CONFIRMATION_REJECTION")
            }
        case "hostname":
            do {
                let unexpected = try await client.connect(host: "127.0.0.1", port: port, serverName: serverName)
                try await unexpected.close()
                throw ProbeError.expectedFailureMissing
            } catch let error as QPeriaptSDKError where error.code == -14 { print("EXPECTED_TLS_REJECTION") }
        default: throw ProbeError.usage
        }
        try client.close()
        try await store.close()
        print("SWIFT_CONNECTION_PROBE_OK \(scenario)")
    }
}
