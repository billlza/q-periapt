// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity
#if canImport(Darwin)
import Darwin
import MachO
#else
import Glibc
#endif

enum ProbeFailure: Error { case contract(String) }
func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw ProbeFailure.contract(message) }
}
func output(_ text: String) throws {
    try FileHandle.standardOutput.write(contentsOf: Data((text + "\n").utf8))
}
func decode<Tag: Sendable>(_ text: String) throws -> ContinuityID<Tag> {
    let bytes = Array(text.utf8)
    guard bytes.count == 64 else { throw ProbeFailure.contract("ID length") }
    func digit(_ value: UInt8) throws -> UInt8 {
        if (48...57).contains(value) { return value - 48 }
        if (97...102).contains(value) { return value - 87 }
        throw ProbeFailure.contract("noncanonical ID")
    }
    return try ContinuityID(bytes: stride(from: 0, to: 64, by: 2).map {
        try digit(bytes[$0]) * 16 + digit(bytes[$0 + 1])
    })
}
func hex<Tag>(_ id: ContinuityID<Tag>) -> String {
    id.bytes.map { String(format: "%02x", $0) }.joined()
}
func close(_ owner: ContinuityOwner) throws {
    try owner.close()
    try failure([2]) { try owner.cancel() }
}
func failure<T>(_ expected: Set<Int32>, _ action: () throws -> T) throws {
    do { _ = try action() }
    catch let error as ContinuityFailure {
        try require(expected.contains(error.code), "unexpected native status \(error)")
        return
    }
    throw ProbeFailure.contract("failure was accepted")
}
func selfCheck() throws {
    for _ in 0..<128 {
        try failure([203]) { try ContinuityOwner.open(path: "relative", quality: .oneTimeBoth) }
    }
    let pending = try ContinuityOwner.prepare(path: "/absent-continuity-probe", quality: .oneTimeBoth)
    try pending.cancel()
    try failure([302]) { try pending.finishOpen() }
    try close(pending)
    let stale = try ContinuityOwner.prepare(path: "/absent-continuity-probe", quality: .oneTimeBoth)
    try close(stale)
    try failure([2]) { try stale.finishOpen() }
}
func verifyLoadedLibrary() throws {
#if canImport(Darwin)
    guard let expected = ProcessInfo.processInfo.environment["QPERIAPT_EXPECTED_CONTINUITY_LIBRARY"],
          expected.hasPrefix("/") else { throw ProbeFailure.contract("missing installed library identity") }
    var matches: [String] = []
    for index in 0..<_dyld_image_count() {
        guard let pointer = _dyld_get_image_name(index), let name = String(validatingCString: pointer) else {
            throw ProbeFailure.contract("loader image name")
        }
        if URL(fileURLWithPath: name).lastPathComponent == "libq_periapt_continuity_c_consumer.dylib" {
            matches.append(URL(fileURLWithPath: name).resolvingSymlinksInPath().path)
        }
    }
    try require(matches == [URL(fileURLWithPath: expected).resolvingSymlinksInPath().path], "wrong installed native library")
#else
    throw ProbeFailure.contract("this package collector qualifies macOS only")
#endif
}
func waitMarker(_ path: String) throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(10))
    while ContinuousClock.now < deadline {
        let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        if descriptor < 0 {
            guard errno == ENOENT else { throw ProbeFailure.contract("marker open \(errno)") }
            Thread.sleep(forTimeInterval: 0.025)
            continue
        }
        var bytes = [UInt8](repeating: 0, count: 2)
        let count = bytes.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, 2) }
        let code = close(descriptor)
        try require(code == 0 && count == 1 && bytes[0] == 49, "marker contents")
        return
    }
    throw ProbeFailure.contract("marker deadline")
}

@main struct Client {
    static func main() async {
        do { try await run(Array(CommandLine.arguments.dropFirst())) }
        catch {
            do { try FileHandle.standardError.write(contentsOf: Data("Swift consumer failed: \(error)\n".utf8)) }
            catch { exit(2) }
            exit(1)
        }
    }
    static func run(_ args: [String]) async throws {
        try verifyLoadedLibrary()
        guard let command = args.first else { throw ProbeFailure.contract("missing command") }
        if command == "self-check" {
            try require(args.count == 1, "self-check arguments")
            try selfCheck()
            try output("self-check-passed")
            return
        }
        guard args.count >= 2 else { throw ProbeFailure.contract("missing original configuration") }
        if command == "reject-open" {
            try require(args.count == 2, "reject arguments")
            do {
                let owner = try ContinuityOwner.open(path: args[1], quality: .oneTimeBoth)
                try close(owner)
            } catch let error as ContinuityFailure {
                try output("rejected:\(error.code)")
                return
            }
            throw ProbeFailure.contract("invalid binding admitted")
        }
        var owner = try ContinuityOwner.open(path: args[1], quality: .oneTimeBoth)
        switch command {
        case "serve":
            try require(args.count >= 3, "serve arguments")
            try require(args.count == (args[2] == "rekey" ? 4 : 3), "serve arguments")
            try serve(owner, path: args[1], mode: args[2], sessionText: args.count == 4 ? args[3] : nil)
        case "connect":
            try require(args.count == 4, "connect arguments")
            let result = try owner.establish(peer: args[2], request: decode(args[3]))
            try output(hex(result.session))
        case "next":
            try require(args.count == 3, "next arguments")
            try output(hex(owner.nextMessage(session: decode(args[2]))))
        case "status":
            try require(args.count == 4, "status arguments")
            try output(String(owner.status(session: decode(args[2]), message: decode(args[3])).rawValue))
        case "rekey":
            try require(args.count == 4, "rekey arguments")
            try require(owner.rekey(peer: args[2], session: decode(args[3]), target: 1) == 1, "target epoch")
            try output("rekey-1-confirmed")
        case "send", "uncertain-send", "cancel-send", "busy-cancel":
            let busy = command == "busy-cancel"
            let cancelled = command == "cancel-send"
            let uncertain = command == "uncertain-send"
            try require(args.count == (busy ? 6 : 5), "send arguments")
            let session: SessionID = try decode(args[3])
            let message: MessageID = try decode(args[4])
            let current = owner
            let send: @Sendable () throws -> SendResult = {
                try current.send(peer: args[2], session: session, message: message,
                    plaintext: Array("persisted before process exit".utf8), associatedData: Array("owned-service".utf8))
            }
            if cancelled { try owner.cancel() }
            if busy {
                let worker = Task.detached(operation: send)
                do {
                    try waitMarker(args[5])
                    try failure([3]) { try owner.close() }
                    try owner.cancel()
                } catch {
                    // Join the owned invocation even when the test barrier fails.
                    let original = error
                    let cancellation = Result { try owner.cancel() }
                    let outcome = await worker.result
                    throw ProbeFailure.contract("barrier: \(original); cancellation: \(cancellation); worker: \(outcome)")
                }
                let result = await worker.result
                switch result {
                case let .failure(error):
                    guard let error = error as? ContinuityFailure, error.code == 302 else { throw error }
                case .success: throw ProbeFailure.contract("cancelled call reported success")
                }
            } else if cancelled || uncertain {
                try failure(cancelled ? [302] : [303, 309, 310, 311], send)
            } else {
                let result = try send()
                try require(result.consumption == .confirmed, "unconfirmed consumption")
            }
            let expected: MessageStatus = cancelled ? .absent : (busy || uncertain ? .committed : .acknowledged)
            try require(owner.status(session: session, message: message) == expected, "durable message status")
            if busy {
                try close(owner)
                owner = try ContinuityOwner.open(path: args[1], quality: .oneTimeBoth)
                try require(owner.status(session: session, message: message) == .committed, "reopen lost committed work")
            }
            try output(cancelled ? "cancelled-absent" :
                (busy ? "cancelled-committed-reopened" : (uncertain ? "delivery-unknown-committed" : "consumed")))
        default: throw ProbeFailure.contract("unknown command")
        }
        try close(owner)
    }
}
