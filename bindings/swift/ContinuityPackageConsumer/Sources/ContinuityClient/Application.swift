// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

private func ioFailure(_ operation: String) -> ProbeFailure {
    .contract("application \(operation) failed: errno \(errno)")
}
private func withDescriptor<T>(_ descriptor: Int32, _ body: (Int32) throws -> T) throws -> T {
    guard descriptor >= 0 else { throw ioFailure("open") }
    let result = Result { try body(descriptor) }
    if close(descriptor) != 0 {
        throw ProbeFailure.contract("application close failed: errno \(errno); body: \(result)")
    }
    return try result.get()
}

/// Test-application transaction only; no cryptographic/protocol state is implemented here.
/// Effect and deduplication bytes share one exclusive name and are synced before success.
final class Application {
    let path: String
    var calls = 0
    var created = 0
    init(path: String) { self.path = path }

    private func existing(_ directory: Int32, _ name: String, _ expected: [UInt8]) throws -> Bool {
        let descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        if descriptor < 0 {
            guard errno == ENOENT else { throw ioFailure("open existing effect") }
            return false
        }
        return try withDescriptor(descriptor) { file in
            var info = stat()
            guard fstat(file, &info) == 0 else { throw ioFailure("stat effect") }
            try require(info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) && info.st_size == expected.count, "application effect shape")
            var bytes = [UInt8](repeating: 0, count: expected.count + 1)
            var used = 0
            while used < bytes.count {
                let count = bytes.withUnsafeMutableBytes { read(file, $0.baseAddress?.advanced(by: used), $0.count - used) }
                if count < 0 && errno == EINTR { continue }
                guard count >= 0 else { throw ioFailure("read effect") }
                if count == 0 { break }
                used += count
            }
            try require(used == expected.count && Array(bytes.prefix(used)) == expected, "application effect conflicts with original ID")
            guard fsync(file) == 0 else { throw ioFailure("sync effect") }
            guard fsync(directory) == 0 else { throw ioFailure("sync effect directory") }
            return true
        }
    }

    func persist(_ delivery: ReceivedMessage) throws {
        try require(delivery.plaintext == Array("persisted before process exit".utf8), "application payload differs")
        let bytes = delivery.session.bytes + delivery.message.bytes + delivery.plaintext
        let name = "application-" + hex(delivery.message)
        let temporary = ".\(name).\(getpid()).tmp"
        try withDescriptor(open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) { directory in
            if try existing(directory, name, bytes) { return }
            let descriptor = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
            guard descriptor >= 0 else { throw ioFailure("create temporary effect") }
            let operation = Result {
                try withDescriptor(descriptor) { file in
                    var used = 0
                    while used < bytes.count {
                        let count = bytes.withUnsafeBytes { write(file, $0.baseAddress?.advanced(by: used), $0.count - used) }
                        if count < 0 && errno == EINTR { continue }
                        guard count > 0 else { throw ioFailure("write effect") }
                        used += count
                    }
                    guard fsync(file) == 0 else { throw ioFailure("sync temporary effect") }
                }
                if linkat(directory, temporary, directory, name, 0) == 0 { created += 1 }
                else if errno != EEXIST { throw ioFailure("publish effect") }
                try require(existing(directory, name, bytes), "published effect is absent")
            }
            if unlinkat(directory, temporary, 0) != 0 {
                throw ProbeFailure.contract("temporary effect cleanup failed: errno \(errno); operation: \(operation)")
            }
            guard fsync(directory) == 0 else { throw ioFailure("sync temporary removal") }
            try operation.get()
        }
    }
}

func serve(_ owner: ContinuityOwner, path: String, mode: String, sessionText: String?) throws {
    try require(["bootstrap", "message", "fail-before", "uncertain", "crash-after", "rekey", "pre-cancel", "deadline"].contains(mode), "unknown server mode")
    let application = Application(path: path)
    let port = try owner.listen(address: "127.0.0.1:0")
    try output("listening:\(port)")
    try failure([108]) { try owner.listen(address: "127.0.0.1:0") }
    if mode == "rekey" {
        guard let sessionText else { throw ProbeFailure.contract("missing rekey session") }
        try require(owner.serveRekey(session: decode(sessionText)) == 1, "server rekey target")
        try output("server-rekey-1")
        return
    }
    if mode == "pre-cancel" { try owner.cancel() }
    do {
        let event = try owner.serve { delivery in
            application.calls += 1
            try failure([3]) { try owner.close() }
            if mode == "fail-before" { throw try ApplicationCommitRefusal(status: 17, reason: "before application commit") }
            try application.persist(delivery)
            if mode == "uncertain" { throw try ApplicationCommitRefusal(status: 29, reason: "application commit outcome unknown") }
            if mode == "crash-after" { exit(77) }
        }
        try require(mode == "bootstrap" || mode == "message", "failure reported consumption")
        switch event {
        case let .established(session):
            try output("served:1:0:\(application.calls):\(application.created)")
            try output(hex(session)); try output(String(repeating: "0", count: 64))
        case let .consumed(session, message, duplicate):
            try output("served:2:\(duplicate ? 1 : 0):\(application.calls):\(application.created)")
            try output(hex(session)); try output(hex(message))
        }
    } catch let error as ContinuityApplicationFailure {
        guard let native = error.nativeError as? ContinuityFailure,
              let original = error.applicationError as? ApplicationCommitRefusal else { throw error }
        try require(native.code == 308 && application.calls == 1, "callback failure native outcome")
        let expected: Int32 = mode == "fail-before" ? 17 : 29
        try require((mode == "fail-before" || mode == "uncertain") && original.status == expected &&
                    native.message.contains("callback returned \(expected);"), "callback failure cause replaced")
        try output("application-failed:\(application.calls):\(application.created)")
    } catch let error as ContinuityFailure {
        try require(application.calls == 0, "cancelled/deadline server invoked application")
        if mode == "pre-cancel" && error.code == 302 { try output("server-cancelled") }
        else if mode == "deadline" && error.code == 303 { try output("server-deadline") }
        else { throw error }
    }
}
