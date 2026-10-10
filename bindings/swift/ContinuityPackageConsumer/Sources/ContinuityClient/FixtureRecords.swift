// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

private func recordIO(_ operation: String) -> ProbeFailure {
    .contract("fixture record \(operation) failed: errno \(errno)")
}
private func readRecordBytes(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer?, _ count: Int) -> Int {
    read(descriptor, buffer, count)
}
private func withRecordDescriptor<T>(_ descriptor: Int32, _ body: (Int32) throws -> T) throws -> T {
    guard descriptor >= 0 else { throw recordIO("open") }
    let result = Result { try body(descriptor) }
    if close(descriptor) != 0 {
        throw ProbeFailure.contract("fixture record close failed: errno \(errno); body: \(result)")
    }
    return try result.get()
}

/// Test-host durable effect/report store, never a protocol or key store.
/// One no-clobber file contains both effect/accounting and its exact identity.
struct FixtureRecords {
    let path: String
    let maximumBytes: Int
    init(path: String, maximumBytes: Int = 1_048_576) {
        self.path = path; self.maximumBytes = maximumBytes
    }
    private func validate(_ name: String) throws {
        try require((1...8_388_608).contains(maximumBytes), "fixture record capacity")
        try require(!name.isEmpty && name.utf8.count <= 128 && name != "." && name != ".." &&
                    !name.contains("/") && !name.utf8.contains(0), "fixture record name")
    }
    private func read(_ directory: Int32, _ name: String) throws -> [UInt8]? {
        let descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        if descriptor < 0 {
            guard errno == ENOENT else { throw recordIO("open retained record") }
            return nil
        }
        return try withRecordDescriptor(descriptor) { file in
            var info = stat()
            guard fstat(file, &info) == 0 else { throw recordIO("stat record") }
            try require(info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) &&
                        info.st_size > 0 && info.st_size <= maximumBytes, "fixture record shape")
            var bytes = [UInt8](repeating: 0, count: Int(info.st_size) + 1)
            var used = 0
            while used < bytes.count {
                let count = bytes.withUnsafeMutableBytes { readRecordBytes(file, $0.baseAddress?.advanced(by: used), $0.count - used) }
                if count < 0 && errno == EINTR { continue }
                guard count >= 0 else { throw recordIO("read record") }
                if count == 0 { break }
                used += count
            }
            try require(used == info.st_size, "fixture record changed while reading")
            guard fsync(file) == 0 else { throw recordIO("sync record") }
            guard fsync(directory) == 0 else { throw recordIO("sync directory") }
            return Array(bytes.prefix(used))
        }
    }
    func read(_ name: String) throws -> [UInt8] {
        try validate(name)
        return try withRecordDescriptor(open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) { directory in
            guard let bytes = try read(directory, name) else { throw ProbeFailure.contract("original record absent") }
            return bytes
        }
    }
    /// Returns true only for this call's newly published record. Existing bytes
    /// must match exactly; create=false refuses a missing retained original.
    func retain(_ name: String, bytes: [UInt8], create: Bool) throws -> Bool {
        try validate(name)
        try require(!bytes.isEmpty && bytes.count <= maximumBytes, "fixture record length")
        let temporary = ".\(name).\(getpid()).tmp"
        return try withRecordDescriptor(open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) { directory in
            if let old = try read(directory, name) {
                try require(old == bytes, "retained original record conflicts")
                return false
            }
            try require(create, "original retained record unavailable")
            let descriptor = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
            guard descriptor >= 0 else { throw recordIO("create temporary record") }
            let operation = Result {
                try withRecordDescriptor(descriptor) { file in
                    var used = 0
                    while used < bytes.count {
                        let count = bytes.withUnsafeBytes { write(file, $0.baseAddress?.advanced(by: used), $0.count - used) }
                        if count < 0 && errno == EINTR { continue }
                        guard count > 0 else { throw recordIO("write record") }
                        used += count
                    }
                    guard fsync(file) == 0 else { throw recordIO("sync temporary record") }
                }
                let published = linkat(directory, temporary, directory, name, 0) == 0
                if !published && errno != EEXIST { throw recordIO("publish record") }
                guard let retained = try read(directory, name) else { throw ProbeFailure.contract("published record absent") }
                try require(retained == bytes, "published original record conflicts")
                return published
            }
            if unlinkat(directory, temporary, 0) != 0 {
                throw ProbeFailure.contract("temporary record cleanup failed: errno \(errno); operation: \(operation)")
            }
            guard fsync(directory) == 0 else { throw recordIO("sync temporary removal") }
            return try operation.get()
        }
    }
}
