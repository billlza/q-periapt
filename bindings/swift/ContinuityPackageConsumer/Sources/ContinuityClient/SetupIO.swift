// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Qualification-only phase receipt in the harness-owned probe log.
private func setupIOPhase(_ phase: Int) throws {
    let environment = ProcessInfo.processInfo.environment
    guard environment["QPC_TEST_SYNC_ACTION"] == "io",
          let path = environment["QPC_TEST_SYNC_LOG"], path.hasPrefix("/"),
          !path.utf8.contains(0), (1...4).contains(phase) else {
        throw ProbeFailure.contract("setup I/O phase requires its owned probe")
    }
    let descriptor = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW)
    try require(descriptor >= 0, "setup I/O phase open")
    let result = Result {
        var info = stat()
        try require(fstat(descriptor, &info) == 0 && info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) &&
                    info.st_uid == geteuid() && info.st_mode & 0o777 == 0o600 && info.st_nlink == 1,
                    "setup I/O phase receipt shape")
        let bytes = Array("phase \(phase) 0\n".utf8)
        var used = 0
        while used < bytes.count {
            let count = bytes.withUnsafeBytes { write(descriptor, $0.baseAddress?.advanced(by: used), $0.count - used) }
            if count < 0 && errno == EINTR { continue }
            try require(count > 0, "setup I/O phase write")
            used += count
        }
    }
    if close(descriptor) != 0 { throw ProbeFailure.contract("setup I/O phase close failed; body: \(result)") }
    try result.get()
}

func setupIOActivate(_ path: String, witness: WitnessCarrier) throws {
    guard case .local = witness else { throw ProbeFailure.contract("setup I/O observation requires local original state") }
    let setup = try ContinuitySetup.prepareResume(path: path, witness: witness)
    var successor: ContinuityDevice?
    do {
        try setupIOPhase(1)
        var code: Int32 = 0
        do { try setup.finishOpen() }
        catch let error as ContinuityFailure where error.code == 204 { code = error.code }
        var batch: AccountOperationID?
        if code == 0 {
            try setupIOPhase(2)
            do { successor = try setup.activate() }
            catch let error as ContinuityFailure where error.code == 207 { code = error.code }
        }
        try failure([2]) { try setup.status() }
        try failure([2]) { try setup.prepareStorage() }
        if let device = successor {
            try require(code == 0, "failed setup I/O retained successor")
            batch = try device.nextAccountOperation()
        } else { try require(code == 204 || code == 207, "setup I/O omitted successor") }
        try setupIOPhase(3)
        try setup.close()
        if let device = successor {
            try device.close()
            try failure([2]) { try device.nextAccountOperation() }
        }
        try setupIOPhase(4)
        if let batch { try output("setup-io:0\n\(hex(batch))") }
        else { try output("setup-io:\(code)") }
    } catch {
        let original = error
        let setupDisposal = Result { try setup.close() }
        let deviceDisposal = Result { if let device = successor { try device.close() } }
        throw ProbeFailure.contract("setup I/O observation failed: \(original); setup disposal: \(setupDisposal); device disposal: \(deviceDisposal)")
    }
}
