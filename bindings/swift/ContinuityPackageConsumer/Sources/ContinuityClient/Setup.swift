// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity

private final class WeakSetup {
    weak var value: ContinuitySetup?
    init(_ value: ContinuitySetup) { self.value = value }
}
private func closeSetup<T>(_ setup: ContinuitySetup, body: () throws -> T) throws -> T {
    let result: T
    do { result = try body() }
    catch {
        let original = error
        do { try setup.close() }
        catch { throw ProbeFailure.contract("setup failed: \(original); disposal failed: \(error)") }
        throw original
    }
    try setup.close()
    return result
}
private func transferSetup(_ path: String, _ witness: WitnessCarrier) throws -> (ContinuityDevice, WeakSetup) {
    let setup = try ContinuitySetup.resume(path: path, witness: witness)
    let weak = WeakSetup(setup)
    let device = try closeSetup(setup) {
        let device = try setup.activate()
        do {
            try setup.close()
            try failure([2]) { try setup.status() }
            try failure([2]) { try setup.prepareStorage() }
            try failure([2]) { try setup.activate() }
            try failure([2]) { try setup.cancel() }
            return device
        } catch {
            let original = error
            do { try device.close() }
            catch { throw ProbeFailure.contract("transfer failed: \(original); successor disposal failed: \(error)") }
            throw original
        }
    }
    return (device, weak)
}

func setupCommand(_ args: [String], witness: WitnessCarrier) async throws {
    try require((2...3).contains(args.count), "setup arguments")
    let mode = args[0], path = args[1]
    let cancelled = mode == "setup-cancel", preCancelled = mode == "setup-pre-cancel"
    try require(["setup-create", "setup-status", "setup-storage", "setup-activate", "setup-pre-cancel", "setup-cancel"].contains(mode), "setup selection")
    var expected: Int32?
    if cancelled {
        try require(args.count == 3, "setup cancellation barrier missing")
        if case .local = witness { throw ProbeFailure.contract("setup cancellation requires a witness") }
    }
    else if args.count == 3 {
        guard let value = Int32(args[2]), (1...10000).contains(value) else { throw ProbeFailure.contract("setup expected status") }
        expected = value
    }
    if mode == "setup-activate" && expected == nil {
        let (device, old) = try transferSetup(path, witness)
        let batch: AccountOperationID
        do {
            try require(old.value == nil, "old setup wrapper retained after transfer")
            batch = try device.nextAccountOperation()
        } catch {
            let original = error
            do { try device.close() }
            catch { throw ProbeFailure.contract("successor failed: \(original); disposal failed: \(error)") }
            throw original
        }
        try device.close()
        try failure([2]) { try device.nextAccountOperation() }
        try output("setup-activated\n\(hex(batch))\nsetup-transfer:closed-alias-released-device-live")
        return
    }
    let setup = try mode == "setup-create" || preCancelled ?
        ContinuitySetup.prepareCreate(path: path, witness: witness) : ContinuitySetup.prepareResume(path: path, witness: witness)
    if cancelled {
        do { try setup.finishOpen() }
        catch {
            let original = error
            do { try setup.close() }
            catch { throw ProbeFailure.contract("setup open failed: \(original); disposal failed: \(error)") }
            throw original
        }
        let worker = Task.detached { try setup.activate() }
        let before: ContinuousClock.Instant
        do {
            try waitMarker(args[2])
            try failure([3]) { try setup.close() }
            try failure([3]) { try setup.status() }
            try failure([3]) { try setup.prepareStorage() }
            try failure([3]) { try setup.activate() }
            before = ContinuousClock.now
            try setup.cancel()
        } catch {
            let original = error
            let cancellation = Result { try setup.cancel() }
            let result = await worker.result
            if case let .success(device) = result { try device.close() }
            let disposal = Result { try setup.close() }
            throw ProbeFailure.contract("setup barrier: \(original); cancellation: \(cancellation); worker: \(result); disposal: \(disposal)")
        }
        let result = await worker.result
        try closeSetup(setup) {
            switch result {
            case let .failure(error):
                guard let native = error as? ContinuityFailure, native.code == 218 else { throw error }
            case let .success(device):
                try device.close()
                throw ProbeFailure.contract("cancelled setup activation reported success")
            }
            let elapsed = try observedCancellationMilliseconds(before.duration(to: ContinuousClock.now))
            try failure([2]) { try setup.status() }
            try output("setup-cancelled:218:\(elapsed)")
        }
        return
    }
    let text = try closeSetup(setup) {
        func operation() throws -> String {
            if preCancelled { try setup.cancel() }
            try setup.finishOpen()
            if mode == "setup-activate" {
                let device = try setup.activate()
                try device.close()
                throw ProbeFailure.contract("expected refused setup activation succeeded")
            }
            if mode == "setup-storage" {
                switch try setup.prepareStorage() {
                case let .local(journal):
                    return "setup-prepared:1\n\(hex(journal))\n\(String(repeating: "0", count: 192))\n\(String(repeating: "0", count: 64))"
                case let .requiresEnrollment(genesis):
                    let subject = genesis.subject.map { String(format: "%02x", $0) }.joined()
                    let digest = genesis.imageDigest.map { String(format: "%02x", $0) }.joined()
                    return "setup-prepared:2\n\(hex(genesis.journal))\n\(subject)\n\(digest)"
                }
            }
            let status = try setup.status()
            return "setup-status:\(status.phase.rawValue)\n\(hex(status.journal))"
        }
        if let expected {
            try failure([expected]) { try operation() }
            return "setup-refused:\(expected)"
        }
        return try operation()
    }
    try output(text)
}
