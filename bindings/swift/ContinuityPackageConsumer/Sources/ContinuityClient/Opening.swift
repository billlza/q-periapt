// SPDX-License-Identifier: Apache-2.0 OR MIT
import QPeriaptContinuity

/// Test dispatch over the two public owner types; no raw handle or extra worker
/// exists in the library. The executable joins every worker that it creates.
private enum PreparedInvocation: Sendable {
    case operational(ContinuityOwner), recovery(ContinuityRecoveryOwner)

    func finish() throws {
        switch self {
        case let .operational(owner): try owner.finishOpen()
        case let .recovery(owner): try owner.finishOpen()
        }
    }
    func cancel() throws {
        switch self {
        case let .operational(owner): try owner.cancel()
        case let .recovery(owner): try owner.cancel()
        }
    }
    func close() throws {
        switch self {
        case let .operational(owner): try owner.close()
        case let .recovery(owner): try owner.close()
        }
    }
    func rejectWork(_ code: Int32) throws {
        switch self {
        case let .operational(owner): try failure([code]) { try owner.listen(address: "127.0.0.1:0") }
        case let .recovery(owner): try failure([code]) { try owner.sessionCount() }
        }
    }
    func inspectRecovery() throws {
        if case let .recovery(owner) = self { _ = try owner.sessionCount() }
    }
}

func opening(_ args: [String], witness selected: WitnessCarrier, session: SessionID? = nil) async throws {
    try require(args.count >= 3, "opening arguments")
    let mode = args[0], kind = args[2]
    let cancelled = mode == "opening-cancel"
    let preCancelled = mode == "opening-pre-cancel"
    try require(cancelled || preCancelled || mode == "opening-prepare", "opening mode")
    try require(args.count == (cancelled ? 4 : 3) && (kind == "operational" || kind == "recovery") &&
                (!cancelled || kind == "operational") && (session == nil || kind == "operational"), "opening selection")
    var path = args[1]
    var witness = selected
    let owner: PreparedInvocation
    if kind == "operational" {
        if let session {
            owner = .operational(try ContinuityOwner.prepareReopen(path: path, quality: .oneTimeBoth, session: session, witness: witness))
        } else {
            owner = .operational(try ContinuityOwner.prepare(path: path, quality: .oneTimeBoth, witness: witness))
        }
    } else {
        owner = .recovery(try ContinuityRecoveryOwner.prepare(path: path, witness: witness))
    }
    // Caller configuration is a value. Activation must use the configuration
    // copied at prepare time, even after these caller variables are reassigned.
    path = "changed-after-prepare"
    witness = .signedTCP(address: "changed-after-prepare", timeoutMilliseconds: 0)
    defer { withExtendedLifetime((path, witness)) {} }
    try owner.rejectWork(6)
    let number = kind == "operational" ? 1 : 2
    if preCancelled {
        try owner.cancel()
        try failure([302]) { try owner.finish() }
        try failure([2]) { try owner.finish() }
        try owner.rejectWork(2)
        try output("prepared-pre-cancel:\(number)")
    } else if cancelled {
        let worker = Task.detached { try owner.finish() }
        let beforeCancellation: ContinuousClock.Instant
        do {
            try waitMarker(args[3])
            try failure([3]) { try owner.close() }
            try failure([3]) { try owner.finish() }
            try owner.rejectWork(3)
            beforeCancellation = ContinuousClock.now
            try owner.cancel()
        } catch {
            let original = error
            let cancellation = Result { try owner.cancel() }
            let result = await worker.result
            throw ProbeFailure.contract("opening barrier: \(original); cancellation: \(cancellation); worker: \(result)")
        }
        switch await worker.result {
        case let .failure(error):
            guard let native = error as? ContinuityFailure, native.code == 218 else { throw error }
        case .success: throw ProbeFailure.contract("cancelled activation reported success")
        }
        let milliseconds = try observedCancellationMilliseconds(beforeCancellation.duration(to: ContinuousClock.now))
        try failure([2]) { try owner.finish() }
        try owner.rejectWork(2)
        try output("prepared-cancelled:218:\(milliseconds)")
    } else {
        try owner.finish()
        try failure([6]) { try owner.finish() }
        try owner.inspectRecovery()
        try output("prepared-open:\(number)")
    }
    try owner.close()
    try failure([2]) { try owner.cancel() }
}
