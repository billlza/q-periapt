// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity
import CQPCOwner
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

private func hexBytes(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
private func closeRecovery(_ owner: ContinuityRecoveryOwner) throws {
    try owner.close()
    try failure([2]) { try owner.cancel() }
}

/// A deliberate raw-ABI negative control in the test executable only. Ordinary
/// Swift operations below use the public typed owners. Swift exposes no handle
/// conversion with which an application could invoke the wrong owner's methods.
private func checkNativeKindSeparation(_ path: String) throws {
    let bytes = Array(path.utf8)
    func check(_ result: Int32, _ error: qpc_error_v1, expected: Int32) throws {
        try require(result == expected && error.code == result && error.length <= 512 && error.truncated <= 1 &&
                    (result == 0 ? error.length == 0 && error.truncated == 0 : error.length > 0), "native kind negative control")
    }
    for kind in [UInt32(1), 2] {
        var handle: UInt64 = 0, error = qpc_error_v1()
        var options = qpc_open_options_v1(kind: kind, quality: kind == 1 ? 1 : 0, carrier: 0, witness: nil)
        var result = bytes.withUnsafeBufferPointer {
            qpc_owner_v1_prepare_open($0.baseAddress, $0.count, &options, &handle, &error)
        }
        try check(result, error, expected: 0)
        try require(handle != 0, "negative control missing owner")
        let operation = Result {
            result = qpc_owner_v1_finish_open(handle, &error)
            try check(result, error, expected: 0)
            if kind == 1 {
                var header = qpc_closure_header_v1()
                result = qpc_recovery_v1_begin(handle, &header, &error)
                try check(result, error, expected: 6)
            } else {
                let address = Array("127.0.0.1:0".utf8)
                var port: UInt16 = 99
                result = address.withUnsafeBufferPointer {
                    qpc_owner_v1_listen(handle, $0.baseAddress, $0.count, &port, &error)
                }
                try check(result, error, expected: 6)
                try require(port == 0, "cleanup owner acquired listener")
            }
        }
        result = qpc_owner_v1_close(handle, &error)
        do { try check(result, error, expected: 0) }
        catch { throw ProbeFailure.contract("kind control close: \(error); original: \(operation)") }
        try operation.get()
    }
}

private func savedReport(_ files: FixtureRecords) throws -> ClosureReportID {
    let bytes = try files.read("c-loss-report")
    let prefix = Array("QPC-C-LOSS/1\nreport ".utf8)
    try require(bytes.count >= prefix.count + 65 && Array(bytes.prefix(prefix.count)) == prefix &&
                bytes[prefix.count + 64] == 10, "saved report identity")
    guard let text = String(bytes: bytes[prefix.count..<prefix.count + 64], encoding: .utf8) else {
        throw ProbeFailure.contract("saved report encoding")
    }
    return try decode(text)
}

private func snapshot(_ owner: ContinuityRecoveryOwner, files: FixtureRecords, create: Bool) throws -> ClosureReportID {
    let h = try owner.begin()
    try require(h.role == .responder && h.peerGeneration == 1 && h.epochCount <= 4 && h.reservedCount <= 4, "report fixture scope")
    var lines = ["QPC-C-LOSS/1", "report " + hex(h.report),
        "header \(hex(h.session)) \(hexBytes(h.context)) \(hexBytes(h.peerAccount)) \(hexBytes(h.peerDevice)) " +
        "\(h.role.rawValue) \(h.peerGeneration) \(h.confirmedEpoch) \(h.sendingEpoch) \(h.receivingEpoch) " +
        "\(h.pendingEpoch == nil ? 0 : 1) \(h.pendingEpoch ?? 0) \(h.reservedCount) \(h.epochCount)"]
    for i in 0..<h.reservedCount {
        let r = try owner.reservation(at: i)
        lines.append("reserved \(i) \(hex(r.message)) \(r.plaintextBytes) \(r.associatedDataBytes)")
    }
    try failure([1]) { try owner.reservation(at: h.reservedCount) }
    for i in 0..<h.epochCount {
        let p = try owner.epoch(at: i)
        try require(p.unconfirmedCount <= 64 && p.deliveryCount <= 128 && p.skippedCount <= 128, "epoch fixture bounds")
        let resolution: Int, report: String
        switch p.resolution {
        case .unrequested: resolution = 0; report = String(repeating: "0", count: 64)
        case let .pending(id): resolution = 1; report = hex(id)
        case let .acknowledged(id): resolution = 2; report = hex(id)
        }
        lines.append("epoch \(i) \(p.epoch) \(p.acknowledgedBefore) \(p.sent) \(p.consumedBefore) \(p.received) " +
            "\(p.peerSent == nil ? 0 : 1) \(p.peerSent ?? 0) \(resolution) \(report) " +
            "\(p.unconfirmedCount) \(p.deliveryCount) \(p.skippedCount)")
        for j in 0..<p.unconfirmedCount {
            let u = try owner.unconfirmed(epoch: i, at: j)
            lines.append("unconfirmed \(i) \(j) \(hex(u.message)) \(hexBytes(u.ciphertextDigest))")
        }
        for j in 0..<p.deliveryCount {
            let d = try owner.delivery(epoch: i, at: j)
            lines.append("delivery \(i) \(j) \(hex(d.message)) \(d.index) \(d.plaintextBytes)")
        }
        for j in 0..<p.skippedCount { lines.append("skipped \(i) \(j) \(try owner.skippedPosition(epoch: i, at: j))") }
        try failure([1]) { try owner.unconfirmed(epoch: i, at: p.unconfirmedCount) }
        try failure([1]) { try owner.delivery(epoch: i, at: p.deliveryCount) }
        try failure([1]) { try owner.skippedPosition(epoch: i, at: p.skippedCount) }
    }
    try failure([1]) { try owner.epoch(at: h.epochCount) }
    _ = try files.retain("c-loss-report", bytes: Array((lines.joined(separator: "\n") + "\n").utf8), create: create)
    try require(owner.status() == .pending(h.report), "pending report identity")
    return h.report
}

func recover(_ args: [String]) throws {
    try require((2...3).contains(args.count), "recovery arguments")
    let mode = args[0], path = args[1]
    if mode == "recover-kind" {
        try require(args.count == 2, "kind arguments")
        try checkNativeKindSeparation(path)
        try output("operational-owner-not-recovery")
        return
    }
    let owner = try ContinuityRecoveryOwner.open(path: path)
    let count = try owner.sessionCount()
    let files = FixtureRecords(path: path)
    switch mode {
    case "recover-list":
        try require(args.count == 2, "list arguments")
        try output("catalogue:\(count)")
    case "recover-tamper":
        try require(args.count == 2 && count == 1, "tamper setup")
        var archive = try files.read("native-closure-archive")
        try require(archive.count == Int(QPC_CLOSURE_ARCHIVE_BYTES), "archive size")
        try failure([101]) { try owner.select(archive: Array(archive.dropLast())) }
        try require(owner.sessionCount() == 1, "parse error consumed discovery")
        archive[archive.count - 1] ^= 1
        try failure([208]) { try owner.select(archive: archive) }
        try failure([202]) { try owner.sessionCount() }
        try output("tampered-archive-refused")
    case "recover-archive":
        try require(args.count == 2 && count == 0, "archive setup")
        try owner.select(archive: files.read("c-closure-archive"))
        let report = try savedReport(files)
        try require(owner.status() == .closed(report), "archive restored operational state")
        try owner.restoreIndex(); try owner.restoreIndex()
        try require(owner.retire(report: report), "restored row not retired")
        try require(!owner.retire(report: report), "absent row not independently validated")
        try output("archive-closed-metadata-only")
    default:
        try require(args.count == 3 && count == 1, "selection setup")
        let session: SessionID = try decode(args[2])
        try require(owner.session(at: 0) == session, "catalogue hint differs")
        try failure([1]) { try owner.session(at: 1) }
        if mode == "recover-missing" {
            var bytes = session.bytes; bytes[31] ^= 1
            try failure([201]) { try owner.select(session: SessionID(bytes: bytes)) }
            try failure([202]) { try owner.sessionCount() }
            try output("missing-session-refused")
        } else {
            try owner.select(session: session)
            try failure([108]) { try owner.select(session: session) }
            _ = try files.retain("c-closure-archive", bytes: owner.archive(), create: true)
            switch mode {
            case "recover-cancel":
                try require(owner.status() == .open, "already frozen")
                try owner.cancel()
                try failure([302]) { try owner.begin() }
                try require(owner.status() == .open, "cancelled cleanup froze session")
                try failure([302]) { try owner.restoreIndex() }
                try output("cancelled-cleanup-not-frozen")
            case "recover-freeze":
                _ = try snapshot(owner, files: files, create: true)
                exit(77)
            case "recover-ack-crash":
                let report = try snapshot(owner, files: files, create: false)
                var wrong = report.bytes; wrong[0] ^= 1
                try failure([211]) { try owner.acknowledge(report: ClosureReportID(bytes: wrong)) }
                try require(owner.status() == .pending(report), "wrong ACK changed closure")
                try owner.acknowledge(report: report)
                try require(owner.status() == .closed(report), "ACK not closed")
                try failure([112]) { try owner.begin() }
                exit(77)
            case "recover-finish":
                let report = try savedReport(files)
                try require(owner.status() == .closed(report), "unknown ACK not reconciled")
                try owner.acknowledge(report: report)
                try require(owner.retire(report: report), "original row not retired")
                try require(!owner.retire(report: report), "already absent row changed")
                try output("original-report-closed-retired")
            default: throw ProbeFailure.contract("unknown recovery mode")
            }
        }
    }
    try closeRecovery(owner)
}
