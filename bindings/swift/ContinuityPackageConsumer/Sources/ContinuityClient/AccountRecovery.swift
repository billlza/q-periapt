// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity

private func reconciledAccount(_ owner: ContinuityRecoveryOwner, operation: AccountOperationID,
                               files: FixtureRecords, retire: Bool) throws -> String {
    let result = try owner.reconcileAccount()
    try require(result.operation == operation, "original reconciliation scope")
    var lines = ["QPC-C-RECONCILIATION/1", "batch " + hex(result.operation), "members \(result.members.count)"]
    for (index, member) in result.members.enumerated() {
        lines.append("member \(index) \(hexBytes(member.device)) \(hex(member.session)) \(hex(member.message)) \(member.state.rawValue)")
    }
    let text = lines.joined(separator: "\n")
    if retire {
        try require(result.members.allSatisfy { $0.state != .committed && $0.state != .resolutionPending },
                    "unsettled original member")
        let bytes = Array((text + "\n").utf8)
        _ = try files.retain("c-account-reconciliation", bytes: bytes, create: true)
        _ = try files.retain("c-account-reconciliation", bytes: bytes, create: false)
        try owner.retireAccount(); try owner.retireAccount()
        try require(owner.accountCleanupStatus() == .retired, "original batch not retired")
        try failure([112]) { try owner.reconcileAccount() }
    } else {
        try failure([215]) { try owner.retireAccount() }
    }
    return text
}

private func accountSnapshot(_ owner: ContinuityRecoveryOwner, operation: AccountOperationID,
                             files: FixtureRecords, create: Bool) throws -> AccountAbandonmentID {
    let h = try owner.beginAccountCleanup()
    try require(h.operation == operation && h.memberCount <= 32, "account report scope")
    var lines = ["QPC-C-ACCOUNT-LOSS/1", "batch " + hex(h.operation), "report " + hex(h.report),
                 "members \(h.memberCount)"]
    for member in 0..<h.memberCount {
        let m = try owner.accountMember(at: member)
        lines.append("member \(member) \(hexBytes(m.device)) \(hexBytes(m.context)) \(hex(m.session)) " +
            "\(m.role.rawValue) \(m.generation) \(m.confirmedEpoch) \(m.sendingEpoch) \(m.receivingEpoch) " +
            "\(m.pendingEpoch == nil ? 0 : 1) \(m.pendingEpoch ?? 0) \(m.epochCount)")
        let r = try owner.accountReservation(member: member)
        lines.append("reserved \(member) \(hex(r.message)) \(r.plaintextBytes) \(r.associatedDataBytes)")
        for i in 0..<m.epochCount {
            let p = try owner.accountEpoch(member: member, at: i)
            try require(p.unconfirmedCount <= 64 && p.deliveryCount <= 128 && p.skippedCount <= 128,
                        "account epoch fixture bounds")
            let resolution: Int, report: String
            switch p.resolution {
            case .unrequested: resolution = 0; report = String(repeating: "0", count: 64)
            case let .pending(id): resolution = 1; report = hex(id)
            case let .acknowledged(id): resolution = 2; report = hex(id)
            }
            lines.append("epoch \(member) \(i) \(p.epoch) \(p.acknowledgedBefore) \(p.sent) \(p.consumedBefore) \(p.received) " +
                "\(p.peerSent == nil ? 0 : 1) \(p.peerSent ?? 0) \(resolution) \(report) " +
                "\(p.unconfirmedCount) \(p.deliveryCount) \(p.skippedCount)")
            for j in 0..<p.unconfirmedCount {
                let u = try owner.accountUnconfirmed(member: member, epoch: i, at: j)
                lines.append("unconfirmed \(member) \(i) \(j) \(hex(u.message)) \(hexBytes(u.ciphertextDigest))")
            }
            for j in 0..<p.deliveryCount {
                let d = try owner.accountDelivery(member: member, epoch: i, at: j)
                lines.append("delivery \(member) \(i) \(j) \(hex(d.message)) \(d.index) \(d.plaintextBytes)")
            }
            for j in 0..<p.skippedCount {
                lines.append("skipped \(member) \(i) \(j) \(try owner.accountSkippedPosition(member: member, epoch: i, at: j))")
            }
            try failure([1]) { try owner.accountUnconfirmed(member: member, epoch: i, at: p.unconfirmedCount) }
            try failure([1]) { try owner.accountDelivery(member: member, epoch: i, at: p.deliveryCount) }
            try failure([1]) { try owner.accountSkippedPosition(member: member, epoch: i, at: p.skippedCount) }
        }
        try failure([1]) { try owner.accountEpoch(member: member, at: m.epochCount) }
    }
    try failure([1]) { try owner.accountMember(at: h.memberCount) }
    try failure([1]) { try owner.accountReservation(member: h.memberCount) }
    try failure([1]) { try owner.accountEpoch(member: h.memberCount, at: 0) }
    try failure([1]) { try owner.accountUnconfirmed(member: h.memberCount, epoch: 0, at: 0) }
    try failure([1]) { try owner.accountDelivery(member: h.memberCount, epoch: 0, at: 0) }
    try failure([1]) { try owner.accountSkippedPosition(member: h.memberCount, epoch: 0, at: 0) }
    let bytes = Array((lines.joined(separator: "\n") + "\n").utf8)
    try require(bytes.count <= 1048576, "account report size")
    _ = try files.retain("c-account-loss-report", bytes: bytes, create: create)
    try require(owner.accountCleanupStatus() == .abandoning(h.report), "account pending report identity")
    return h.report
}

private func savedAccountReport(_ files: FixtureRecords, operation: AccountOperationID) throws -> AccountAbandonmentID {
    let bytes = try files.read("c-account-loss-report")
    let prefix = Array(("QPC-C-ACCOUNT-LOSS/1\nbatch " + hex(operation) + "\nreport ").utf8)
    try require(bytes.count >= prefix.count + 65 && Array(bytes.prefix(prefix.count)) == prefix &&
                bytes[prefix.count + 64] == 10, "saved account report identity")
    guard let text = String(bytes: bytes[prefix.count..<prefix.count + 64], encoding: .utf8) else {
        throw ProbeFailure.contract("saved account report encoding")
    }
    return try decode(text)
}

func recoverAccount(_ args: [String], witness: WitnessCarrier) throws {
    try require(args.count == 3, "account recovery arguments")
    let mode = args[0], path = args[1]
    let operation: AccountOperationID = try decode(args[2])
    let owner = try ContinuityRecoveryOwner.open(path: path, witness: witness)
    if mode == "recover-account-reject" {
        let code = try refusal { try owner.select(account: operation) }
        try require([216, 211, 218].contains(code), "account witness refusal differs")
        try failure([202]) { try owner.sessionCount() }
        try closeRecovery(owner)
        try output("account-selection-refused:\(code)")
        return
    }
    if mode == "recover-account-retired" || mode == "recover-account-absent" {
        let expected: Int32 = mode == "recover-account-retired" ? 112 : 201
        try failure([expected]) { try owner.select(account: operation) }
        try failure([202]) { try owner.sessionCount() }
        try closeRecovery(owner)
        try output("account-selection-refused:\(expected)")
        return
    }
    try owner.select(account: operation)
    try failure([108]) { try owner.sessionCount() }
    try failure([108]) { try owner.begin() }
    try failure([108]) { try owner.restoreIndex() }
    try failure([108]) { try owner.accountMember(at: 0) }
    let current = try owner.accountCleanupStatus()
    let files = FixtureRecords(path: path)
    let response: String
    switch mode {
    case "recover-account-results", "recover-account-settled-retire":
        response = try reconciledAccount(owner, operation: operation, files: files,
            retire: mode == "recover-account-settled-retire")
    case "recover-account-committed":
        try require(current == .committed, "committed account fixture missing")
        try failure([211]) { try owner.beginAccountCleanup() }
        try failure([215]) { try owner.retireAccount() }
        try require(owner.accountCleanupStatus() == .committed, "committed account was relabeled")
        response = "account-committed-not-abandoned"
    case "recover-account-witness-freeze":
        try require(current == .reserved, "account reservation missing")
        try failure([218]) { try owner.beginAccountCleanup() }
        response = "account-freeze-outcome-unavailable"
    case "recover-account-freeze", "recover-account-freeze-reconcile":
        let previous: AccountAbandonmentID?
        if mode == "recover-account-freeze-reconcile" {
            guard case let .abandoning(id) = current else { throw ProbeFailure.contract("unknown freeze not reconciled") }
            previous = id
        } else {
            try require(current == .reserved, "account reservation missing")
            previous = nil
        }
        try failure([215]) { try owner.retireAccount() }
        let report = try accountSnapshot(owner, operation: operation, files: files, create: true)
        if let previous { try require(previous == report, "unknown freeze report changed") }
        var wrong = report.bytes; wrong[0] = report.bytes[0] == 1 ? 2 : 1
        try failure([211]) { try owner.acknowledgeAccount(report: AccountAbandonmentID(bytes: wrong)) }
        try require(owner.accountCleanupStatus() == .abandoning(report), "wrong account report changed state")
        try owner.cancel()
        try failure([302]) { try owner.acknowledgeAccount(report: report) }
        try failure([302]) { try owner.retireAccount() }
        _ = try owner.accountMember(at: 0)
        response = "account-frozen:" + hex(report)
    case "recover-account-witness-ack":
        guard case .abandoning = current else { throw ProbeFailure.contract("account frozen state missing") }
        let report = try accountSnapshot(owner, operation: operation, files: files, create: false)
        try failure([218]) { try owner.acknowledgeAccount(report: report) }
        response = "account-acknowledgement-outcome-unavailable"
    case "recover-account-ack-reconcile":
        let report = try savedAccountReport(files, operation: operation)
        try require(current == .abandoned(report), "unknown acknowledgement changed report")
        try owner.acknowledgeAccount(report: report); try owner.acknowledgeAccount(report: report)
        try require(owner.accountCleanupStatus() == .abandoned(report), "account acknowledgement identity")
        response = "account-acknowledged:" + hex(report)
    case "recover-account-ack":
        guard case .abandoning = current else { throw ProbeFailure.contract("account frozen state missing") }
        let report = try accountSnapshot(owner, operation: operation, files: files, create: false)
        try owner.acknowledgeAccount(report: report); try owner.acknowledgeAccount(report: report)
        try require(owner.accountCleanupStatus() == .abandoned(report), "account acknowledgement identity")
        response = "account-acknowledged:" + hex(report)
    case "recover-account-retire-reconcile":
        _ = try savedAccountReport(files, operation: operation)
        try require(current == .retired, "unknown retirement not reconciled")
        try owner.retireAccount(); try owner.retireAccount()
        try require(owner.accountCleanupStatus() == .retired, "retired account changed")
        try failure([112]) { try owner.beginAccountCleanup() }
        response = "account-retired"
    case "recover-account-witness-retire":
        let report = try savedAccountReport(files, operation: operation)
        try require(current == .abandoned(report), "account terminal report differs")
        try failure([218]) { try owner.retireAccount() }
        response = "account-retirement-outcome-unavailable"
    case "recover-account-retire":
        let report = try savedAccountReport(files, operation: operation)
        try require(current == .abandoned(report), "account terminal report differs")
        try owner.retireAccount(); try owner.retireAccount()
        try require(owner.accountCleanupStatus() == .retired, "account retirement not reconciled")
        try failure([112]) { try owner.beginAccountCleanup() }
        response = "account-retired"
    default: throw ProbeFailure.contract("unknown account recovery mode")
    }
    try closeRecovery(owner)
    try output(response)
}
