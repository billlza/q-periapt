// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity

func rootCommand(_ args: [String]) throws {
    try require(args.count == 6 || args.count == 8, "root arguments")
    let parts = args[0].split(separator: ":", omittingEmptySubsequences: false)
    try require(parts.count == 1 || parts.count == 2, "root route")
    guard let last = parts.last else { throw ProbeFailure.contract("missing root mode") }
    let route = parts.count == 1 ? "original" : String(parts[0]), mode = String(last)
    try require(["original", "transition", "adoption"].contains(route), "root recovery route")
    let traffic = mode.hasPrefix("traffic-")
    try require(args.count == (traffic ? 8 : 6), "root traffic arguments")
    let input = try RootInputs(args), publicPath = args[1]
    try rootThreadObservation(publicPath, mode)
    if mode == "verify" {
        let (device, retained) = try rootDeviceAfterControllerRelease(input, route: route)
        try require(!retained(), "successor retained its root controller through ARC")
        try failure([202]) { try device.nextPublication() }
        try device.close()
        try rootNumber(publicPath, "arc-revokes-successor", 1)
        try output("root-stage-pass:" + mode); return
    }
    let root = try ContinuityAccountAuthority.prepareOpen(path: input.registryPath, trust: input.trust)
    try root.finishOpen()
    if mode == "traffic-authorize-peer" {
        try rootAuthorizePeer(root, input: input, peer: args[6])
        try root.close(); try output("root-stage-pass:" + mode); return
    }
    var successor: ContinuityDevice?
    if mode == "begin" {
        let enrollment = try ContinuityEnrollment.prepareResume(path: input.oldPath, intent: input.original, witness: input.witness)
        try enrollment.finishOpen()
        try enrollment.selectAccountAuthority(root, checkpoint: input.scope.checkpoint)
        let device = try enrollment.activate(); try enrollment.close()
        try root.beginRootReplacement(device: device, scope: input.scope, plan: input.plan)
        try failure([2]) { try device.nextPublication() }; try device.close()
    } else { try input.resume(root, route: route) }
    let state = try root.rootReplacementState()
    switch mode {
    case "begin", "preparing": try require(state == .preparing, "original root preparation")
    case "freeze", "freeze-retry", "freeze-original":
        let proposal = try root.bindRootFreeze(receipt: input.records.read("freeze-receipt", maximum: 131072))
        if mode == "freeze-retry" {
            try require(proposal.bytes == input.records.read("bound-proposal", maximum: 65536), "original proposal changed")
        } else { try input.records.publish(mode == "freeze" ? "bound-proposal" : "original-bound-proposal", proposal.bytes) }
    case "transition", "transition-retry":
        let proposal = try root.transitionRoot(input.transition())
        if mode == "transition" { try input.records.publish("bound-proposal", proposal.bytes) }
        else { try require(proposal.bytes == input.records.read("bound-proposal", maximum: 65536), "transition proposal changed") }
    case "adopt", "adopt-retry": try input.checkpoint(root.adoptRoot(input.adoption()))
    case "retain", "retain-retry": try input.checkpoint(root.retainRootRetirement(receipt: input.records.read("retirement-receipt", maximum: 131072)))
    default:
        try require(state == .committed, "cleanup without committed root")
        let enrollment = try ContinuityEnrollment.prepareResume(path: input.targetPath, intent: input.target, witness: input.witness)
        try enrollment.finishOpen()
        if mode == "activation-unknown" {
            try failure([218]) { try root.activateRootSuccessor(enrollment) }
            try failure([2]) { try root.rootReplacementState() }
            try failure([2]) { try enrollment.status() }
            try enrollment.close(); try root.close(); try output("root-stage-pass:" + mode); return
        }
        let device = try root.activateRootSuccessor(enrollment); try enrollment.close(); successor = device
        if traffic { try rootTraffic(device, input: input, mode: mode, peerPath: args[6], address: args[7]) }
        else {
            let before = try device.nextPublication()
            try rootCleanup(root, records: input.records, mode: mode)
            try require(before == device.nextPublication(), "historical cleanup changed successor publication")
        }
    }
    if ["begin", "freeze", "freeze-original", "transition", "adopt", "retain", "inventory", "report", "prepare-ack", "journal", "signer"].contains(mode) {
        try rootPause(publicPath, mode)
    }
    try root.close()
    if let successor {
        try failure([202]) { try successor.nextPublication() }
        try successor.close()
    }
    try output("root-stage-pass:" + mode)
}

private func rootCleanup(_ root: ContinuityAccountAuthority, records: EnrollmentInputs, mode: String) throws {
    switch mode {
    case "inventory": try records.publish("inventory", root.retiredInventory().bytes)
    case "prepare-report": try records.publish("report-proposal", root.prepareRetiredReport(inventoryReceipt: records.read("inventory-receipt", maximum: 3690)).bytes)
    case "report", "prepare-ack":
        let inventory = try records.read("inventory-receipt", maximum: 3690), reportReceipt = try records.read("report-receipt", maximum: 3730)
        let report = try root.loadRetiredReport(inventoryReceipt: inventory, reportReceipt: reportReceipt)
        if mode == "report" { try records.publish("host-report", report.canonicalBytes) }
        else {
            let original = try records.read("host-report", maximum: 8388608)
            try require(original == report.canonicalBytes, "retained host report changed")
            let ack = try root.prepareRetiredAcknowledgement(inventoryReceipt: inventory, reportReceipt: reportReceipt, recordedReport: original)
            try require(ack.bytes == records.read("report-proposal", maximum: 353), "ACK changed original report identity")
        }
    case "journal":
        try root.eraseRetiredJournal(hostAcknowledgement: records.read("host-ack", maximum: 3730))
        try require(root.retiredJournalState() == .erased, "old journal not erased")
    case "signer":
        try root.prepareRetiredSignerErasure(hostAcknowledgement: records.read("host-ack", maximum: 3730))
        try root.eraseRetiredSigner()
    case "verify": break
    default: throw ProbeFailure.contract("unknown root cleanup stage")
    }
    if mode == "signer" || mode == "verify" {
        try require(root.retiredSignerState() == .erased && root.retiredJournalState() == .erased, "old signer/journal erasure absent")
    }
}

// Only a weak observation escapes with the successor. Final ARC release of the
// controller must revoke that still-reachable successor, without an explicit close.
private func rootDeviceAfterControllerRelease(_ input: RootInputs, route: String) throws -> (ContinuityDevice, () -> Bool) {
    let root = try ContinuityAccountAuthority.prepareOpen(path: input.registryPath, trust: input.trust)
    let retained = { [weak root] in root != nil }
    try root.finishOpen(); try input.resume(root, route: route)
    try require(root.rootReplacementState() == .committed, "ARC check requires committed root")
    let enrollment = try ContinuityEnrollment.prepareResume(path: input.targetPath, intent: input.target, witness: input.witness)
    try enrollment.finishOpen()
    let device = try root.activateRootSuccessor(enrollment); try enrollment.close()
    let before = try device.nextPublication()
    try rootCleanup(root, records: input.records, mode: "verify")
    try require(before == device.nextPublication(), "ARC cleanup changed successor publication")
    return (device, retained)
}
