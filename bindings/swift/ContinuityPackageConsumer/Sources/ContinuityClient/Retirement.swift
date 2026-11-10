// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Actual Swift cleanup processes. Replacement approval and fresh-generation TLS
/// remain in the independently checking native harness, not this consumer.
func retirementCommand(_ args: [String]) throws {
    try require(args.count == 3, "retirement arguments")
    let path = args[1], mode = args[2]
    let records = FixtureRecords(path: path, maximumBytes: 8_388_608)
    func exact(_ name: String, _ count: Int) throws -> [UInt8] {
        let value = try records.read(name)
        try require(value.count == count, "retirement input width: \(name)")
        return value
    }
    func counter(_ bytes: ArraySlice<UInt8>) -> UInt64 { bytes.reduce(0) { ($0 << 8) | UInt64($1) } }
    func publish(_ name: String, _ bytes: [UInt8]) throws {
        try require(records.retain(name, bytes: bytes, create: true), "retirement output exists: \(name)")
    }
    let process = UInt64(getpid())
    try publish("retirement-process-" + mode, (0..<8).map { UInt8(truncatingIfNeeded: process >> (8 * (7 - $0))) })
    let validity = try exact("enrollment-validity", 16)
    let intent = try EnrollmentIntent(root: exact("local-root", 1985), device: exact("local-device", 16),
        generation: counter(exact("local-generation", 8)[...]), family: exact("family", 32),
        validFrom: counter(validity[..<8]), validUntil: counter(validity[8...]))
    let authority = try RetiredEnrollmentAuthority(witness: exact("witness-id", 32),
        publicKey: exact("witness-public", 1985), replacement: records.read("retirement-proposal"),
        subject: exact("witness-subject", 96), receipt: exact("retirement-receipt", 3754))
    func openOwner() throws -> ContinuityRetiredEnrollment {
        try ContinuityRetiredEnrollment.open(path: path, intent: intent, authority: authority)
    }
    func expected(_ proposal: RetiredReportProposal?) throws {
        guard let proposal else { throw ProbeFailure.contract("retirement proposal absent") }
        let original = try exact("retirement-report-proposal", 353)
        try require(proposal.bytes == original && proposal.report.bytes == Array(original.suffix(32)), "retirement proposal changed")
    }
    func prepareAck(_ owner: ContinuityRetiredEnrollment) throws {
        try expected(owner.prepareAcknowledgement(inventoryReceipt: exact("retirement-inventory-receipt", 3690),
            reportReceipt: exact("retirement-report-receipt", 3730), recordedReport: records.read("retirement-host-report")))
        try expected(owner.acknowledgementProposal())
    }
    var owner = try openOwner()
    switch mode {
    case "inventory":
        try publish("retirement-inventory", owner.inventory().bytes)
        do { _ = try owner.prepareReport(inventoryReceipt: [UInt8](repeating: 0, count: 3689))
            throw ProbeFailure.contract("short retirement receipt accepted")
        } catch let error as ContinuityBoundaryError {
            try require(error == .inputLength, "short receipt failed at a different boundary")
        }
        _ = try owner.inventory()
        try failure([101]) { try owner.prepareReport(inventoryReceipt: [UInt8](repeating: 0, count: 3690)) }
        try failure([2]) { try owner.inventory() }
        try owner.close()
        owner = try openOwner()
        try owner.cancel()
        try failure([302]) { try owner.inventory() }
        let pending = try ContinuityRetiredEnrollment.prepareOpen(path: path, intent: intent, authority: authority)
        try failure([6]) { try pending.inventory() }
        try pending.cancel()
        try failure([302]) { try pending.finishOpen() }
        try pending.close()
    case "prepare-report":
        let proposal = try owner.prepareReport(inventoryReceipt: exact("retirement-inventory-receipt", 3690))
        try publish("retirement-report-proposal", proposal.bytes)
        try expected(owner.reportProposal())
    case "report", "report-reopen":
        let report = try owner.loadReport(inventoryReceipt: exact("retirement-inventory-receipt", 3690),
            reportReceipt: exact("retirement-report-receipt", 3730))
        let original = try exact("retirement-report-proposal", 353)
        try require(report.viewCount == 1 && report.report.bytes == Array(original.suffix(32)), "retirement report identity")
        if mode == "report" {
            try publish("retirement-host-report", report.canonicalBytes)
            _exit(77)
        }
        try require(records.read("retirement-host-report") == report.canonicalBytes, "retirement report changed after reopen")
        try publish("retirement-report-reopened", report.report.bytes)
    case "prepare-ack":
        try prepareAck(owner)
    case "erase-journal":
        try failure([102]) { try owner.eraseJournal(hostAcknowledgement: exact("retirement-report-receipt", 3730)) }
        try failure([2]) { try owner.journalState() }
        try owner.close(); owner = try openOwner()
        try require(owner.journalState() == .retained, "wrong-purpose receipt erased journal")
        try owner.eraseJournal(hostAcknowledgement: exact("retirement-ack", 3730))
        _exit(77)
    case "erase-signer":
        try require(owner.journalState() == .erased, "journal not erased before signer")
        try owner.prepareSignerErasure(hostAcknowledgement: exact("retirement-ack", 3730))
        try require(owner.signerState() == .retained, "original signer not retained")
        try owner.eraseSigner()
        _exit(77)
    case "verify":
        try prepareAck(owner)
        try publish("retirement-host-report-verified", records.read("retirement-host-report"))
        try require(owner.journalState() == .erased && owner.signerState() == .erased, "retirement terminal missing")
        try owner.eraseSigner()
        try failure([2]) { try owner.signerState() }
        try publish("retirement-verified", Array(exact("retirement-report-proposal", 353).suffix(32)))
    default: throw ProbeFailure.contract("unknown retirement stage")
    }
    try owner.close()
    try output("retirement-stage-pass:" + mode)
}
