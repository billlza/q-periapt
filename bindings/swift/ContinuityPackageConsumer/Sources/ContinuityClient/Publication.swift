// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity

private func publicationText(_ status: PublicationStatus) -> String {
    let zero = [UInt8](repeating: 0, count: 32)
    let state: Int, intent: [UInt8], manifest: [UInt8], artifact: [UInt8]
    switch status {
    case .absent: (state, intent, manifest, artifact) = (0, zero, zero, zero)
    case .retired: (state, intent, manifest, artifact) = (3, zero, zero, zero)
    case let .reserved(saved): (state, intent, manifest, artifact) = (1, saved, zero, zero)
    case let .prepared(i, m, a): (state, intent, manifest, artifact) = (2, i, m, a)
    }
    func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    return "publication-state:\(state)\n\(hex(intent))\n\(hex(manifest))\n\(hex(artifact))"
}
func publicationCommand(_ args: [String], parent: EnrollmentParentSelection, witness: WitnessCarrier) throws {
    try require((2...3).contains(args.count) && args[1] == parent.path && !parent.continued, "original publication parent arguments")
    let records = FixtureRecords(path: parent.path, maximumBytes: 2 * 1024 * 1024)
    let device = try parent.openDevice(witness: witness)
    let result = Result {
        if args[0] == "publication-next" {
            try require(args.count == 2, "next publication arguments")
            return try hex(device.nextPublication())
        }
        try require(args.count == 3, "original publication ID missing")
        let id: PrekeyPublicationID = try decode(args[2])
        switch args[0] {
        case "publication-status": return try publicationText(device.status(publication: id))
        case "publication-retire":
            let bytes = try records.read("publication-artifact")
            try require(bytes.count >= 104 && bytes.starts(with: Array("QPPUBA01".utf8)) && Array(bytes[8..<40]) == id.bytes,
                        "host-retained publication identity")
            return try publicationText(device.retirePublication(id, artifact: Array(bytes[72..<104])))
        case "publication-prepare", "publication-retry", "publication-cancel":
            let bytes = try records.read("publication-plan")
            try require(bytes.count == 48, "complete original publication plan")
            let from = bytes[32..<40].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            let until = bytes[40..<48].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            let kinds: [PublicationKeyKind] = [.signedClassical, .oneTimeClassical, .lastResortPQ, .oneTimePQ]
            let plan = try PublicationPlan(directory: Array(bytes.prefix(32)), validFrom: from, validUntil: until,
                keys: kinds.map { try PublicationKey(kind: $0, validFrom: from, validUntil: until) })
            if args[0] == "publication-cancel" {
                try device.cancel()
                try failure([302]) { try device.preparePublication(id, plan: plan) }
                return "publication-cancelled"
            }
            let prepared = try device.preparePublication(id, plan: plan)
            let status = try device.status(publication: id)
            guard case let .prepared(intent, _, artifact) = status else { throw ProbeFailure.contract("publication incomplete state") }
            try require(prepared.intent == intent && prepared.artifact == artifact, "publication commitments differ")
            _ = try records.retain(args[0] == "publication-retry" ? "publication-retry" : "publication-artifact",
                                   bytes: prepared.canonicalBytes, create: true)
            return publicationText(status)
        default: throw ProbeFailure.contract("unsupported publication command")
        }
    }
    do { try device.close() }
    catch { throw ProbeFailure.contract("publication owner close: \(error); operation: \(result)") }
    try output(result.get())
}
