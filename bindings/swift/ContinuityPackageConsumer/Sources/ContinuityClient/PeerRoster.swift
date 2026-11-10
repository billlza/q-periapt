// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity

func peerRosterCommand(_ args: [String], parent: EnrollmentParentSelection, witness: WitnessCarrier) async throws {
    try require([4, 5, 10].contains(args.count) && args[1] == parent.path, "peer roster arguments")
    let mode = args[3], records = FixtureRecords(path: args[2])
    func exact(_ name: String, _ count: Int) throws -> [UInt8] {
        let value = try records.read(name); try require(value.count == count, "peer roster field width"); return value
    }
    let version = try exact("version", 8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    let pin = try AccountPin(account: AccountID(bytes: exact("account", 32)), root: exact("root", 1985),
        family: exact("family", 32), checkpoint: RosterCheckpoint(version: version, digest: exact("digest", 32)))
    let roster = try records.read("roster")
    let device = try parent.openDevice(witness: witness)
    var peers: [ContinuityOwner] = []
    let outcome: Result<String, Error>
    do {
        if mode == "suspend" {
            try require(args.count == 10, "complete original batch inputs")
            for (path, session) in [(args[4], args[5]), (args[6], args[7])] {
                let peer = try device.preparePeerReopen(path: path, quality: .oneTimeBoth, role: .initiator, session: decode(session))
                peers.append(peer); try peer.finishOpen()
            }
        }
        do { _ = try device.admitPeerRoster(roster: [], pin: pin); throw ProbeFailure.contract("empty peer roster accepted") }
        catch ContinuityBoundaryError.inputLength { /* Expected public input refusal. */ }
        var wrong = pin.checkpoint.digest; wrong[0] ^= 1
        let wrongPin = try AccountPin(account: pin.account, root: pin.root, family: pin.family,
            checkpoint: RosterCheckpoint(version: version, digest: wrong))
        try failure([105]) { try device.admitPeerRoster(roster: roster, pin: wrongPin) }
        let text: String
        if mode == "cancel-active" {
            try require(args.count == 5, "peer roster barrier required")
            let worker = Task.detached { try device.admitPeerRoster(roster: roster, pin: pin) }
            let start: ContinuousClock.Instant
            do {
                try waitMarker(args[4]); try failure([3]) { try device.close() }
                start = ContinuousClock.now; try device.cancel()
            } catch {
                let original = error, cancellation = Result { try device.cancel() }
                let completed = await worker.result
                throw ProbeFailure.contract("peer roster barrier: \(original); cancellation: \(cancellation); worker: \(completed)")
            }
            switch await worker.result {
            case let .failure(error):
                guard let native = error as? ContinuityFailure, native.code == 218 else { throw error }
            case .success: throw ProbeFailure.contract("unknown roster commit published checkpoint")
            }
            _ = try observedCancellationMilliseconds(start.duration(to: ContinuousClock.now))
            try failure([302]) { try device.nextAccountOperation() }
            text = "peer-roster-cancelled-after-advance"
        } else if mode == "lost" {
            try failure([218]) { try device.admitPeerRoster(roster: roster, pin: pin) }
            try failure([202]) { try device.nextAccountOperation() }
            text = "peer-roster-outcome-unavailable"
        } else if mode == "cancel" {
            try device.cancel(); try failure([302]) { try device.admitPeerRoster(roster: roster, pin: pin) }
            text = "peer-roster-cancelled"
        } else {
            try require(mode == "admit" || mode == "suspend", "unknown peer roster mode")
            let result = try device.admitPeerRoster(roster: roster, pin: pin)
            try require(result == pin.checkpoint && device.admitPeerRoster(roster: roster, pin: pin) == result, "peer roster exact retry changed target")
            if mode == "suspend" {
                let targets = try [AccountTarget(peer: peers[0], session: decode(args[5])), AccountTarget(peer: peers[1], session: decode(args[7]))]
                try failure([103]) {
                    try device.sendAccountMember(operation: decode(args[9]), account: decode(args[8]), targets: targets,
                        selected: 1, address: "127.0.0.1:1", plaintext: Array("persisted before process exit".utf8), associatedData: Array("owned-service".utf8))
                }
                text = "account-refused:103\npeer-roster-admitted"
            } else { text = "peer-roster-admitted" }
        }
        outcome = .success(text)
    } catch { outcome = .failure(error) }
    var disposal: [String] = []
    for peer in peers.reversed() { do { try peer.close() } catch { disposal.append(String(describing: error)) } }
    do { try device.close() } catch { disposal.append(String(describing: error)) }
    if !disposal.isEmpty { throw ProbeFailure.contract("peer roster disposal: \(disposal); operation: \(outcome)") }
    try output(outcome.get())
}
