// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity

// Qualification host only: input files model separately approved public trust.
// Only typed copied values, never a peer path, reach the explicit SDK API.
func peerConfiguration(_ path: String) throws -> PeerConfiguration {
    let records = FixtureRecords(path: path, maximumBytes: 65536)
    func exact(_ name: String, _ count: Int) throws -> [UInt8] {
        let bytes = try records.read(name)
        try require(bytes.count == count, "peer input width: \(name)")
        return bytes
    }
    func counter(_ name: String) throws -> UInt64 {
        try exact(name, 8).reduce(0) { ($0 << 8) | UInt64($1) }
    }
    func device(_ prefix: String) throws -> PeerDeviceExpectation {
        let pin = try AccountPin(account: AccountID(bytes: exact(prefix + "-account", 32)),
            root: exact(prefix + "-root", 1985), family: exact("family", 32),
            checkpoint: RosterCheckpoint(version: counter(prefix + "-roster-version"), digest: exact(prefix + "-roster-digest", 32)))
        return try PeerDeviceExpectation(account: pin, device: exact(prefix + "-device", 16), generation: counter(prefix + "-generation"))
    }
    guard let name = String(bytes: try records.read("tls-peer-name"), encoding: .utf8) else {
        throw ProbeFailure.contract("peer name UTF-8")
    }
    return try PeerConfiguration(initiator: device("initiator"), responder: device("responder"),
        directory: exact("directory", 32), bundle: records.read("bootstrap.bundle"),
        tlsPeerCertificate: records.read("tls-peer"), tlsPeerName: name)
}

private final class WeakPeerDevice {
    weak var value: ContinuityDevice?
    init(_ value: ContinuityDevice) { self.value = value }
}
private func preparedWithoutPublicParent(_ path: String, _ input: PeerConfiguration, _ session: SessionID) throws -> (ContinuityOwner, WeakPeerDevice) {
    let device = try EnrollmentParentSelection(path: path, role: .initiator, policy: .original).openDevice(witness: .local)
    do {
        return (try device.preparePeerReopen(configuration: input, quality: .oneTimeBoth, role: .initiator, session: session), WeakPeerDevice(device))
    } catch {
        let original = error
        do { try device.close() }
        catch { throw ProbeFailure.contract("peer preparation failed: \(original); parent close: \(error)") }
        throw original
    }
}
func peerConfigurationLifetime(_ args: [String]) throws {
    try require(args.count == 4, "peer lifetime arguments")
    let path = args[1], input = try peerConfiguration(args[2]), session: SessionID = try decode(args[3])
    func parent() throws -> ContinuityDevice {
        try EnrollmentParentSelection(path: path, role: .initiator, policy: .original).openDevice(witness: .local)
    }
    let (retained, publicParent) = try preparedWithoutPublicParent(path, input, session)
    try require(publicParent.value == nil, "public parent retained by configured peer")
    try retained.finishOpen()
    _ = try retained.nextMessage(session: session)
    try close(retained)
    let reopened = try parent() // Must release the real lease while the closed child wrapper survives.
    try reopened.close()
    try failure([2]) { try retained.nextMessage(session: session) }

    let original = try parent()
    let child = try original.openPeer(configuration: input, quality: .oneTimeBoth, role: .initiator)
    try original.close()
    try failure([2]) { try child.nextMessage(session: session) }
    let replacement = try parent()
    try replacement.close()
    try close(child)

    let live = try parent()
    let cancelled = try live.preparePeerReopen(configuration: input, quality: .oneTimeBoth, role: .initiator, session: session)
    try cancelled.cancel()
    try failure([302]) { try cancelled.finishOpen() }
    _ = try live.nextAccountOperation()
    try close(cancelled)
    try live.close()
    try output("QPC_CONFIGURED_PEER_LIFETIME_PASS")
}
