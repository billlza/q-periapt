// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity

func rootAuthorizePeer(_ root: ContinuityAccountAuthority, input: RootInputs, peer: String) throws {
    let p = EnrollmentInputs(records: FixtureRecords(path: peer))
    let publicRecords = EnrollmentInputs(records: FixtureRecords(path: input.records.records.path + "/traffic"))
    let version = try p.exact("responder-roster-version", count: 8)
    let pin = try AccountPin(account: AccountID(bytes: p.exact("responder-account", count: 32)),
        root: p.exact("responder-root", count: 1985), family: input.trust.family,
        checkpoint: RosterCheckpoint(version: p.counter(version[...]), digest: p.exact("responder-roster-digest", count: 32)))
    let application = try ApplicationAccountID(bytes: publicRecords.exact("peer-application", count: 32))
    let next = try root.associate(application: application, pin: pin,
        certificate: p.read("responder-certificate", maximum: 8192), roster: p.read("responder-roster", maximum: 65536))
    try require(next.application == application && next.account == pin.account && next.revision == 1, "independent peer association")
    try rootNumber(publicRecords.records.path, "peer-associated-revision", next.revision)
}
func rootTraffic(_ device: ContinuityDevice, input: RootInputs, mode: String, peerPath: String, address: String) throws {
    let path = input.records.records.path + "/traffic", records = EnrollmentInputs(records: FixtureRecords(path: input.records.records.path + "/traffic"))
    let connect = mode == "traffic-connect", reject = mode == "traffic-reject-peer"
    let peer: ContinuityOwner
    var session: SessionID?
    if connect || reject { peer = try device.preparePeer(path: peerPath, quality: .oneTimeBoth, role: .initiator) }
    else {
        let original = try SessionID(bytes: records.exact("session", count: 32)); session = original
        peer = try device.preparePeerReopen(path: peerPath, quality: .oneTimeBoth, role: .initiator, session: original)
    }
    if reject {
        try failure([201]) { try peer.finishOpen() }; try peer.close()
        try rootNumber(path, "unknown-peer-code", 201); return
    }
    try peer.finishOpen()
    if connect {
        let value = try peer.establish(peer: address, request: InitiationID(bytes: [UInt8](repeating: 155, count: 32)))
        try require((1...8).contains(value.exchanges), "root bootstrap exchanges")
        try records.publish("session", value.session.bytes)
    } else {
        guard let session else { throw ProbeFailure.contract("root traffic missing original session") }
        if mode == "traffic-receive-cut" || mode == "traffic-receive-recover" {
            try rootReceive(peer, records: records, mode: mode, session: session)
        } else if mode == "traffic-rekey" {
            let epoch = try peer.rekey(peer: address, session: session, target: 1)
            try require(epoch == 1, "root rekey epoch"); try rootNumber(path, "rekey-epoch", epoch)
        } else {
            try rootSend(peer, records: records, mode: mode, address: address, session: session)
        }
    }
    try peer.close()
}
private func rootSend(_ peer: ContinuityOwner, records: EnrollmentInputs, mode: String,
                      address: String, session: SessionID) throws {
    let unknown = mode == "traffic-send-cut", retry = mode == "traffic-recover", after = mode == "traffic-after-rekey"
    try require(unknown || retry || after, "root send mode")
    let path = records.records.path, message: MessageID
    if retry {
        message = try MessageID(bytes: records.exact("message-before", count: 32))
        try require(peer.status(session: session, message: message) == .committed, "restart lost original message")
    } else {
        message = try peer.nextMessage(session: session)
        try require(records.counter(message.bytes[0..<8]) == (after ? 1 : 0) &&
            records.counter(message.bytes[8..<16]) == 0, "root message epoch/sequence")
        try records.publish(after ? "message-after" : "message-before", message.bytes)
    }
    let send = { try peer.send(peer: address, session: session, message: message,
        plaintext: Array("persisted before process exit".utf8), associatedData: Array("owned-service".utf8)) }
    if unknown {
        do { _ = try send(); throw ProbeFailure.contract("receiver loss falsely confirmed") }
        catch let error as ContinuityFailure {
            try require([303, 309, 310, 311].contains(error.code), "unexpected transport outcome")
            try require(peer.status(session: session, message: message) == .committed, "receiver loss discarded message")
            try rootNumber(path, "uncertain-code", UInt64(error.code))
        }
        try rootPause(path, "sender")
    }
    let result = try send()
    try require(result.consumption == .confirmed && (1...8).contains(result.exchanges) &&
        peer.status(session: session, message: message) == .acknowledged, "root consumption absent")
    try rootNumber(path, retry ? "recovered-status" : "after-status", 3)
}
private func rootReceive(_ peer: ContinuityOwner, records: EnrollmentInputs, mode: String, session: SessionID) throws {
    let cut = mode == "traffic-receive-cut", application = Application(path: records.records.path)
    let port = try peer.listen(address: "127.0.0.1:0")
    try require(port > 0, "root receive listener"); try output("root-listening:\(port)")
    let event = try peer.serve { delivery in
        application.calls += 1
        try require(delivery.session == session, "root receive session differs")
        try failure([3]) { try peer.close() }
        try application.persist(delivery)
        if cut { try rootPause(records.records.path, "receiver") }
    }
    guard case let .consumed(actual, message, duplicate) = event else { throw ProbeFailure.contract("root receive not consumed") }
    try require(!cut && actual == session && !duplicate && application.calls == 1 && application.created == 0,
        "root reverse recovery was not original single effect")
    try records.publish("reply-received", message.bytes)
    try rootNumber(records.records.path, "reply-created-on-recovery", UInt64(application.created))
}
