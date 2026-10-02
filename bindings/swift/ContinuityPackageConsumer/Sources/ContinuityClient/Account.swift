// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity

private func closeDevice(_ device: ContinuityDevice) throws {
    try device.close()
    try failure([2]) { try device.cancel() }
}
private func accountShapeChecks() throws {
    let device = try ContinuityDevice.prepare(path: "/unused")
    let peer = try ContinuityOwner.prepare(path: "/unused", quality: .oneTimeBoth)
    let target = AccountTarget(peer: peer, session: try SessionID(bytes: [UInt8](repeating: 1, count: 32)))
    let operation = try AccountOperationID(bytes: [UInt8](repeating: 2, count: 32))
    let account = try AccountID(bytes: [UInt8](repeating: 3, count: 32))
    for (count, selected) in [(0, 0), (33, 0), (2, 2), (2, -1)] {
        do {
            _ = try device.sendAccountMember(operation: operation, account: account,
                targets: Array(repeating: target, count: count), selected: selected,
                address: "127.0.0.1:1", plaintext: [], associatedData: [])
        } catch let error as ContinuityBoundaryError {
            try require(error == .inputLength, "account shape error")
            continue
        }
        throw ProbeFailure.contract("account shape admitted")
    }
    try close(peer)
    try closeDevice(device)
}

func account(_ args: [String], witness: WitnessCarrier) async throws {
    try require(args.count >= 2, "account arguments")
    try accountShapeChecks()
    let command = args[0], path = args[1]
    if command == "account-connect" {
        try require(args.count == 8, "account connect arguments")
        // Returning prepared peers drops the public device wrapper. Their native
        // parent must remain alive through activation and both socket operations.
        weak var observedDevice: ContinuityDevice?
        func preparedPeers() throws -> [ContinuityOwner] {
            let device = try ContinuityDevice.open(path: path, witness: witness)
            observedDevice = device
            return try [device.preparePeer(path: args[2], quality: .oneTimeBoth, role: .initiator),
                        device.preparePeer(path: args[3], quality: .oneTimeBoth, role: .initiator)]
        }
        func establish() throws -> [SessionID] {
            let peers = try preparedPeers()
            try require(observedDevice == nil, "public device wrapper remained alive")
            var sessions: [SessionID] = []
            for index in 0..<2 {
                try peers[index].finishOpen()
                sessions.append(try peers[index].establish(peer: args[4 + index], request: decode(args[6 + index])).session)
            }
            for peer in peers.reversed() { try close(peer) }
            return sessions
        }
        let sessions = try establish()
        // Once those child wrappers leave scope, ARC must release the original
        // parent lease in this same process, without depending on process exit.
        let reopened = try ContinuityDevice.open(path: path, witness: witness)
        try closeDevice(reopened)
        for session in sessions { try output(hex(session)) }
        return
    }
    let device = try ContinuityDevice.open(path: path, witness: witness)
    if command == "account-next" {
        try require(args.count == 2, "account next arguments")
        try output(hex(device.nextAccountOperation()))
        try closeDevice(device)
        return
    }
    if command == "account-status" {
        try require(args.count == 3, "account status arguments")
        let value = try device.status(operation: decode(args[2]))
        let state: Int, report: [UInt8]
        switch value {
        case .absent: state = 0; report = [UInt8](repeating: 0, count: 32)
        case .reserved: state = 1; report = [UInt8](repeating: 0, count: 32)
        case .committed: state = 2; report = [UInt8](repeating: 0, count: 32)
        case let .abandoning(id): state = 3; report = id.bytes
        case let .abandoned(id): state = 4; report = id.bytes
        case .retired: state = 5; report = [UInt8](repeating: 0, count: 32)
        }
        try output("account-status:\(state)")
        try output(report.map { String(format: "%02x", $0) }.joined())
        try closeDevice(device)
        return
    }
    try require(command == "account-send" && (args.count == 11 || args.count == 12), "account send arguments")
    let sessions: [SessionID] = try [decode(args[3]), decode(args[5])]
    let peers = try [device.reopenPeer(path: args[2], quality: .oneTimeBoth, role: .initiator, session: sessions[0]),
                     device.reopenPeer(path: args[4], quality: .oneTimeBoth, role: .initiator, session: sessions[1])]
    let recipient: AccountID = try decode(args[6]), operation: AccountOperationID = try decode(args[7])
    try require(args[8] == "0" || args[8] == "1", "account selection")
    var selected = args[8] == "0" ? 0 : 1
    var targets = [AccountTarget(peer: peers[0], session: sessions[0]), AccountTarget(peer: peers[1], session: sessions[1])]
    let address = args[9], mode = args[10]
    let payload = Array("persisted before process exit".utf8), ad = Array("owned-service".utf8)
    var expected: Int32?, secondClosed = false
    var otherParent: ContinuityDevice?, otherPeer: ContinuityOwner?
    if mode == "unary" {
        try require(args.count == 12, "original account member ID")
        try failure([215]) {
            try peers[selected].send(peer: address, session: sessions[selected], message: decode(args[11]),
                                     plaintext: payload, associatedData: ad)
        }
        try output("account-refused:215")
        try close(peers[1]); try close(peers[0]); try closeDevice(device)
        return
    }
    switch mode {
    case "omit": targets.removeLast(); selected = 0; expected = 106
    case "duplicate-peer": targets[1] = AccountTarget(peer: peers[0], session: sessions[1]); expected = 1
    case "duplicate-session": targets[1] = AccountTarget(peer: peers[1], session: sessions[0]); expected = 1
    case "cancel-peer": try peers[1].cancel(); expected = 302
    case "closed-peer": try close(peers[1]); secondClosed = true; expected = 2
    case "wrong-parent":
        try require(args.count == 12, "other original device missing")
        let parent = try ContinuityDevice.open(path: args[11], witness: witness)
        let peer = try parent.reopenPeer(path: args[11], quality: .oneTimeBoth, role: .responder, session: sessions[1])
        otherParent = parent; otherPeer = peer
        targets[1] = AccountTarget(peer: peer, session: sessions[1]); expected = 211
    case "changed-input": expected = 211
    case "unknown": expected = 311
    case "reverse-retained": targets.reverse(); selected = 1 - selected
    case "deliver", "retained", "cancel-active": break
    default: throw ProbeFailure.contract("account mode")
    }
    let retainedTargets = targets, index = selected
    let body = mode == "changed-input" ? Array("different".utf8) : payload
    let invoke: @Sendable () throws -> AccountDelivery = {
        try device.sendAccountMember(operation: operation, account: recipient, targets: retainedTargets,
            selected: index, address: address, plaintext: body, associatedData: ad)
    }
    if mode == "cancel-active" {
        try require(args.count == 12, "account socket barrier")
        let idle = try device.reopenPeer(path: args[2], quality: .oneTimeBoth, role: .initiator, session: sessions[0])
        let worker = Task.detached(operation: invoke)
        let start: ContinuousClock.Instant
        do {
            try waitMarker(args[11])
            try close(idle)
            try failure([3]) { try device.close() }
            for peer in peers { try failure([3]) { try peer.close() } }
            start = ContinuousClock.now
            try peers[1].cancel()
        } catch {
            let original = error
            let cancellation = Result { try device.cancel() }
            let result = await worker.result
            throw ProbeFailure.contract("account barrier: \(original); cancellation: \(cancellation); worker: \(result)")
        }
        switch await worker.result {
        case let .failure(error):
            guard let native = error as? ContinuityFailure, native.code == 302 else { throw error }
        case .success: throw ProbeFailure.contract("cancelled account call returned success")
        }
        let milliseconds = try observedCancellationMilliseconds(start.duration(to: ContinuousClock.now))
        _ = try device.nextAccountOperation()
        _ = try peers[0].nextMessage(session: sessions[0])
        try output("account-refused:302")
        try output("account-cancel-active:\(milliseconds):3")
    } else if let expected {
        try failure([expected], invoke)
        try output("account-refused:\(expected)")
    } else {
        let result = try invoke()
        try require(result.outcome == .consumption(.confirmed) && result.session == retainedTargets[index].session,
                    "account scope/outcome")
        try require((mode == "retained" || mode == "reverse-retained") == (result.exchanges == 0), "retained account network count")
        try output("account-delivered:1:\(result.exchanges)")
        try output(hex(result.session)); try output(hex(result.message))
        try output(result.device.map { String(format: "%02x", $0) }.joined())
    }
    if let otherPeer { try close(otherPeer) }
    if let otherParent { try closeDevice(otherParent) }
    if !secondClosed { try close(peers[1]) }
    try close(peers[0]); try closeDevice(device)
}
