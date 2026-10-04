// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity

// Public authority records belong to the test host. The native registration
// remains the only writer of the protected key, request and installation state.
private struct EnrollmentInputs {
    let records: FixtureRecords
    func read(_ name: String, maximum: Int) throws -> [UInt8] {
        let bytes = try records.read(name)
        try require(bytes.count <= maximum, "enrollment public input width: \(name)")
        return bytes
    }
    func exact(_ name: String, count: Int) throws -> [UInt8] {
        let bytes = try read(name, maximum: count)
        try require(bytes.count == count, "enrollment public input width: \(name)")
        return bytes
    }
    func counter(_ bytes: ArraySlice<UInt8>) -> UInt64 {
        bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }
    func intent() throws -> EnrollmentIntent {
        let bytes = try exact("enrollment-intent", count: 72)
        return try EnrollmentIntent(root: exact("enrollment-root", count: 1985),
            device: Array(bytes[0..<16]), generation: counter(bytes[16..<24]),
            family: Array(bytes[24..<56]), validFrom: counter(bytes[56..<64]), validUntil: counter(bytes[64..<72]))
    }
    func pin(renewal: Bool) throws -> AccountPin {
        let original = try intent()
        let version = try exact(renewal ? "renewal-version" : "trusted-roster-version", count: 8)
        let checkpoint = try RosterCheckpoint(version: counter(version[...]),
            digest: exact(renewal ? "renewal-digest" : "trusted-roster-digest", count: 32))
        return try AccountPin(account: AccountID(bytes: exact("trusted-account", count: 32)),
            root: original.root, family: original.family, checkpoint: checkpoint)
    }
    func publish(_ name: String, _ bytes: [UInt8]) throws {
        try require(records.retain(name, bytes: bytes, create: true), "enrollment output already exists: \(name)")
    }
}

private func disposingEnrollment<T>(_ owner: ContinuityEnrollment, _ body: () throws -> T) throws -> T {
    let result = Result { try body() }
    do { try owner.close() }
    catch { throw ProbeFailure.contract("enrollment disposal failed: \(error); operation: \(result)") }
    return try result.get()
}
private func disposingEnrollmentDevice<T>(_ device: ContinuityDevice, _ body: () throws -> T) throws -> T {
    // This scope owns the sole close attempt. Its body may retain a child for
    // checks after return, but must not close the parent itself.
    let result = Result { try body() }
    do { try device.close() }
    catch { throw ProbeFailure.contract("enrolled device disposal failed: \(error); operation: \(result)") }
    return try result.get()
}
private func expectedEnrollmentFailure<T>(_ code: Int32, _ body: () throws -> T) throws -> ContinuityFailure {
    do { _ = try body() }
    catch let error as ContinuityFailure {
        guard error.code == code else { throw error }
        return error
    }
    throw ProbeFailure.contract("enrollment failure \(code) was accepted")
}
private func refusedEnrollmentActivation(_ owner: ContinuityEnrollment, code: Int32) throws -> ContinuityFailure {
    switch Result(catching: { try owner.activate() }) {
    case let .failure(error):
        guard let native = error as? ContinuityFailure, native.code == code else { throw error }
        return native
    case let .success(device):
        try device.close()
        throw ProbeFailure.contract("refused enrollment activation published device")
    }
}
private func invalidEnrollmentLength<T>(_ body: () throws -> T) throws {
    do { _ = try body() }
    catch ContinuityBoundaryError.inputLength { return }
    throw ProbeFailure.contract("empty enrollment input was accepted")
}
private func prepareEnrollment(_ path: String, witness: WitnessCarrier, create: Bool) throws -> ContinuityEnrollment {
    let intent = try EnrollmentInputs(records: FixtureRecords(path: path)).intent()
    return try create ? ContinuityEnrollment.prepareCreate(path: path, intent: intent, witness: witness) :
        ContinuityEnrollment.prepareResume(path: path, intent: intent, witness: witness)
}
private final class WeakEnrollment {
    weak var value: ContinuityEnrollment?
    init(_ owner: ContinuityEnrollment) { value = owner }
}
private func transferEnrollment(_ path: String, witness: WitnessCarrier) throws -> (ContinuityDevice, WeakEnrollment) {
    let owner = try prepareEnrollment(path, witness: witness, create: false)
    let old = WeakEnrollment(owner)
    let device = try disposingEnrollment(owner) {
        try owner.finishOpen()
        let device = try owner.activate()
        do {
            try owner.close()
            _ = try expectedEnrollmentFailure(2) { try owner.status() }
            _ = try expectedEnrollmentFailure(2) { try owner.request() }
            _ = try expectedEnrollmentFailure(2) { try owner.prepareStorage() }
            _ = try expectedEnrollmentFailure(2) { try owner.cancel() }
            _ = try refusedEnrollmentActivation(owner, code: 2)
            return device
        } catch {
            let original = error
            do { try device.close() }
            catch { throw ProbeFailure.contract("enrollment transfer failed: \(original); successor disposal: \(error)") }
            throw original
        }
    }
    return (device, old)
}
private func activatedEnrollment(_ path: String, witness: WitnessCarrier) throws -> ContinuityDevice {
    let (device, old) = try transferEnrollment(path, witness: witness)
    do {
        try require(old.value == nil, "old enrollment wrapper retained after transfer")
        _ = try device.nextAccountOperation()
        _ = try FixtureRecords(path: path).retain("swift-enrollment-transfer",
            bytes: Array("old-registration-released original-device-live\n".utf8), create: true)
        return device
    } catch {
        let original = error
        do { try device.close() }
        catch { throw ProbeFailure.contract("enrollment successor failed: \(original); disposal: \(error)") }
        throw original
    }
}

struct EnrollmentParentSelection {
    let path: String
    let role: BootstrapRole
    func openPeer(path peerPath: String, session: SessionID?, witness: WitnessCarrier) throws -> ConfiguredClientOwner {
        let device = try activatedEnrollment(path, witness: witness)
        do {
            let peer = try session.map {
                try device.preparePeerReopen(path: peerPath, quality: .oneTimeBoth, role: role, session: $0)
            } ?? device.preparePeer(path: peerPath, quality: .oneTimeBoth, role: role)
            do { try peer.finishOpen() }
            catch {
                let original = error
                do { try close(peer) }
                catch { throw ProbeFailure.contract("enrolled peer open failed: \(original); disposal: \(error)") }
                throw original
            }
            return ConfiguredClientOwner(peer: peer, parent: device)
        } catch {
            let original = error
            do { try device.close() }
            catch { throw ProbeFailure.contract("enrolled peer failed: \(original); parent disposal: \(error)") }
            throw original
        }
    }
}
struct ConfiguredClientOwner {
    let peer: ContinuityOwner
    let parent: ContinuityDevice?
    func dispose() throws {
        try close(peer)
        if let parent {
            try parent.close()
            _ = try expectedEnrollmentFailure(2) { try parent.nextAccountOperation() }
        }
    }
}

private func cancelledEnrollmentActivation(_ owner: ContinuityEnrollment, marker: String) async throws {
    let worker = Task.detached { try owner.activate() }
    do {
        try waitMarker(marker)
        _ = try expectedEnrollmentFailure(3) { try owner.status() }
        _ = try expectedEnrollmentFailure(3) { try owner.close() }
        _ = try refusedEnrollmentActivation(owner, code: 3)
        try owner.cancel()
    } catch {
        let original = error
        let cancellation = Result { try owner.cancel() }
        let result = await worker.result
        let successorDisposal = Result {
            if case let .success(device) = result { try device.close() }
        }
        let disposal = Result { try owner.close() }
        throw ProbeFailure.contract("enrollment barrier: \(original); cancellation: \(cancellation); worker: \(result); successor disposal: \(successorDisposal); disposal: \(disposal)")
    }
    let result = await worker.result
    try disposingEnrollment(owner) {
        switch result {
        case let .failure(error):
            guard let native = error as? ContinuityFailure, native.code == 218 else { throw error }
        case let .success(device):
            try device.close()
            throw ProbeFailure.contract("cancelled enrollment activation reported success")
        }
        _ = try expectedEnrollmentFailure(2) { try owner.status() }
    }
}

func enrollmentCommand(_ args: [String], witness: WitnessCarrier) async throws {
    try require(args.count >= 2, "enrollment arguments")
    let mode = args[0], path = args[1]
    let inputs = EnrollmentInputs(records: FixtureRecords(path: path))
    let counts = mode == "enrollment-hold" ? 3...4 :
        (mode == "enrollment-activate-error" || mode == "enrollment-cancel-activate" ? 3...3 : 2...2)
    try require(counts.contains(args.count), "enrollment argument count")
    if mode == "enrollment-key" {
        try ContinuityEnrollment.provisionWrappingKey(path: path)
        try output("enrollment-key"); return
    }
    if mode == "enrollment-key-conflict" {
        _ = try expectedEnrollmentFailure(211) { try ContinuityEnrollment.provisionWrappingKey(path: path) }
        try output("enrollment-key-refused:211"); return
    }
    if mode == "enrollment-activate" || mode == "enrollment-hold" {
        let device = try activatedEnrollment(path, witness: witness)
        var child: ContinuityOwner?
        let operation = Result {
            let batch = try disposingEnrollmentDevice(device) {
                let batch = try device.nextAccountOperation()
                if mode == "enrollment-hold" {
                    if args.count == 4 {
                        // Keep one child after closing a separately owned sibling.
                        child = try device.openPeer(path: args[3], quality: .oneTimeBoth, role: .initiator)
                        let sibling = try device.openPeer(path: args[3], quality: .oneTimeBoth, role: .initiator)
                        try close(sibling)
                    }
                    try inputs.publish("enrollment-held", Array("1".utf8))
                    try waitMarker(args[2])
                }
                return batch
            }
            // The scope has closed the parent exactly once. Its retained child
            // must now have lost authority even though the Swift wrapper lives.
            _ = try expectedEnrollmentFailure(2) { try device.nextAccountOperation() }
            if let child {
                let session = try SessionID(bytes: [1] + [UInt8](repeating: 0, count: 31))
                _ = try expectedEnrollmentFailure(2) { try child.nextMessage(session: session) }
            }
            return batch
        }
        do { if let child { try close(child) } }
        catch { throw ProbeFailure.contract("enrollment child disposal failed: \(error); operation: \(operation)") }
        let batch = try operation.get()
        try output("enrollment-active\n\(hex(batch))"); return
    }
    let create = mode == "enrollment-create" || mode == "enrollment-refuse-create"
    let owner = try prepareEnrollment(path, witness: witness, create: create)
    if mode == "enrollment-cancel-activate" {
        do {
            if case .local = witness { throw ProbeFailure.contract("enrollment cancellation requires witness") }
            try owner.finishOpen()
        } catch {
            let original = error
            try disposingEnrollment(owner) { throw original }
        }
        try await cancelledEnrollmentActivation(owner, marker: args[2])
        try output("enrollment-activation-cancelled"); return
    }
    let text = try disposingEnrollment(owner) {
        if mode == "enrollment-refuse-resume" || mode == "enrollment-refuse-create" {
            let code: Int32 = create ? 211 : 204
            _ = try expectedEnrollmentFailure(code) { try owner.finishOpen() }
            _ = try expectedEnrollmentFailure(2) { try owner.status() }
            return "enrollment-open-refused:\(code)"
        }
        try owner.finishOpen()
        let original = try owner.status()
        if mode.hasPrefix("enrollment-credential-") {
            return try credentialEnrollmentCommand(owner, inputs: inputs, mode: mode, original: original)
        }
        switch mode {
        case "enrollment-create":
            try require(original.phase == .preparing, "new enrollment not Preparing")
        case "enrollment-request", "enrollment-request-retry":
            let request = try owner.request()
            try require(request.count == 5506 && request == owner.request(), "original enrollment request changed")
            if mode == "enrollment-request-retry" {
                try require(request == inputs.read("enrollment-request", maximum: 8192), "restart replaced enrollment request")
            }
            try inputs.publish(mode == "enrollment-request" ? "enrollment-request" : "enrollment-reopened-request", request)
        case "enrollment-accept", "enrollment-reject-signature":
            var certificate = try inputs.read("grant-certificate", maximum: 8192)
            let roster = try inputs.read("grant-roster", maximum: 8192), pin = try inputs.pin(renewal: false)
            try invalidEnrollmentLength { try owner.accept(certificate: [], roster: roster, pin: pin) }
            try invalidEnrollmentLength { try owner.accept(certificate: certificate, roster: [], pin: pin) }
            try require(owner.status() == original, "input shape error consumed enrollment")
            if mode == "enrollment-reject-signature" {
                certificate[certificate.count - 1] ^= 1
                _ = try expectedEnrollmentFailure(102) { try owner.accept(certificate: certificate, roster: roster, pin: pin) }
                _ = try expectedEnrollmentFailure(2) { try owner.status() }
                return "enrollment-signature-refused"
            }
            let journal = try owner.accept(certificate: certificate, roster: roster, pin: pin)
            try require(owner.status().journal == journal, "accepted journal changed")
        case "enrollment-storage":
            let prepared = try owner.prepareStorage()
            try require(prepared == owner.prepareStorage(), "original enrollment preparation changed")
            switch prepared {
            case let .local(journal):
                try require(journal == original.journal, "prepared journal changed")
                try inputs.publish("enrollment-genesis-subject", [UInt8](repeating: 0, count: 96))
                try inputs.publish("enrollment-genesis-digest", [UInt8](repeating: 0, count: 32))
            case let .requiresEnrollment(genesis):
                try require(genesis.journal == original.journal, "prepared journal changed")
                try inputs.publish("enrollment-genesis-subject", genesis.subject)
                try inputs.publish("enrollment-genesis-digest", genesis.imageDigest)
            }
        case "enrollment-refresh":
            let previous = try inputs.pin(renewal: false).checkpoint, pin = try inputs.pin(renewal: true)
            let roster = try inputs.read("renewal-roster", maximum: 8192)
            try invalidEnrollmentLength { try owner.refreshRoster(previous: previous, roster: [], pin: pin) }
            try require(owner.status() == original, "refresh shape error consumed enrollment")
            let state = try owner.refreshRoster(previous: previous, roster: roster, pin: pin)
            try require(state.phase == .refreshing && state.previous == previous && state.next == pin.checkpoint &&
                        state.signingID == original.signingID && state.journal == original.journal, "refresh changed original binding")
        case "enrollment-activate-error":
            guard let expected = Int32(args[2]), (1...10000).contains(expected), String(expected) == args[2] else {
                throw ProbeFailure.contract("expected enrollment activation status")
            }
            let refusal = try refusedEnrollmentActivation(owner, code: expected)
            _ = try expectedEnrollmentFailure(2) { try owner.status() }
            let name = expected == 218 ? "enrollment-authority-refusal" :
                (expected == 216 ? "enrollment-required-refusal" :
                (expected == 104 ? "enrollment-policy-refusal" : "enrollment-activation-refusal"))
            try inputs.publish(name, Array(refusal.message.utf8))
            return "enrollment-activation-refused:\(expected)"
        case "enrollment-cancel":
            try owner.cancel()
            _ = try expectedEnrollmentFailure(302) { try owner.request() }
            return "enrollment-cancelled"
        case "enrollment-status": break
        default: throw ProbeFailure.contract("unknown enrollment command")
        }
        let state = try owner.status()
        return "enrollment-phase:\(state.phase.rawValue)\n\(hex(state.signingID))\n\(state.journal.map(hex) ?? String(repeating: "0", count: 64))"
    }
    try output(text)
}

private func renewalHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}
private func renewalText(_ status: CredentialRenewalStatus) -> String {
    let phase: UInt32, operation: [UInt8], statement: [UInt8], checkpoint: RosterCheckpoint?, observedAt: UInt64
    switch status {
    case .absent:
        phase = 0; operation = [UInt8](repeating: 0, count: 32); statement = operation; checkpoint = nil; observedAt = 0
    case let .pending(id, identity):
        phase = 1; operation = id.bytes; statement = identity.bytes; checkpoint = nil; observedAt = 0
    case let .committed(id, identity, target):
        phase = 2; operation = id.bytes; statement = identity.bytes; checkpoint = target; observedAt = 0
    case let .closed(id, identity, target):
        phase = 4; operation = id.bytes; statement = identity.bytes; checkpoint = target; observedAt = 0
    case let .expiredUncommitted(id, identity, head, at):
        phase = 3; operation = id.bytes; statement = identity.bytes; checkpoint = head; observedAt = at
    }
    return "credential-phase:\(phase)\n\(renewalHex(operation))\n\(renewalHex(statement))\ncredential-head:\(checkpoint?.version ?? 0)\n\(checkpoint.map { renewalHex($0.digest) } ?? String(repeating: "0", count: 64))\ncredential-observed:\(observedAt)"
}
private func credentialEnrollmentCommand(_ owner: ContinuityEnrollment, inputs: EnrollmentInputs,
    mode: String, original: EnrollmentStatus) throws -> String {
    let status: CredentialRenewalStatus
    switch mode {
    case "enrollment-credential-witness-commit-no-sdk", "enrollment-credential-witness-commit-policy-expired":
        let expected: Int32 = mode == "enrollment-credential-witness-commit-policy-expired" ? 104 : 702
        let operation = try CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32))
        let statement = try CredentialRenewalStatementID(bytes: inputs.exact("credential-statement", count: 32))
        _ = try expectedEnrollmentFailure(expected) { try owner.commitWitnessedCredentialRenewal(operation: operation, statement: statement) }
        _ = try expectedEnrollmentFailure(2) { try owner.credentialRenewalStatus() }
        return "credential-witness-commit-refused:\(expected)"
    case "enrollment-credential-witness-prepare":
        let proposal = try owner.prepareWitnessedCredentialRenewal()
        try require(proposal == owner.prepareWitnessedCredentialRenewal(), "witness preparation changed original target")
        try inputs.publish("credential-proposal", proposal.bytes)
        try require(owner.status() == original, "witness preparation replaced registration")
        return "credential-witness-prepared"
    case "enrollment-credential-witness-commit", "enrollment-credential-witness-close", "enrollment-credential-witness-reconcile":
        let operation = try CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32))
        let statement = try CredentialRenewalStatementID(bytes: inputs.exact("credential-statement", count: 32))
        switch mode {
        case "enrollment-credential-witness-commit":
            status = try owner.commitWitnessedCredentialRenewal(operation: operation, statement: statement)
        case "enrollment-credential-witness-close":
            status = try owner.closeWitnessedCredentialRenewal(operation: operation, statement: statement)
        default: status = try owner.reconcileWitnessedCredentialRenewal(operation: operation, statement: statement)
        }
        try require(owner.status() == original, "witness reconciliation replaced registration")
    case "enrollment-credential-status": status = try owner.credentialRenewalStatus()
    case "enrollment-credential-activate-refused":
        _ = try refusedEnrollmentActivation(owner, code: 104)
        _ = try expectedEnrollmentFailure(2) { try owner.credentialRenewalStatus() }
        return "credential-expired-activation-refused"
    case "enrollment-credential-stage", "enrollment-credential-reject":
        var grant = try inputs.read("credential-renewal", maximum: 65536)
        try require(!grant.isEmpty, "empty credential grant")
        let operation = try CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32))
        let pin = try inputs.pin(renewal: true)
        try invalidEnrollmentLength { try owner.stageCredentialRenewal(grant: [], pin: pin, operation: operation) }
        try require(owner.status() == original, "renewal shape refusal consumed registration")
        if mode == "enrollment-credential-reject" {
            grant[grant.count - 1] ^= 1
            _ = try expectedEnrollmentFailure(102) { try owner.stageCredentialRenewal(grant: grant, pin: pin, operation: operation) }
            _ = try expectedEnrollmentFailure(2) { try owner.credentialRenewalStatus() }
            return "credential-signature-refused"
        }
        status = try owner.stageCredentialRenewal(grant: grant, pin: pin, operation: operation)
        try require(status == owner.credentialRenewalStatus(), "renewal stage differs from authenticated readback")
    case "enrollment-credential-reconcile":
        status = try owner.reconcileExpiredCredentialRenewal(
            operation: CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32)),
            statement: CredentialRenewalStatementID(bytes: inputs.exact("credential-statement", count: 32)))
        try require(owner.status() == original, "reconciliation replaced the registration owner")
    default: throw ProbeFailure.contract("unknown credential renewal command")
    }
    return renewalText(status)
}

private func refusedRenewalPeer(_ device: ContinuityDevice, path: String, role: BootstrapRole,
    session: SessionID?, code: Int32) throws {
    let peer = try session.map { try device.preparePeerReopen(path: path, quality: .oneTimeBoth, role: role, session: $0) }
        ?? device.preparePeer(path: path, quality: .oneTimeBoth, role: role)
    let result = Result {
        _ = try expectedEnrollmentFailure(code) { try peer.finishOpen() }
        _ = try expectedEnrollmentFailure(2) { try peer.finishOpen() }
    }
    do { try close(peer) }
    catch { throw ProbeFailure.contract("refused peer disposal: \(error); operation: \(result)") }
    try result.get()
}
private func admitRenewalPeer(_ device: ContinuityDevice, path: String, controls: Bool) throws {
    let inputs = EnrollmentInputs(records: FixtureRecords(path: path))
    let grant = try inputs.read("credential-renewal", maximum: 65536), pin = try inputs.pin(renewal: true)
    let operation = try CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32))
    if controls {
        try invalidEnrollmentLength { try device.admitPeerCredentialRenewal(grant: [], pin: pin, operation: operation) }
        var digest = pin.checkpoint.digest; digest[0] ^= 1
        let wrong = try AccountPin(account: pin.account, root: pin.root, family: pin.family,
            checkpoint: RosterCheckpoint(version: pin.checkpoint.version, digest: digest))
        _ = try expectedEnrollmentFailure(105) { try device.admitPeerCredentialRenewal(grant: grant, pin: wrong, operation: operation) }
        var bytes = operation.bytes; bytes[0] ^= 1
        let wrongOperation = try CredentialRenewalID(bytes: bytes)
        _ = try expectedEnrollmentFailure(211) { try device.admitPeerCredentialRenewal(grant: grant, pin: pin, operation: wrongOperation) }
    }
    try require(device.admitPeerCredentialRenewal(grant: grant, pin: pin, operation: operation) == pin.checkpoint,
        "peer grant returned wrong target")
    try require(device.admitPeerCredentialRenewal(grant: grant, pin: pin, operation: operation) == pin.checkpoint,
        "peer grant retry changed target")
}
func credentialPeerCommand(_ args: [String]) throws {
    try require(args.count == 6, "credential peer arguments")
    let path = args[1], session: SessionID = try decode(args[4]), message: MessageID = try decode(args[5])
    var bytes = session.bytes; bytes[0] ^= 1
    let wrong = try SessionID(bytes: bytes)
    let device = try ContinuityDevice.open(path: path)
    try disposingEnrollmentDevice(device) {
        try refusedRenewalPeer(device, path: path, role: .responder, session: session, code: 104)
        try admitRenewalPeer(device, path: args[2], controls: true)
        try refusedRenewalPeer(device, path: path, role: .responder, session: nil, code: 104)
        try refusedRenewalPeer(device, path: path, role: .initiator, session: session, code: 211)
        try refusedRenewalPeer(device, path: path, role: .responder, session: wrong, code: 201)
        let first = try device.reopenPeer(path: path, quality: .oneTimeBoth, role: .responder, session: session)
        let result = Result {
            try require(first.status(session: session, message: message) == .committed, "first grant lost original outbox")
            let next = try first.nextMessage(session: session)
            try admitRenewalPeer(device, path: args[3], controls: false)
            _ = try expectedEnrollmentFailure(211) { try first.nextMessage(session: session) }
            return next
        }
        do { try close(first) }
        catch { throw ProbeFailure.contract("stale child disposal: \(error); operation: \(result)") }
        let next = try result.get()
        let current = try device.reopenPeer(path: path, quality: .oneTimeBoth, role: .responder, session: session)
        let checked = Result {
            try require(current.status(session: session, message: message) == .committed, "next grant lost original outbox")
            try require(current.nextMessage(session: session) == next, "stale refusal advanced message slot")
        }
        do { try close(current) }
        catch { throw ProbeFailure.contract("current child disposal: \(error); operation: \(checked)") }
        try checked.get()
    }
    let reopened = try ContinuityDevice.open(path: path)
    try disposingEnrollmentDevice(reopened) {
        let peer = try reopened.reopenPeer(path: path, quality: .oneTimeBoth, role: .responder, session: session)
        let checked = Result { try require(peer.status(session: session, message: message) == .committed, "restart lost original outbox") }
        do { try close(peer) }
        catch { throw ProbeFailure.contract("reopened child disposal: \(error); operation: \(checked)") }
        try checked.get()
    }
    try output("credential-peer-passed")
}
