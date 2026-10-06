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
    func policyDocument() throws -> PolicyDocument {
        let version = try exact("policy-version", count: 8)
        return try PolicyDocument(root: exact("policy-root", count: 1985), family: exact("family", count: 32),
            checkpoint: PolicyCheckpoint(version: counter(version[...]), digest: exact("policy-digest", count: 32)),
            wire: read("protocol-policy", maximum: 8192))
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
enum EnrollmentPolicyMode { case original, joint, independent }
private func activateEnrollment(_ owner: ContinuityEnrollment, policy: EnrollmentPolicyMode) throws -> ContinuityDevice {
    switch policy {
    case .original: return try owner.activate()
    case .joint: return try owner.activatePolicyContinuation()
    case .independent: return try owner.activatePolicyRenewal()
    }
}
private func refusedEnrollmentActivation(_ owner: ContinuityEnrollment, code: Int32, policy: EnrollmentPolicyMode = .original) throws -> ContinuityFailure {
    switch Result(catching: { try activateEnrollment(owner, policy: policy) }) {
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
private func transferEnrollment(_ path: String, witness: WitnessCarrier, policy: EnrollmentPolicyMode) throws -> (ContinuityDevice, WeakEnrollment) {
    let owner = try prepareEnrollment(path, witness: witness, create: false)
    let old = WeakEnrollment(owner)
    let device = try disposingEnrollment(owner) {
        try owner.finishOpen()
        if policy != .original {
            let targetPath = URL(fileURLWithPath: path).appendingPathComponent(policy == .joint ? "continued-sdk" : "independent-sdk").path
            let target = try EnrollmentInputs(records: FixtureRecords(path: targetPath)).policyDocument()
            try owner.selectContinuedPolicy(path: targetPath, target: target)
        }
        let device = try activateEnrollment(owner, policy: policy)
        do {
            try owner.close()
            _ = try expectedEnrollmentFailure(2) { try owner.status() }
            _ = try expectedEnrollmentFailure(2) { try owner.request() }
            _ = try expectedEnrollmentFailure(2) { try owner.prepareStorage() }
            _ = try expectedEnrollmentFailure(2) { try owner.cancel() }
            _ = try refusedEnrollmentActivation(owner, code: 2, policy: policy)
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
private func activatedEnrollment(_ path: String, witness: WitnessCarrier, policy: EnrollmentPolicyMode = .original) throws -> ContinuityDevice {
    let (device, old) = try transferEnrollment(path, witness: witness, policy: policy)
    do {
        try require(old.value == nil, "old enrollment wrapper retained after transfer")
        _ = try device.nextAccountOperation()
        _ = try FixtureRecords(path: path).retain(policy == .original ? "swift-enrollment-transfer" : policy == .joint ? "swift-policy-enrollment-transfer" : "swift-independent-policy-transfer",
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
    let policy: EnrollmentPolicyMode
    var continued: Bool { policy != .original }
    func openPeer(path peerPath: String, session: SessionID?, witness: WitnessCarrier) throws -> ConfiguredClientOwner {
        try require(!continued || session != nil, "continued enrollment requires an original session")
        let device = try activatedEnrollment(path, witness: witness, policy: policy)
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
        if mode.hasPrefix("enrollment-independent-policy-") {
            return try independentPolicyEnrollmentCommand(owner, path: path, inputs: inputs,
                mode: String(mode.dropFirst("enrollment-independent-policy-".count)))
        }
        if mode.hasPrefix("enrollment-policy-") {
            return try policyEnrollmentCommand(owner, path: path, inputs: inputs, mode: mode)
        }
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
    case "enrollment-credential-witness-commit-no-sdk", "enrollment-credential-witness-commit-policy-expired", "enrollment-credential-witness-commit-cancellation", "enrollment-credential-witness-commit-transport-error":
        let expected: Int32 = mode == "enrollment-credential-witness-commit-transport-error" ? 218 :
            mode == "enrollment-credential-witness-commit-cancellation" ? 215 :
            mode == "enrollment-credential-witness-commit-policy-expired" ? 104 : 702
        let operation = try CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32))
        let statement = try CredentialRenewalStatementID(bytes: inputs.exact("credential-statement", count: 32))
        _ = try expectedEnrollmentFailure(expected) { try owner.commitWitnessedCredentialRenewal(operation: operation, statement: statement) }
        _ = try expectedEnrollmentFailure(2) { try owner.credentialRenewalStatus() }
        return "credential-witness-commit-refused:\(expected)"
    case "enrollment-credential-witness-cancel-prepare":
        let cancellation = try owner.prepareWitnessedCredentialCancellation()
        try require(cancellation == owner.prepareWitnessedCredentialCancellation(), "cancellation reservation changed original head")
        try inputs.publish("credential-cancellation", cancellation.bytes)
        try require(owner.status() == original, "cancellation reservation replaced registration")
        return "credential-witness-cancel-reserved"
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

private func policyEnrollmentCommand(_ owner: ContinuityEnrollment, path: String,
    inputs: EnrollmentInputs, mode: String) throws -> String {
    if mode == "enrollment-policy-witness-cancel-prepare" {
        let original = try owner.status()
        let operation = try CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32))
        let statement = try CredentialRenewalStatementID(bytes: inputs.exact("credential-statement", count: 32))
        let credential = try CredentialRenewalStatementID(bytes: inputs.exact("policy-credential-statement", count: 32))
        let cancellation = try owner.prepareWitnessedPolicyCancellation()
        try require(cancellation == owner.prepareWitnessedPolicyCancellation(), "policy cancellation changed original reservation")
        try require(cancellation.bytes.count == 281 && cancellation.adoptsPolicy && cancellation.operation == operation &&
            cancellation.statement == statement && cancellation.credentialStatement == credential,
            "policy cancellation differs from original joint operation")
        try inputs.publish("policy-cancellation", cancellation.bytes)
        try require(owner.status() == original, "policy cancellation changed registration")
        return "policy-witness-cancellation-prepared"
    }
    let targetPath = URL(fileURLWithPath: path).appendingPathComponent("continued-sdk").path
    let target = try EnrollmentInputs(records: FixtureRecords(path: targetPath)).policyDocument()
    if mode == "enrollment-policy-recover-history" || mode == "enrollment-policy-history-pending" {
        let operation = try CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32))
        let statement = try CredentialRenewalStatementID(bytes: inputs.exact("credential-statement", count: 32))
        if mode == "enrollment-policy-history-pending" {
            _ = try expectedEnrollmentFailure(215) {
                try owner.recoverHistoricalPolicyContinuation(operation: operation, statement: statement, target: target)
            }
            _ = try expectedEnrollmentFailure(2) { try owner.status() }
            return "policy-history-pending"
        }
        let status = try owner.recoverHistoricalPolicyContinuation(operation: operation, statement: statement, target: target)
        guard case .committed = status else { throw ProbeFailure.contract("historical policy result is not Committed") }
        try require(owner.status().phase == .active, "history changed registration phase")
        return renewalText(status)
    }
    if mode == "enrollment-policy-current-refused" {
        _ = try expectedEnrollmentFailure(104) { try owner.selectContinuedPolicy(path: targetPath, target: target) }
        _ = try expectedEnrollmentFailure(2) { try owner.status() }
        return "policy-expired-current-refused"
    }
    try owner.selectContinuedPolicy(path: targetPath, target: target)
    let status: CredentialRenewalStatus
    switch mode {
    case "enrollment-policy-stage", "enrollment-policy-carry-stage", "enrollment-policy-stage-conflict":
        let operation = try CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32))
        let grant = try inputs.read("credential-renewal", maximum: 65536), pin = try inputs.pin(renewal: true)
        if mode == "enrollment-policy-carry-stage" {
            status = try owner.stageContinuedCredentialRenewal(grant: grant, pin: pin, operation: operation)
        } else {
            let previousPath = URL(fileURLWithPath: path).appendingPathComponent("previous-policy").path
            let previous = try EnrollmentInputs(records: FixtureRecords(path: previousPath)).policyDocument()
            let kind = try inputs.exact("policy-predecessor-kind", count: 1)[0]
            try require(kind <= 1, "policy predecessor kind")
            let previousT = try kind == 0 ? nil : PolicyContinuationStatementID(bytes: inputs.exact("policy-predecessor-statement", count: 32))
            let approvals = try inputs.read("policy-approvals", maximum: 7746)
            let stage = {
                try owner.stagePolicyContinuation(grant: grant, pin: pin, operation: operation,
                    approvals: approvals, previous: previous, previousAuthorization: previousT)
            }
            if mode == "enrollment-policy-stage-conflict" {
                _ = try expectedEnrollmentFailure(211, stage)
                _ = try expectedEnrollmentFailure(2) { try owner.status() }
                return "policy-stage-conflict"
            }
            status = try stage()
        }
        guard case .pending = status else { throw ProbeFailure.contract("policy stage did not retain Pending") }
    case "enrollment-policy-witness-prepare", "enrollment-policy-witness-carry-prepare":
        let original = try owner.status()
        let operation = try CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32))
        let statement = try CredentialRenewalStatementID(bytes: inputs.exact("credential-statement", count: 32))
        let proposal = try owner.prepareWitnessedPolicyContinuation()
        try require(proposal == owner.prepareWitnessedPolicyContinuation(), "policy witness preparation changed original target")
        let carries = mode == "enrollment-policy-witness-carry-prepare"
        try require(proposal.bytes.count == 329 && proposal.adoptsPolicy == !carries && proposal.operation == operation && proposal.statement == statement,
            "policy witness proposal differs from original joint operation")
        if carries {
            let retained = try PolicyContinuationStatementID(bytes: inputs.exact("policy-retained-statement", count: 32))
            try require(proposal.credentialStatement == statement && proposal.policyStatement == retained,
                "policy witness carry changed retained T")
        }
        try inputs.publish("policy-proposal", proposal.bytes)
        try require(owner.status() == original, "policy witness preparation changed registration")
        return "policy-witness-prepared"
    case "enrollment-policy-witness-commit":
        let original = try owner.status()
        status = try owner.commitWitnessedPolicyContinuation(
            operation: CredentialRenewalID(bytes: inputs.exact("credential-operation", count: 32)),
            statement: CredentialRenewalStatementID(bytes: inputs.exact("credential-statement", count: 32)))
        guard case .committed = status else { throw ProbeFailure.contract("policy witness commit did not report Committed") }
        try require(owner.status() == original, "policy witness commit changed registration")
    case "enrollment-policy-reconcile":
        status = try owner.reconcilePolicyContinuation()
        guard case .committed = status else { throw ProbeFailure.contract("policy reconciliation did not retain Committed") }
    case "enrollment-policy-activate-missing-witness":
        _ = try refusedEnrollmentActivation(owner, code: 216, policy: .joint)
        _ = try expectedEnrollmentFailure(2) { try owner.status() }
        return "policy-required-witness-refused"
    case "enrollment-policy-activate":
        let device = try owner.activatePolicyContinuation()
        return try disposingEnrollmentDevice(device) {
            _ = try expectedEnrollmentFailure(2) { try owner.status() }
            _ = try device.nextAccountOperation()
            return "policy-device-active"
        }
    default: throw ProbeFailure.contract("unknown policy continuation command")
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
func continuedPeerCommand(_ args: [String], witness: WitnessCarrier) throws {
    switch args.first {
    case "continued-peer-refused":
        try require(args.count == 5, "continued peer refusal arguments")
        let role: BootstrapRole
        switch args[3] {
        case "1": role = .initiator
        case "2": role = .responder
        default: throw ProbeFailure.contract("continued peer role must be 1 or 2")
        }
        let session: SessionID = try decode(args[4])
        let device = try activatedEnrollment(args[1], witness: witness, policy: .joint)
        try disposingEnrollmentDevice(device) {
            try refusedRenewalPeer(device, path: args[2], role: role, session: session, code: 104)
        }
        try output("continued-peer-expired-refused")
    case "continued-peer-admit":
        try require(args.count == 3, "continued peer admission arguments")
        let device = try activatedEnrollment(args[1], witness: witness, policy: .joint)
        try disposingEnrollmentDevice(device) {
            try admitRenewalPeer(device, path: args[2], controls: true)
        }
        try output("continued-peer-admitted")
    default: throw ProbeFailure.contract("unknown continued peer command")
    }
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

// Same-host fixture format shared with the C/Rust harness. This serializes only
// public wrapper fields, never an internal codec/handle or a portable network API.
private struct IndependentRequestFixture {
    var bytes: [UInt8]
    var offset = 0
    mutating func take(_ count: Int) throws -> [UInt8] {
        try require(count >= 0 && offset <= bytes.count && count <= bytes.count - offset, "truncated independent request")
        defer { offset += count }; return Array(bytes[offset..<(offset + count)])
    }
    mutating func u32() throws -> UInt32 { try take(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) } }
    mutating func u64() throws -> UInt64 { try take(8).withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) } }
    mutating func roster() throws -> RosterCheckpoint { try RosterCheckpoint(version: u64(), digest: take(32)) }
    mutating func policy() throws -> PolicyCheckpoint { try PolicyCheckpoint(version: u64(), digest: take(32)) }
    mutating func blob() throws -> [UInt8] {
        let length = Int(try u32()), value = try take(8192)
        try require((1...8192).contains(length) && value.dropFirst(length).allSatisfy({ $0 == 0 }), "invalid public record tail")
        return Array(value.prefix(length))
    }
    static func read(_ bytes: [UInt8]) throws -> PolicyRenewalRequest {
        try require(bytes.count == 33176, "independent request fixture width")
        var r = Self(bytes: bytes)
        let operation = try PolicyRenewalID(bytes: r.take(32)), journal = try JournalID(bytes: r.take(32))
        let owner = try r.take(32), original = try r.take(32), current = try r.take(32)
        let roster = try r.roster(), originalPolicy = try r.policy(), previousPolicy = try r.policy(), authorization = try r.take(32)
        let previous: PolicyAuthorizationID?
        switch try r.u32() {
        case 0: try require(authorization.allSatisfy({ $0 == 0 }), "absent authorization nonzero"); previous = nil
        case 1: previous = try PolicyAuthorizationID(bytes: authorization)
        default: throw ProbeFailure.contract("unknown optional authorization")
        }
        try require(r.u32() == 0, "reserved scope word")
        let scope = try PolicyRenewalScope(operation: operation, journal: journal, originalOwner: owner,
            originalCredential: original, currentCredential: current, currentRoster: roster,
            originalPolicy: originalPolicy, previousPolicy: previousPolicy, previousAuthorization: previous)
        let value = try PolicyRenewalRequest(scope: scope, account: AccountID(bytes: r.take(32)), originalRosterCheckpoint: r.roster(),
            originalCredential: r.blob(), originalRoster: r.blob(), currentCredential: r.blob(), currentRoster: r.blob())
        try require(r.offset == bytes.count, "trailing independent request fixture"); return value
    }
    private static func number<T: FixedWidthInteger>(_ value: T) -> [UInt8] { var value = value; return withUnsafeBytes(of: &value) { Array($0) } }
    static func write(_ r: PolicyRenewalRequest) throws -> [UInt8] {
        let s = r.scope
        var bytes = s.operation.bytes + s.journal.bytes + s.originalOwner + s.originalCredential + s.currentCredential
        bytes += number(s.currentRoster.version) + s.currentRoster.digest
        bytes += number(s.originalPolicy.version) + s.originalPolicy.digest
        bytes += number(s.previousPolicy.version) + s.previousPolicy.digest
        bytes += s.previousAuthorization?.bytes ?? [UInt8](repeating: 0, count: 32)
        bytes += number(UInt32(s.previousAuthorization == nil ? 0 : 1)) + number(UInt32(0))
        bytes += r.account.bytes + number(r.originalRosterCheckpoint.version) + r.originalRosterCheckpoint.digest
        for value in [r.originalCredential, r.originalRoster, r.currentCredential, r.currentRoster] {
            bytes += number(UInt32(value.count)) + value + [UInt8](repeating: 0, count: 8192 - value.count)
        }
        try require(bytes.count == 33176, "encoded independent request width"); return bytes
    }
}
private func independentPolicyStatus(_ value: PolicyRenewalStatus) -> String {
    let zero = String(repeating: "0", count: 64)
    func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    func record(_ phase: UInt32, _ operation: PolicyRenewalID, _ statement: PolicyRenewalStatementID, _ target: PolicyCheckpoint,
        reason: UInt32 = 0, roster: RosterCheckpoint? = nil, time: UInt64 = 0) -> String {
        [String(phase), String(reason), hex(operation.bytes), hex(statement.bytes), String(target.version), hex(target.digest),
            roster.map { String($0.version) } ?? "0", roster.map { hex($0.digest) } ?? zero, String(time)].joined(separator: "\n")
    }
    switch value {
    case .absent: return ["0", "0", zero, zero, "0", zero, "0", zero, "0"].joined(separator: "\n")
    case let .pending(operation, statement, target): return record(1, operation, statement, target)
    case let .committed(operation, statement, target): return record(2, operation, statement, target)
    case let .abandonedUncommitted(operation, statement, target, reason, roster, time):
        return record(3, operation, statement, target, reason: reason.rawValue, roster: roster, time: time)
    }
}
private func independentPolicyEnrollmentCommand(_ owner: ContinuityEnrollment, path: String,
    inputs: EnrollmentInputs, mode: String) throws -> String {
    if mode.hasPrefix("witness-") {
        return try witnessedIndependentPolicyCommand(owner, path: path, inputs: inputs, mode: String(mode.dropFirst(8)))
    }
    let operation = try PolicyRenewalID(bytes: inputs.exact("independent-operation", count: 32))
    switch mode {
    case "request":
        let request = try owner.policyRenewalRequest(operation: operation)
        try inputs.publish("independent-request", IndependentRequestFixture.write(request)); return "request-saved"
    case "request-refused":
        _ = try expectedEnrollmentFailure(215) { try owner.policyRenewalRequest(operation: operation) }
        _ = try expectedEnrollmentFailure(2) { try owner.status() }; return "request-refused:215"
    case "status": return try independentPolicyStatus(owner.policyRenewalStatus())
    case "pending":
        try require(owner.pendingPolicyRenewalApproval(operation: operation) == inputs.read("independent-first-approvals", maximum: 8192), "first policy signatures changed")
        return "pending-exact"
    default: break
    }
    let targetPath = URL(fileURLWithPath: path).appendingPathComponent("independent-sdk").path
    let target = try EnrollmentInputs(records: FixtureRecords(path: targetPath)).policyDocument()
    if ["resolve", "resolve-pending", "resolve-conflict", "resolve-scope", "resolve-cancelled"].contains(mode) {
        let statement = try PolicyRenewalStatementID(bytes: inputs.exact("independent-statement", count: 32))
        let expected: Int32 = mode == "resolve-pending" ? 215 : mode == "resolve-conflict" ? 211 : mode == "resolve-scope" ? 103 : mode == "resolve-cancelled" ? 302 : 0
        if expected == 302 { try owner.cancel() }
        if expected != 0 {
            _ = try expectedEnrollmentFailure(expected) { try owner.resolvePolicyRenewal(operation: operation, statement: statement, target: target) }
            _ = try expectedEnrollmentFailure(expected == 302 ? 302 : 2) { try owner.status() }
            return expected == 215 ? "pending-unresolved:215" : "policy-resolve-refused:\(expected)"
        }
        return try independentPolicyStatus(owner.resolvePolicyRenewal(operation: operation, statement: statement, target: target))
    }
    try owner.selectContinuedPolicy(path: targetPath, target: target)
    switch mode {
    case "stage", "stage-corrupt-scope", "stage-corrupt-certificate", "stage-cancelled":
        let retained = try IndependentRequestFixture.read(inputs.read("independent-request", maximum: 33176))
        let s = retained.scope
        var operation = s.operation.bytes
        if mode == "stage-corrupt-scope" { operation[0] ^= 1 }
        let scope = try PolicyRenewalScope(operation: PolicyRenewalID(bytes: operation), journal: s.journal,
            originalOwner: s.originalOwner, originalCredential: s.originalCredential, currentCredential: s.currentCredential,
            currentRoster: s.currentRoster, originalPolicy: s.originalPolicy, previousPolicy: s.previousPolicy, previousAuthorization: s.previousAuthorization)
        var certificate = retained.originalCredential
        if mode == "stage-corrupt-certificate" { certificate[certificate.count - 1] ^= 1 }
        let request = try PolicyRenewalRequest(scope: scope, account: retained.account, originalRosterCheckpoint: retained.originalRosterCheckpoint,
            originalCredential: certificate, originalRoster: retained.originalRoster, currentCredential: retained.currentCredential, currentRoster: retained.currentRoster)
        let pin = try inputs.pin(renewal: false)
        if mode == "stage-cancelled" { try owner.cancel() }
        let stage = { try owner.stagePolicyRenewal(request: request, originalPin: pin, currentPin: pin,
            approvals: inputs.read("independent-approvals", maximum: 8192), previous: inputs.policyDocument()) }
        if mode == "stage" { return try independentPolicyStatus(stage()) }
        let expected: Int32 = mode == "stage-corrupt-scope" ? 103 : mode == "stage-corrupt-certificate" ? 102 : 302
        _ = try expectedEnrollmentFailure(expected, stage)
        _ = try expectedEnrollmentFailure(expected == 302 ? 302 : 2) { try owner.status() }
        return "stage-refused:\(expected)"
    case "reconcile": return try independentPolicyStatus(owner.reconcilePolicyRenewal())
    case "activate":
        let device = try owner.activatePolicyRenewal()
        try disposingEnrollmentDevice(device) {
            try owner.close(); _ = try expectedEnrollmentFailure(2) { try owner.status() }
            _ = try device.nextAccountOperation()
        }
        return "independent-device-active"
    default: throw ProbeFailure.contract("unknown independent policy mode")
    }
}

private func witnessedIndependentPolicyCommand(_ owner: ContinuityEnrollment, path: String,
    inputs: EnrollmentInputs, mode: String) throws -> String {
    func select() throws {
        let targetPath = URL(fileURLWithPath: path).appendingPathComponent("independent-sdk").path
        try owner.selectContinuedPolicy(path: targetPath, target: EnrollmentInputs(records: FixtureRecords(path: targetPath)).policyDocument())
    }
    func retained() throws -> IndependentPolicyProposal {
        try IndependentPolicyProposal(retainedBytes: inputs.exact("independent-witness-proposal", count: 296))
    }
    switch mode {
    case "request":
        let operation = try PolicyRenewalID(bytes: inputs.exact("independent-operation", count: 32))
        let request = try owner.witnessedPolicyRenewalRequest(operation: operation)
        try inputs.publish("independent-request", IndependentRequestFixture.write(request))
        return "request-saved"
    case "prepare":
        try select()
        let previous = try inputs.policyDocument()
        let proposal = try owner.prepareWitnessedPolicyRenewal(previous: previous)
        try require(owner.prepareWitnessedPolicyRenewal(previous: previous) == proposal, "P retry changed original sealed target")
        try inputs.publish("independent-witness-proposal", proposal.bytes)
        return "proposal-saved"
    case "recover", "recover-absent":
        let result = try owner.recoverWitnessedPolicyRenewalPreparation()
        if mode == "recover-absent" {
            try require(result == nil, "unexpected local P preparation")
            return "preparation-absent"
        }
        try require(result == retained(), "original P preparation changed")
        return "preparation-exact"
    case "progress":
        let progress = try owner.witnessedPolicyRenewalProgress()
        func record(_ phase: UInt32, _ proposal: IndependentPolicyProposal, _ target: PolicyCheckpoint, _ retired: Bool) throws -> String {
            try require(proposal == retained(), "P progress changed original proposal")
            return "\(phase)\n\(retired ? 1 : 0)\n\(target.version)\n\(renewalHex(target.digest))"
        }
        switch progress {
        case .absent: return "0\n0\n0\n" + String(repeating: "0", count: 64)
        case let .reserved(proposal, target): return try record(1, proposal, target, false)
        case let .applied(proposal, target, retired): return try record(2, proposal, target, retired)
        case let .closed(proposal, target, retired): return try record(3, proposal, target, retired)
        }
    default: break
    }
    try require(["commit", "commit-lost", "close", "close-lost", "reconcile", "reconcile-lost", "substitute", "cancelled"].contains(mode), "unknown witness P mode")
    var bytes = try retained().bytes
    if mode == "substitute" { bytes[295] ^= 1 }
    let proposal = try IndependentPolicyProposal(retainedBytes: bytes)
    if mode == "cancelled" { try owner.cancel() }
    let expected: Int32 = mode == "substitute" ? 211 : mode == "cancelled" ? 302 : mode.hasSuffix("-lost") ? 218 : 0
    let command: () throws -> IndependentPolicyState
    if mode == "commit" || mode == "commit-lost" {
        try select(); command = { try owner.commitWitnessedPolicyRenewal(proposal) }
    } else if mode == "close" || mode == "close-lost" {
        command = { try owner.closeWitnessedPolicyRenewal(proposal) }
    } else {
        command = { try owner.reconcileWitnessedPolicyRenewal(proposal) }
    }
    if expected != 0 {
        _ = try expectedEnrollmentFailure(expected, command)
        _ = try expectedEnrollmentFailure(expected == 302 ? 302 : 2) { try owner.status() }
        return "witness-refused:\(expected)"
    }
    return "witness-state:\(try command().rawValue)"
}
