// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

private struct ClientError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
private func withFile<T>(_ file: FileHandle, _ body: (FileHandle) throws -> T) throws -> T {
    let result: Result<T, Error>
    do { result = .success(try body(file)) } catch { result = .failure(error) }
    do { try file.close() } catch {
        switch result {
        case .success: throw error
        case .failure(let original): throw ClientError("\(original); file close also failed: \(error)")
        }
    }
    return try result.get()
}
private func load(_ source: URL, _ name: String, _ maximum: Int) throws -> [UInt8] {
    try withFile(FileHandle(forReadingFrom: source.appendingPathComponent(name))) { file in
        var bytes = Data()
        while bytes.count <= maximum {
            guard let next = try file.read(upToCount: maximum + 1 - bytes.count), !next.isEmpty else { break }
            bytes.append(next)
        }
        guard !bytes.isEmpty, bytes.count <= maximum else { throw ClientError("input width: \(name)") }
        return Array(bytes)
    }
}
private func exact(_ source: URL, _ name: String, _ count: Int) throws -> [UInt8] {
    let bytes = try load(source, name, count)
    guard bytes.count == count else { throw ClientError("exact input width: \(name)") }
    return bytes
}
private func counter(_ bytes: ArraySlice<UInt8>) throws -> UInt64 {
    guard bytes.count == 8 else { throw ClientError("counter width") }
    return bytes.reduce(0) { ($0 << 8) | UInt64($1) }
}
private func write(_ bytes: [UInt8], to path: String) throws {
    let descriptor = path.withCString { open($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600) }
    guard descriptor >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
    try withFile(FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)) { try $0.write(contentsOf: Data(bytes)) }
}
private func trust(_ source: URL, _ recoverable: Bool) throws -> SdkPolicyTrust {
    let root = try exact(source, "sdk-root", 1952)
    if recoverable {
        return try .recoverable(scope: exact(source, "recovery-scope", 32), initialRoot: root,
                                recoveryRoot: exact(source, "recovery-root", 1952))
    }
    return try .fixed(root: root)
}
private func policy(_ source: URL) throws -> PolicyDocument {
    try PolicyDocument(root: exact(source, "policy-root", 1985), family: exact(source, "family", 32),
        checkpoint: PolicyCheckpoint(version: counter(exact(source, "policy-version", 8)[...]),
                                     digest: exact(source, "policy-digest", 32)), wire: load(source, "protocol-policy", 8192))
}
private func initial(_ source: URL, _ recoverable: Bool) throws -> InstallationConfiguration {
    try InstallationConfiguration(
        sdk: InitialSdkPolicy(trust: trust(source, recoverable), policy: load(source, "sdk-policy", 65536),
            signature: exact(source, "sdk-signature", 3309),
            recoveryEnrollment: recoverable ? exact(source, "recovery-enrollment", 3309) : nil),
        protocolPolicy: policy(source),
        tls: LocalTlsIdentity(certificate: load(source, "tls-cert", 8192), privateKey: load(source, "tls-key", 8192)))
}
private func witness(_ source: URL, _ carrier: String?, wrong: Bool) throws -> ConfigurationWitness? {
    guard let carrier else { return nil }
    var identity = try exact(source, "witness-id", 32)
    if wrong { identity[0] ^= 1 }
    let key = try exact(source, "witness-public", 1985)
    guard let address = String(bytes: try load(source, "witness-address", 128), encoding: .utf8) else { throw ClientError("address encoding") }
    if carrier == "signed" { return try .signedTCP(identity: identity, publicKey: key, address: address, timeoutMilliseconds: 3000) }
    guard carrier == "tls", let name = String(bytes: try load(source, "witness-tls-name", 128), encoding: .utf8) else { throw ClientError("TLS carrier/name") }
    return try .mutualTLS(identity: identity, publicKey: key, address: address, timeoutMilliseconds: 3000,
        peerCertificate: load(source, "witness-tls-peer", 8192), serverName: name,
        localIdentity: LocalTlsIdentity(certificate: load(source, "witness-tls-cert", 8192), privateKey: load(source, "witness-tls-key", 8192)))
}
private func peerInput(_ source: URL) throws -> PeerConfiguration {
    let path = source.appendingPathComponent("peer", isDirectory: true)
    func device(_ prefix: String) throws -> PeerDeviceExpectation {
        let pin = try AccountPin(account: AccountID(bytes: exact(path, prefix + "-account", 32)),
            root: exact(path, prefix + "-root", 1985), family: exact(path, "family", 32),
            checkpoint: RosterCheckpoint(version: counter(exact(path, prefix + "-roster-version", 8)[...]), digest: exact(path, prefix + "-roster-digest", 32)))
        return try PeerDeviceExpectation(account: pin, device: exact(path, prefix + "-device", 16), generation: counter(exact(path, prefix + "-generation", 8)[...]))
    }
    guard let name = String(bytes: try load(path, "tls-peer-name", 128), encoding: .utf8) else { throw ClientError("peer name UTF-8") }
    return try PeerConfiguration(initiator: device("initiator"), responder: device("responder"), directory: exact(path, "directory", 32),
        bundle: load(path, "bootstrap.bundle", 65536), tlsPeerCertificate: load(path, "tls-peer", 8192), tlsPeerName: name)
}
private func traffic(_ device: ContinuityDevice, source: URL, mode: String) throws -> [UInt8] {
    let input = try peerInput(source)
    guard let address = String(bytes: try load(source, "connection-address", 128), encoding: .utf8) else { throw ClientError("address UTF-8") }
    let original: SessionID? = mode == "connect" ? nil : try SessionID(bytes: exact(source, "connection-session", 32))
    let peer: ContinuityOwner
    if let original { peer = try device.preparePeerReopen(configuration: input, quality: .oneTimeBoth, role: .initiator, session: original) }
    else { peer = try device.preparePeer(configuration: input, quality: .oneTimeBoth, role: .initiator) }
    var result: Result<[UInt8], Error>
    do {
        try peer.finishOpen()
        if let session = original {
            let uncertain = mode == "uncertain-send"
            let message = uncertain ? try peer.nextMessage(session: session) : try MessageID(bytes: exact(source, "connection-message", 32))
            do {
                let sent = try peer.send(peer: address, session: session, message: message, plaintext: Array("persisted before process exit".utf8), associatedData: Array("configuration-v1".utf8))
                guard !uncertain, sent.consumption == .confirmed else { throw ClientError("incorrect delivery result") }
            } catch let failure as ContinuityFailure {
                guard uncertain, [303, 309, 310, 311].contains(failure.code) else { throw failure }
            }
            guard try peer.status(session: session, message: message) == (uncertain ? .committed : .acknowledged) else { throw ClientError("original message status differs") }
            result = .success(session.bytes + message.bytes)
        } else {
            result = .success(try peer.establish(peer: address, request: InitiationID(bytes: exact(source, "connection-initiation", 32))).session.bytes)
        }
    } catch { result = .failure(error) }
    do { try peer.close() } catch {
        switch result { case .success: throw error; case .failure(let original): throw ClientError("\(original); peer close also failed: \(error)") }
    }
    return try result.get()
}
private func expect(_ code: Int32, _ body: () throws -> Void) throws {
    do { try body(); throw ClientError("expected native refusal \(code)") }
    catch let failure as ContinuityFailure { guard failure.code == code else { throw failure } }
}

@main
private struct Main {
    static func main() {
        do { try run() } catch {
            do { try FileHandle.standardError.write(contentsOf: Data("\(error)\n".utf8)) }
            catch { exit(74) }
            exit(1)
        }
    }
    private static func checkArcCapacity(_ source: URL, _ target: String, _ recoverable: Bool) throws {
        let input = try initial(source, recoverable)
        var owners: [ContinuityConfiguration?] = []
        for index in 0..<64 {
            owners.append(try .prepareCreate(path: target + ".\(index)", input: input))
        }
        try expect(4) { _ = try ContinuityConfiguration.prepareCreate(path: target + ".overflow", input: input) }
        weak var released: ContinuityConfiguration?
        var replacements: [ContinuityConfiguration] = []
        for index in [0, 1] {
            released = owners[index]
            owners[index] = nil
            guard released == nil else { throw ClientError("ARC retained configuration facade") }
            replacements.append(try ContinuityConfiguration.prepareCreate(path: target + ".replacement.\(index)", input: input))
        }
        for owner in owners { try owner?.close() }
        for replacement in replacements { try replacement.close() }
        for index in 0..<64 {
            guard !FileManager.default.fileExists(atPath: target + ".\(index)") else { throw ClientError("prepare performed filesystem work") }
        }
    }

    private static func checkTargetLease(_ enrollment: ContinuityEnrollment, source: URL,
                                        path: String, recoverable: Bool, reject: Bool) throws {
        let inputs = reject ? source : source.appendingPathComponent("continuation", isDirectory: true)
        let targetPath = path + (reject ? ".rejected-target" : ".continued-target")
        let target = try ContinuityConfiguration.prepareCreate(path: targetPath, input: initial(inputs, recoverable))
        try target.finishOpen()
        if reject {
            try expect(103) { try target.selectContinuationTarget(for: enrollment) }
            // An admitted error releases both leases even while the language
            // objects and their empty registry handles are still retained.
            for (directory, configuration) in [(path, source), (targetPath, inputs)] {
                let probe = try ContinuityConfiguration.prepareOpen(path: directory, trust: trust(configuration, recoverable), protocolPolicy: policy(configuration))
                try probe.finishOpen(); try probe.close()
            }
        } else {
            try target.selectContinuationTarget(for: enrollment)
            try target.close()
            try expect(2) { try target.cancel() }
            let busy = try ContinuityConfiguration.prepareOpen(path: targetPath, trust: trust(inputs, recoverable), protocolPolicy: policy(inputs))
            try expect(703) { try busy.finishOpen() }
            try busy.close()
        }
        try enrollment.close()
        // Retaining the transferred target object must not retain the SDK lease.
        let reopened = try ContinuityConfiguration.prepareOpen(path: targetPath, trust: trust(inputs, recoverable), protocolPolicy: policy(inputs))
        try reopened.finishOpen(); try reopened.close()
        withExtendedLifetime(target) {}
        if reject { try target.close() }
    }

    static func run() throws {
        let args = CommandLine.arguments
        guard args.count == 6 || args.count == 7 else { throw ClientError("argument count") }
        let mode = args[1], profile = args[2]
        guard ["create", "resume", "reconcile", "reconcile-refused", "cancel-create", "arc-capacity", "select-target", "select-target-reject", "prepare", "activate", "activate-missing", "activate-bad-receipt", "wrong-witness", "cancel", "enroll-local", "connect", "uncertain-send", "retry-send"].contains(mode),
              ["fixed", "recoverable"].contains(profile) else { throw ClientError("mode/profile") }
        let source = URL(fileURLWithPath: args[3], isDirectory: true), target = args[4], output = args[5]
        let carrier = args.count == 7 ? args[6] : nil
        let recoverable = profile == "recoverable"
        if mode == "arc-capacity" {
            try checkArcCapacity(source, target, recoverable)
            print("QPC_CONFIGURATION_ARC_PASS")
            return
        }
        // The temporary input value can disappear before finishOpen. No borrowed
        // Swift buffer may remain in the C configuration owner after preparation.
        let configuration: ContinuityConfiguration
        if mode == "create" || mode == "cancel-create" {
            configuration = try .prepareCreate(path: target, input: initial(source, recoverable))
        } else if mode == "reconcile" || mode == "reconcile-refused" {
            configuration = try .prepareReconcile(path: target, input: initial(source, recoverable))
        } else {
            configuration = try .prepareOpen(path: target, trust: trust(source, recoverable), protocolPolicy: policy(source))
        }
        var registration: ContinuityEnrollment?
        var device: ContinuityDevice?
        var result: Result<String, Error>
        do {
            if mode == "cancel-create" {
                try configuration.cancel()
                try expect(302) { try configuration.finishOpen() }
                guard !FileManager.default.fileExists(atPath: target) else { throw ClientError("cancelled creation wrote files") }
                result = .success("QPC_CONFIGURATION_CREATE_CANCELLED")
            } else if mode == "reconcile-refused" {
                try expect(107) { try configuration.finishOpen() }
                result = .success("QPC_CONFIGURATION_RECONCILE_REFUSED")
            } else {
            try configuration.finishOpen()
            let wire = try exact(source, "enrollment-intent", 72)
            let intent = try EnrollmentIntent(root: exact(source, "enrollment-root", 1985), device: Array(wire[0..<16]),
                generation: counter(wire[16..<24]), family: Array(wire[24..<56]),
                validFrom: counter(wire[56..<64]), validUntil: counter(wire[64..<72]))
            let selected = try witness(source, carrier, wrong: mode == "wrong-witness")
            if mode == "cancel" { try configuration.cancel() }
            if mode == "wrong-witness" || mode == "cancel" {
                try expect(mode == "cancel" ? 302 : 103) {
                    _ = try configuration.resumeEnrollment(intent: intent, witness: selected)
                }
                result = .success(mode == "cancel" ? "QPC_CONFIGURATION_CANCELLED" : "QPC_CONFIGURATION_WITNESS_SCOPE_REFUSED")
            } else {
                let owner = mode == "create" ? try configuration.createEnrollment(intent: intent, witness: selected)
                                             : try configuration.resumeEnrollment(intent: intent, witness: selected)
                registration = owner
                // A retained/transferred source must not close or pin the successor.
                try configuration.close()
                var bytes = try owner.request()
                var marker = "QPC_CONFIGURATION_REQUEST_PASS"
                if mode == "select-target" || mode == "select-target-reject" {
                    try checkTargetLease(owner, source: source, path: target, recoverable: recoverable, reject: mode == "select-target-reject")
                    registration = nil
                    marker = mode == "select-target" ? "QPC_CONFIGURATION_TARGET_LEASE_PASS" : "QPC_CONFIGURATION_TARGET_FAILURE_PASS"
                } else if mode == "prepare" || mode == "enroll-local" {
                    let pin = try AccountPin(account: AccountID(bytes: exact(source, "trusted-account", 32)),
                        root: exact(source, "enrollment-root", 1985), family: intent.family,
                        checkpoint: RosterCheckpoint(version: counter(exact(source, "trusted-roster-version", 8)[...]),
                                                     digest: exact(source, "trusted-roster-digest", 32)))
                    let journal = try owner.accept(certificate: load(source, "grant-certificate", 8192), roster: load(source, "grant-roster", 65536), pin: pin)
                    let prepared = try owner.prepareStorage()
                    if mode == "enroll-local" {
                        guard case .local(let actual) = prepared, actual == journal else { throw ClientError("local installation differs") }
                        device = try owner.activate(); try owner.close(); marker = "QPC_CONFIGURATION_LOCAL_ACTIVE"
                    } else {
                        guard case .requiresEnrollment(let genesis) = prepared, genesis.journal == journal else { throw ClientError("required genesis differs") }
                        bytes = [0, 0, 0, 2] + journal.bytes + genesis.subject + genesis.imageDigest
                        marker = "QPC_CONFIGURATION_GENESIS_PASS"
                    }
                } else if mode == "activate-missing" || mode == "activate-bad-receipt" {
                    try expect(mode == "activate-missing" ? 216 : 218) { _ = try owner.activate() }
                    marker = mode == "activate-missing" ? "QPC_CONFIGURATION_WITNESS_REQUIRED" : "QPC_CONFIGURATION_WITNESS_RECEIPT_REFUSED"
                } else if ["connect", "uncertain-send", "retry-send"].contains(mode) {
                    let active = try owner.activate(); device = active; try owner.close()
                    bytes = try traffic(active, source: source, mode: mode)
                    marker = mode == "connect" ? "QPC_CONFIGURATION_CONNECTION_PASS" : mode == "uncertain-send" ? "QPC_CONFIGURATION_UNKNOWN_COMMITTED" : "QPC_CONFIGURATION_ORIGINAL_ACKNOWLEDGED"
                } else if mode == "activate" {
                    device = try owner.activate()
                    try owner.close()
                    marker = "QPC_CONFIGURATION_ACTIVATION_PASS"
                }
                try write(bytes, to: output)
                result = .success(marker)
            }
            }
        } catch { result = .failure(error) }
        // Explicit cleanup checks every result. ARC is the final lifetime guard,
        // not a way to turn a failed close into a successful client run.
        let cleanup: [() throws -> Void] = [
            { if let device { try device.close() } },
            { if let registration { try registration.close() } },
            { try configuration.close() },
        ]
        for close in cleanup {
            do { try close() } catch {
                switch result {
                case .success: result = .failure(error)
                case .failure(let original): result = .failure(ClientError("\(original); owner close also failed: \(error)"))
                }
            }
        }
        print(try result.get())
    }
}
