// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner

public enum PrekeyPublicationTag: Sendable {}
public enum PrekeyInventoryTag: Sendable {}
public typealias PrekeyPublicationID = ContinuityID<PrekeyPublicationTag>
public typealias PrekeyInventoryID = ContinuityID<PrekeyInventoryTag>

public enum PublicationKeyKind: UInt32, Sendable {
    case signedClassical = 1, oneTimeClassical = 2, lastResortPQ = 3, oneTimePQ = 4
}
/// Public original intent only. Reuse is admitted by the native inventory, not this value.
public struct PublicationKey: Sendable, Equatable {
    public let kind: PublicationKeyKind
    public let validFrom: UInt64
    public let validUntil: UInt64
    public let reusedRequest: PrekeyInventoryID?
    public init(kind: PublicationKeyKind, validFrom: UInt64, validUntil: UInt64,
                reusedRequest: PrekeyInventoryID? = nil) throws {
        guard validFrom < validUntil, validUntil < UInt64.max,
              reusedRequest == nil || reusedRequest?.bytes.contains(where: { $0 != 0 }) == true else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        self.kind = kind; self.validFrom = validFrom; self.validUntil = validUntil
        self.reusedRequest = reusedRequest
    }
}
/// Retain this complete plan and the next ID before dispatch. The directory
/// expectation must come from an independent trusted source.
public struct PublicationPlan: Sendable, Equatable {
    public let directory: [UInt8]
    public let validFrom: UInt64
    public let validUntil: UInt64
    public let keys: [PublicationKey]
    public init(directory: [UInt8], validFrom: UInt64, validUntil: UInt64, keys: [PublicationKey]) throws {
        guard directory.count == 32, (1...1024).contains(keys.count) else { throw ContinuityBoundaryError.inputLength }
        guard directory.contains(where: { $0 != 0 }), validFrom < validUntil, validUntil < UInt64.max,
              keys.allSatisfy({ validFrom <= $0.validFrom && $0.validUntil <= validUntil }),
              keys.contains(where: { $0.kind == .signedClassical }), keys.contains(where: { $0.kind == .lastResortPQ }) else {
            throw ContinuityBoundaryError.invalidEnrollmentInput
        }
        let reused = keys.compactMap(\.reusedRequest).map(\.bytes)
        guard Set(reused).count == reused.count else { throw ContinuityBoundaryError.invalidEnrollmentInput }
        self.directory = directory; self.validFrom = validFrom; self.validUntil = validUntil; self.keys = keys
    }
    func withNative<T>(_ body: (UnsafePointer<qpc_publication_plan_v1>) throws -> T) rethrows -> T {
        let records = keys.map { key in
            var value = qpc_publication_key_v1()
            value.kind = key.kind.rawValue; value.reuse = key.reusedRequest == nil ? 0 : 1
            value.valid_from = key.validFrom; value.valid_until = key.validUntil
            if let reused = key.reusedRequest { withUnsafeMutableBytes(of: &value.request) { $0.copyBytes(from: reused.bytes) } }
            return value
        }
        return try records.withUnsafeBufferPointer { keys in
            var value = qpc_publication_plan_v1()
            value.struct_size = UInt32(MemoryLayout<qpc_publication_plan_v1>.size)
            value.valid_from = validFrom; value.valid_until = validUntil
            value.keys = keys.baseAddress; value.count = keys.count
            withUnsafeMutableBytes(of: &value.directory) { $0.copyBytes(from: directory) }
            return try withUnsafePointer(to: &value, body)
        }
    }
}

/// Historical local state; prepared never means remote publication or current usability.
public enum PublicationStatus: Sendable, Equatable {
    case absent, retired
    case reserved(intent: [UInt8])
    case prepared(intent: [UInt8], manifest: [UInt8], artifact: [UInt8])
}
func publicationStatus(_ value: qpc_publication_status_v1) throws -> PublicationStatus {
    let intent = octets(value.intent), manifest = octets(value.manifest), artifact = octets(value.artifact)
    guard value.reserved_zero == 0 else { throw ContinuityBoundaryError.malformedOutput }
    switch value.state {
    case 0, 3:
        guard (intent + manifest + artifact).allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        return value.state == 0 ? .absent : .retired
    case 1:
        guard intent.contains(where: { $0 != 0 }), (manifest + artifact).allSatisfy({ $0 == 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        return .reserved(intent: intent)
    case 2:
        guard [intent, manifest, artifact].allSatisfy({ $0.contains(where: { $0 != 0 }) }) else { throw ContinuityBoundaryError.malformedOutput }
        return .prepared(intent: intent, manifest: manifest, artifact: artifact)
    default: throw ContinuityBoundaryError.malformedOutput
    }
}

/// Complete native-verified public result. Copying/parsing bytes is not independent
/// signature verification, directory freshness or permission to use a consumed key.
public struct PreparedPublication: Sendable, Equatable {
    public let id: PrekeyPublicationID
    public let intent: [UInt8]
    public let artifact: [UInt8]
    public let canonicalBytes: [UInt8]
    public let manifest: [UInt8]
    /// Original plan order. This is different from membership-proof order.
    public let inventoryRequests: [PrekeyInventoryID]
    /// Canonical manifest leaf order.
    public let membershipProofs: [[UInt8]]
    init(bytes: [UInt8], expectedID: PrekeyPublicationID, plan: PublicationPlan) throws {
        guard bytes.count <= 2 * 1024 * 1024 else { throw ContinuityBoundaryError.malformedOutput }
        var position = 0
        func take(_ count: Int) throws -> [UInt8] {
            guard count >= 0, count <= bytes.count - position else { throw ContinuityBoundaryError.malformedOutput }
            defer { position += count }
            return Array(bytes[position..<(position + count)])
        }
        func number(_ count: Int) throws -> Int { try take(count).reduce(0) { ($0 << 8) | Int($1) } }
        guard try take(8) == Array("QPPUBA01".utf8), try take(32) == expectedID.bytes,
              expectedID.bytes.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        let intent = try take(32), artifact = try take(32)
        guard intent.contains(where: { $0 != 0 }), artifact.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.malformedOutput }
        let manifestLength = try number(4)
        guard manifestLength == 3667 else { throw ContinuityBoundaryError.malformedOutput }
        let manifest = try take(manifestLength)
        guard try number(2) == plan.keys.count else { throw ContinuityBoundaryError.malformedOutput }
        var requests: [PrekeyInventoryID] = []
        for key in plan.keys {
            let id = try PrekeyInventoryID(bytes: take(32))
            guard id.bytes.contains(where: { $0 != 0 }), key.reusedRequest == nil || id == key.reusedRequest else { throw ContinuityBoundaryError.malformedOutput }
            requests.append(id)
        }
        guard Set(requests.map(\.bytes)).count == requests.count else { throw ContinuityBoundaryError.malformedOutput }
        var proofs: [[UInt8]] = []
        for index in plan.keys.indices {
            let length = try number(2)
            guard (62...1534).contains(length) else { throw ContinuityBoundaryError.malformedOutput }
            let proof = try take(length)
            guard Int(proof[0]) * 256 + Int(proof[1]) == index else { throw ContinuityBoundaryError.malformedOutput }
            proofs.append(proof)
        }
        guard position == bytes.count else { throw ContinuityBoundaryError.malformedOutput }
        self.id = expectedID; self.intent = intent; self.artifact = artifact
        self.canonicalBytes = bytes; self.manifest = manifest
        self.inventoryRequests = requests; self.membershipProofs = proofs
    }
}

extension ContinuityDevice {
    public func nextPublication() throws -> PrekeyPublicationID {
        try call { handle in
            var id = [UInt8](repeating: 0, count: 32), error = qpc_error_v1()
            let code = id.withUnsafeMutableBufferPointer { qpc_device_v1_next_publication(handle, $0.baseAddress, &error) }
            try checked(code, &error)
            guard id.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.malformedOutput }
            return try PrekeyPublicationID(bytes: id)
        }
    }
    public func status(publication: PrekeyPublicationID) throws -> PublicationStatus {
        try call { handle in
            var value = qpc_publication_status_v1(), error = qpc_error_v1()
            let code = publication.bytes.withUnsafeBufferPointer { qpc_device_v1_publication_status(handle, $0.baseAddress, &value, &error) }
            try checked(code, &error)
            return try publicationStatus(value)
        }
    }
    /// Prepare or recover the exact original plan. Errors do not establish absence.
    /// Retain the ID/plan and reopen the original enrollment for uncertain failures.
    public func preparePublication(_ id: PrekeyPublicationID, plan: PublicationPlan) throws -> PreparedPublication {
        try call { handle in
            try plan.withNative { input in
                var capacity = 0, error = qpc_error_v1()
                try checked(qpc_device_v1_publication_size_bound(input, &capacity, &error), &error)
                guard (1...2 * 1024 * 1024).contains(capacity) else { throw ContinuityBoundaryError.malformedOutput }
                var bytes = [UInt8](repeating: 0, count: capacity), length = 0
                let code = id.bytes.withUnsafeBufferPointer { id in
                    bytes.withUnsafeMutableBufferPointer { output in
                        qpc_device_v1_prepare_publication(handle, id.baseAddress, input, output.baseAddress, output.count, &length, &error)
                    }
                }
                try checked(code, &error)
                guard length > 0, length <= bytes.count else { throw ContinuityBoundaryError.malformedOutput }
                return try PreparedPublication(bytes: Array(bytes.prefix(length)), expectedID: id, plan: plan)
            }
        }
    }
    private func publicationMutation(_ id: PrekeyPublicationID, digest: [UInt8], abandon: Bool) throws -> PublicationStatus {
        guard digest.count == 32, digest.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.inputLength }
        return try call { handle in
            var value = qpc_publication_status_v1(), error = qpc_error_v1()
            let code = id.bytes.withUnsafeBufferPointer { id in
                digest.withUnsafeBufferPointer { digest in
                    abandon ? qpc_device_v1_abandon_publication(handle, id.baseAddress, digest.baseAddress, &value, &error) :
                        qpc_device_v1_retire_publication(handle, id.baseAddress, digest.baseAddress, &value, &error)
                }
            }
            try checked(code, &error)
            let status = try publicationStatus(value)
            guard status == .retired else { throw ContinuityBoundaryError.malformedOutput }
            return status
        }
    }
    public func retirePublication(_ id: PrekeyPublicationID, artifact: [UInt8]) throws -> PublicationStatus {
        try publicationMutation(id, digest: artifact, abandon: false)
    }
    public func abandonPublication(_ id: PrekeyPublicationID, intent: [UInt8]) throws -> PublicationStatus {
        try publicationMutation(id, digest: intent, abandon: true)
    }
}
