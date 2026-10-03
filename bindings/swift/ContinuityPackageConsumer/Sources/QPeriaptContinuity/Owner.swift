// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

/// Native failures retain their exact code, UTF-8 diagnostic and truncation flag.
/// Setup reference lifetime checks also use Closed/Busy with wrapper diagnostics.
/// No code implies that a mutation was absent or that a new operation may replace it.
public struct ContinuityFailure: Error, Sendable, Equatable, CustomStringConvertible {
    public let code: Int32
    public let message: String
    public let truncated: Bool
    public var description: String { "Continuity \(code): \(message)" }
}

public enum ContinuityBoundaryError: Error, Sendable, Equatable {
    case inputLength, invalidText, invalidCommitStatus, malformedDiagnostic, malformedOutput
}

func checked(_ code: Int32, _ error: inout qpc_error_v1) throws {
    guard error.code == code, error.length <= 512, error.truncated <= 1,
          code == 0 ? error.length == 0 && error.truncated == 0 : error.length > 0 else {
        throw ContinuityBoundaryError.malformedDiagnostic
    }
    let length = Int(error.length)
    let bytes = withUnsafeBytes(of: &error.message) { Array($0.prefix(length)) }
    guard let text = String(bytes: bytes, encoding: .utf8) else {
        throw ContinuityBoundaryError.malformedDiagnostic
    }
    if code != 0 {
        throw ContinuityFailure(code: code, message: text, truncated: error.truncated == 1)
    }
}

public enum InitiationTag: Sendable {}
public enum SessionTag: Sendable {}
public enum MessageTag: Sendable {}

/// Public protocol IDs are distinct types. They never contain secret key bytes.
public struct ContinuityID<Tag: Sendable>: Sendable, Equatable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) throws {
        guard bytes.count == 32 else { throw ContinuityBoundaryError.inputLength }
        self.bytes = bytes
    }
}
public typealias InitiationID = ContinuityID<InitiationTag>
public typealias SessionID = ContinuityID<SessionTag>
public typealias MessageID = ContinuityID<MessageTag>

public enum PrekeyQuality: UInt32, Sendable {
    case oneTimeBoth = 1, reusableBoth = 2, signedClassicalOneTimePQ = 3
    case oneTimeClassicalLastResortPQ = 4
}
public enum WitnessCarrier: Sendable {
    case local
    case signedTCP(address: String, timeoutMilliseconds: UInt32)
    case mutualTLS(address: String, timeoutMilliseconds: UInt32)
}
public enum MessageStatus: UInt8, Sendable {
    case absent = 0, reserved = 1, committed = 2, acknowledged = 3
    case resolutionPending = 4, deliveryUnknown = 5, reservationAbandoned = 6
}
public enum Consumption: UInt8, Sendable {
    case confirmed = 1, prefixPending = 2
}
public struct Establishment: Sendable {
    public let session: SessionID
    public let exchanges: UInt16
}
public struct SendResult: Sendable {
    public let consumption: Consumption
    public let exchanges: UInt16
}

func textBytes(_ value: String, maximum: Int) throws -> [UInt8] {
    guard !value.isEmpty, value.utf8.count <= maximum else {
        throw ContinuityBoundaryError.inputLength
    }
    guard !value.utf8.contains(0) else { throw ContinuityBoundaryError.invalidText }
    return Array(value.utf8)
}

/// The sole mutable field is private and all access is under `lock`. A call
/// receives a strong snapshot before unlocking; clearing releases its old value
/// after unlocking. No native operation or destructor runs under this lock.
/// The compiler cannot derive NSLock's protection, so only this small reference
/// cell supplies the manual Sendable conformance.
private final class NativeParentReference: @unchecked Sendable {
    private let lock = NSLock()
    private var value: NativeOwner?
    init(_ value: NativeOwner) { self.value = value }
    func snapshot() -> NativeOwner? { lock.withLock { value } }
    func clear() {
        let released = lock.withLock {
            let previous = value
            value = nil
            return previous
        }
        withExtendedLifetime(released) {}
    }
}

/// One shared reference to the native original-installation owner. Only an
/// immutable handle crosses threads; the native registry serializes operations.
/// Every call pins this wrapper through return, including concurrent cancellation.
final class NativeOwner: Sendable {
    private let handle: UInt64
    // The native registry does not retain language objects. A live peer must
    // prevent ARC from closing its parent, including while prepared or in flight.
    private let parent: NativeParentReference?
    private init(handle: UInt64, parent: NativeOwner? = nil) {
        self.handle = handle
        self.parent = parent.map(NativeParentReference.init)
    }

    /// Snapshot configuration without installation I/O. Call finishOpen before
    /// operations. A cancelled or failed activation never gains operational authority.
    static func prepare(path: String, kind: UInt32, quality: UInt32,
                        witness: WitnessCarrier, session: SessionID? = nil,
                        setup: SetupIntent? = nil) throws -> NativeOwner {
        let pathBytes = try textBytes(path, maximum: 4096)
        var handle: UInt64 = 0
        var error = qpc_error_v1()
        func prepare(_ carrier: UInt32, _ witness: UnsafePointer<qpc_witness_v1>?) throws {
            var options = qpc_open_options_v1(kind: kind, quality: quality,
                                             carrier: carrier, witness: witness)
            let code = pathBytes.withUnsafeBufferPointer { path in
                if let setup {
                    switch setup {
                    case .create:
                        return qpc_setup_v1_prepare_create(path.baseAddress, path.count, &options, &handle, &error)
                    case .resume:
                        return qpc_setup_v1_prepare_resume(path.baseAddress, path.count, &options, &handle, &error)
                    }
                }
                if let session {
                    return session.bytes.withUnsafeBufferPointer {
                        qpc_owner_v1_prepare_reopen(path.baseAddress, path.count, &options,
                            $0.baseAddress, &handle, &error)
                    }
                }
                return qpc_owner_v1_prepare_open(path.baseAddress, path.count, &options, &handle, &error)
            }
            try checked(code, &error)
        }
        switch witness {
        case .local:
            try prepare(0, nil)
        case let .signedTCP(address, timeout), let .mutualTLS(address, timeout):
            let addressBytes = try textBytes(address, maximum: 128)
            try addressBytes.withUnsafeBufferPointer { address in
                var options = qpc_witness_v1(address: address.baseAddress,
                    address_length: address.count, timeout_ms: timeout)
                try withUnsafePointer(to: &options) {
                    if case .signedTCP = witness { try prepare(1, $0) }
                    else { try prepare(2, $0) }
                }
            }
        }
        guard handle != 0 else { throw ContinuityBoundaryError.malformedOutput }
        return NativeOwner(handle: handle)
    }

    static func preparePeer(parent: NativeOwner, path: String, quality: PrekeyQuality,
                            role: BootstrapRole, session: SessionID?) throws -> NativeOwner {
        let path = try textBytes(path, maximum: 4096)
        var result: UInt64 = 0
        var error = qpc_error_v1()
        let code = parent.call { parent in
            path.withUnsafeBufferPointer { path in
                if let session {
                    return session.bytes.withUnsafeBufferPointer {
                        qpc_peer_v1_prepare_reopen(parent, path.baseAddress, path.count,
                            quality.rawValue, role.rawValue, $0.baseAddress, &result, &error)
                    }
                }
                return qpc_peer_v1_prepare(parent, path.baseAddress, path.count,
                    quality.rawValue, role.rawValue, &result, &error)
            }
        }
        try checked(code, &error)
        guard result != 0 else { throw ContinuityBoundaryError.malformedOutput }
        return NativeOwner(handle: result, parent: parent)
    }

    func call<T>(_ body: (UInt64) throws -> T) rethrows -> T {
        let retainedParent = parent?.snapshot()
        return try withExtendedLifetime((self, retainedParent)) { try body(handle) }
    }

    public func finishOpen() throws {
        try call { handle in
            var error = qpc_error_v1()
            try checked(qpc_owner_v1_finish_open(handle, &error), &error)
        }
    }
    /// One-way; join active work and close, then reopen the same installation.
    public func cancel() throws {
        try call { handle in
            var error = qpc_error_v1()
            try checked(qpc_owner_v1_cancel(handle, &error), &error)
        }
    }
    /// Busy is an error and preserves the owner. All aliases observe a successful close.
    public func close() throws {
        do {
            try call { handle in
                var error = qpc_error_v1()
                try checked(qpc_owner_v1_close(handle, &error), &error)
            }
        } catch let failure as ContinuityFailure where failure.code == QPC_CLOSED {
            // Preserve the closed diagnostic while releasing an already stale
            // peer's ownership link. Busy and unknown failures retain the link.
            parent?.clear()
            throw failure
        }
        parent?.clear()
    }
    deinit {
        var error = qpc_error_v1()
        let code = qpc_owner_v1_close(handle, &error)
        if code != QPC_OK && code != QPC_CLOSED {
            // Explicit close is throwing. ARC disposal cannot throw; preserve
            // unexpected cleanup failure observability without exposing paths.
            NSLog("Q-Periapt Continuity owner disposal failed with status %d", code)
        }
    }
}

/// Operational authority for one original installation or admitted peer context,
/// retaining its native owner and any parent through each call. It cannot be
/// converted to cleanup authority.
public final class ContinuityOwner: Sendable {
    private let native: NativeOwner
    private init(native: NativeOwner) { self.native = native }

    static func preparePeer(parent: NativeOwner, path: String, quality: PrekeyQuality,
                            role: BootstrapRole, session: SessionID?) throws -> ContinuityOwner {
        try ContinuityOwner(native: NativeOwner.preparePeer(parent: parent, path: path,
            quality: quality, role: role, session: session))
    }

    /// Copies configuration only; finishOpen activates synchronously and can be
    /// cancelled from another thread. Failed activation grants no authority.
    public static func prepare(path: String, quality: PrekeyQuality,
                               witness: WitnessCarrier = .local) throws -> ContinuityOwner {
        try ContinuityOwner(native: NativeOwner.prepare(path: path, kind: 1,
            quality: quality.rawValue, witness: witness))
    }

    /// Opens only the original installation; never initializes or repairs one.
    public static func open(path: String, quality: PrekeyQuality,
                            witness: WitnessCarrier = .local) throws -> ContinuityOwner {
        let owner = try prepare(path: path, quality: quality, witness: witness)
        try owner.finishOpen()
        return owner
    }

    /// Prepare explicit restoration of this existing session without installation I/O.
    /// finishOpen requires the original Active state and current authority; it may
    /// authenticate expired advertisements but never creates missing session state.
    public static func prepareReopen(path: String, quality: PrekeyQuality, session: SessionID,
                                     witness: WitnessCarrier = .local) throws -> ContinuityOwner {
        try ContinuityOwner(native: NativeOwner.prepare(path: path, kind: 1,
            quality: quality.rawValue, witness: witness, session: session))
    }
    /// Restore only the selected original session, without a fresh-open fallback.
    public static func reopen(path: String, quality: PrekeyQuality, session: SessionID,
                              witness: WitnessCarrier = .local) throws -> ContinuityOwner {
        let owner = try prepareReopen(path: path, quality: quality, session: session, witness: witness)
        try owner.finishOpen()
        return owner
    }

    func call<T>(_ body: (UInt64) throws -> T) rethrows -> T {
        try withExtendedLifetime(self) { try native.call(body) }
    }
    public func finishOpen() throws { try native.finishOpen() }
    /// One-way; join active work and close before reopening the same installation.
    public func cancel() throws { try native.cancel() }
    /// Busy preserves ownership. Successful close is observed by every alias.
    public func close() throws { try native.close() }

    public func establish(peer: String, request: InitiationID) throws -> Establishment {
        let peer = try textBytes(peer, maximum: 128)
        return try call { handle in
            var error = qpc_error_v1(), exchanges: UInt16 = 0
            var session = [UInt8](repeating: 0, count: 32)
            let code = peer.withUnsafeBufferPointer { peer in
                request.bytes.withUnsafeBufferPointer { request in
                    session.withUnsafeMutableBufferPointer {
                        qpc_owner_v1_establish(handle, peer.baseAddress, peer.count,
                            request.baseAddress, $0.baseAddress, &exchanges, &error)
                    }
                }
            }
            try checked(code, &error)
            guard (1...8).contains(exchanges) else { throw ContinuityBoundaryError.malformedOutput }
            return Establishment(session: try SessionID(bytes: session), exchanges: exchanges)
        }
    }

    public func nextMessage(session: SessionID) throws -> MessageID {
        try call { handle in
            var error = qpc_error_v1()
            var message = [UInt8](repeating: 0, count: 32)
            let code = session.bytes.withUnsafeBufferPointer { session in
                message.withUnsafeMutableBufferPointer {
                    qpc_owner_v1_next_message(handle, session.baseAddress, $0.baseAddress, &error)
                }
            }
            try checked(code, &error)
            return try MessageID(bytes: message)
        }
    }

    /// Retain this exact message ID after every unknown result. Confirmed and
    /// prefix-pending consumption are separate outcomes; no automatic retry occurs.
    public func send(peer: String, session: SessionID, message: MessageID,
                     plaintext: [UInt8], associatedData: [UInt8]) throws -> SendResult {
        let peer = try textBytes(peer, maximum: 128)
        return try call { handle in
            var error = qpc_error_v1(), exchanges: UInt16 = 0
            var consumption: UInt8 = 0
            let code = peer.withUnsafeBufferPointer { peer in
                session.bytes.withUnsafeBufferPointer { session in
                    message.bytes.withUnsafeBufferPointer { message in
                        plaintext.withUnsafeBufferPointer { plaintext in
                            associatedData.withUnsafeBufferPointer { ad in
                                qpc_owner_v1_send(handle, peer.baseAddress, peer.count,
                                    session.baseAddress, message.baseAddress, plaintext.baseAddress,
                                    plaintext.count, ad.baseAddress, ad.count, &consumption, &exchanges, &error)
                            }
                        }
                    }
                }
            }
            try checked(code, &error)
            guard let value = Consumption(rawValue: consumption), (1...8).contains(exchanges) else {
                throw ContinuityBoundaryError.malformedOutput
            }
            return SendResult(consumption: value, exchanges: exchanges)
        }
    }

    public func status(session: SessionID, message: MessageID) throws -> MessageStatus {
        try call { handle in
            var error = qpc_error_v1(), status: UInt8 = 255
            let code = session.bytes.withUnsafeBufferPointer { session in
                message.bytes.withUnsafeBufferPointer {
                    qpc_owner_v1_message_status(handle, session.baseAddress, $0.baseAddress, &status, &error)
                }
            }
            try checked(code, &error)
            guard let status = MessageStatus(rawValue: status) else {
                throw ContinuityBoundaryError.malformedOutput
            }
            return status
        }
    }

    public func rekey(peer: String, session: SessionID, target: UInt64) throws -> UInt64 {
        let peer = try textBytes(peer, maximum: 128)
        return try call { handle in
            var error = qpc_error_v1(), completed: UInt64 = 0
            let code = peer.withUnsafeBufferPointer { peer in
                session.bytes.withUnsafeBufferPointer {
                    qpc_owner_v1_rekey(handle, peer.baseAddress, peer.count,
                                      $0.baseAddress, target, &completed, &error)
                }
            }
            try checked(code, &error)
            guard completed == target else { throw ContinuityBoundaryError.malformedOutput }
            return completed
        }
    }
}
