// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

/// Authenticated, durably committed inbox data. The application must atomically
/// persist its effect and deduplication by session/message before returning.
/// This owned Swift copy can be retained; the application protects/erases copies.
public struct ReceivedMessage: Sendable {
    public let session: SessionID
    public let message: MessageID
    public let plaintext: [UInt8]
}

public enum ServedExchange: Sendable, Equatable {
    case established(SessionID)
    case consumed(session: SessionID, message: MessageID, duplicate: Bool)
}

/// Optional application status for an explicitly unresolved transaction. Zero is
/// forbidden because it would tell the native owner that consumption committed.
public struct ApplicationCommitRefusal: Error, Sendable, Equatable {
    public let status: Int32
    public let reason: String
    public init(status: Int32, reason: String) throws {
        guard status != 0 else { throw ContinuityBoundaryError.invalidCommitStatus }
        self.status = status
        self.reason = reason
    }
}

/// A failed callback preserves both its original Swift cause and the native
/// outcome. It never authorizes replaying an external effect under a new ID.
public struct ContinuityApplicationFailure: Error, Sendable {
    public let nativeError: any Error
    public let applicationError: any Error
}

// One synchronous invocation owns this box; the native ABI retains neither its
// context pointer nor callback. There is no cross-call or global error storage.
final class CommitInvocation {
    let body: (ReceivedMessage) throws -> Void
    var failure: (any Error)?
    init(_ body: @escaping (ReceivedMessage) throws -> Void) { self.body = body }

    func invoke(session: UnsafePointer<UInt8>?, message: UnsafePointer<UInt8>?,
                plaintext: UnsafePointer<UInt8>?, length: Int) -> Int32 {
        do {
            guard let session, let message, length >= 0, length <= 16 * 1024,
                  length == 0 || plaintext != nil else { throw ContinuityBoundaryError.malformedOutput }
            let delivered = try ReceivedMessage(
                session: SessionID(bytes: Array(UnsafeBufferPointer(start: session, count: 32))),
                message: MessageID(bytes: Array(UnsafeBufferPointer(start: message, count: 32))),
                plaintext: Array(UnsafeBufferPointer(start: plaintext, count: length)))
            try body(delivered)
            return 0
        } catch {
            failure = error
            return (error as? ApplicationCommitRefusal)?.status ?? 1
        }
    }
}

func servedExchange(_ record: inout qpc_served_v1) throws -> ServedExchange {
    let session = try SessionID(bytes: withUnsafeBytes(of: &record.session) { Array($0) })
    let message = withUnsafeBytes(of: &record.message) { Array($0) }
    switch record.kind {
    case 1:
        guard record.duplicate == 0, message.allSatisfy({ $0 == 0 }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        return .established(session)
    case 2:
        guard record.duplicate <= 1 else { throw ContinuityBoundaryError.malformedOutput }
        return .consumed(session: session, message: try MessageID(bytes: message), duplicate: record.duplicate == 1)
    default: throw ContinuityBoundaryError.malformedOutput
    }
}

extension ContinuityOwner {
    /// Bind one listener owned by this handle. Repeated listen is an error;
    /// successful close releases the listener. Port zero requests an ephemeral port.
    public func listen(address: String) throws -> UInt16 {
        let address = try textBytes(address, maximum: 128)
        return try call { handle in
            var port: UInt16 = 0, error = qpc_error_v1()
            let code = address.withUnsafeBufferPointer {
                qpc_owner_v1_listen(handle, $0.baseAddress, $0.count, &port, &error)
            }
            try checked(code, &error)
            guard port != 0 else { throw ContinuityBoundaryError.malformedOutput }
            return port
        }
    }

    /// Receive one bootstrap or application exchange synchronously. The callback
    /// runs on the calling thread after native authentication and inbox commit.
    /// Return normally only after durable effect+deduplication; throw for failure
    /// or unknown commit. Exact retries may invoke it again. Already consumed
    /// messages skip it. Reentrant close/operations are Busy; cancel is available.
    /// Callbacks are cooperative and cannot be preempted by a network deadline.
    public func serve(commit: @escaping (ReceivedMessage) throws -> Void) throws -> ServedExchange {
        let invocation = CommitInvocation(commit)
        return try call { handle in
            var result = qpc_served_v1(), error = qpc_error_v1()
            let code = withExtendedLifetime(invocation) {
                // The context is created here and borrowed only during this exact
                // synchronous C call. No caller-provided raw pointer is accepted.
                qpc_owner_v1_serve(handle, { context, session, message, plaintext, length in
                    guard let context else { return 1 }
                    let invocation = Unmanaged<CommitInvocation>.fromOpaque(context).takeUnretainedValue()
                    return invocation.invoke(session: session, message: message, plaintext: plaintext, length: length)
                }, Unmanaged.passUnretained(invocation).toOpaque(), &result, &error)
            }
            do { try checked(code, &error) }
            catch {
                if let cause = invocation.failure {
                    throw ContinuityApplicationFailure(nativeError: error, applicationError: cause)
                }
                throw error
            }
            guard invocation.failure == nil else { throw ContinuityBoundaryError.malformedOutput }
            return try servedExchange(&result)
        }
    }

    /// Serve a control exchange for the caller-selected original session.
    public func serveRekey(session: SessionID) throws -> UInt64 {
        try call { handle in
            var epoch: UInt64 = 0, error = qpc_error_v1()
            let code = session.bytes.withUnsafeBufferPointer {
                qpc_owner_v1_serve_rekey(handle, $0.baseAddress, &epoch, &error)
            }
            try checked(code, &error)
            return epoch
        }
    }
}
