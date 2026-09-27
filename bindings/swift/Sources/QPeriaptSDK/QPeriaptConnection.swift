// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPeriapt
import Foundation
import Network

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
extension QPeriaptClient {
    /// Establish a fresh authenticated connection, including policy/context
    /// confirmation. No classic fallback, automatic replay, or session resumption.
    /// DNS and TCP setup consume the same absolute handshake budget as TLS.
    public func connect(host: String, port: UInt16, serverName: String) async throws -> QPeriaptConnection {
        guard !host.isEmpty, host.utf8.count <= 253, let port = NWEndpoint.Port(rawValue: port), port.rawValue != 0 else {
            throw QPeriaptSDKError(operation: "TCP address", code: Q_PERIAPT_ERR_LENGTH)
        }
        try Task.checkCancellation()
        let engine = try engine(serverName: serverName)
        let connection = QPeriaptConnection(engine: engine, transport: NetworkTransport(host: host, port: port))
        try await connection.establish()
        return connection
    }
}

/// One request/response may be in flight. A concurrent request is rejected
/// without cancelling the first. Cancellation, network errors and deadlines
/// close the connection; create a new connection explicitly to reconnect.
/// Delivered response bytes belong to the caller and cannot be revoked/erased
/// by the SDK. This is neither durable RPC nor an exactly-once execution promise.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
public actor QPeriaptConnection {
    private let engine: ConnectionEngine
    private let transport: NetworkTransport
    private var busy = false
    private var closed = false

    init(engine: ConnectionEngine, transport: NetworkTransport) {
        self.engine = engine
        self.transport = transport
    }

    func establish() async throws {
        try admit()
        busy = true
        defer { busy = false }
        do {
            try await transport.start(milliseconds: engine.progress().remainingMilliseconds)
            try await drive(until: UInt32(Q_PERIAPT_CONNECTION_READY))
        } catch {
            try await failAndClose(error)
        }
    }

    /// Send up to 64 KiB, and return the authenticated response for that sequence.
    public func request(_ payload: [UInt8]) async throws -> [UInt8] {
        try admit()
        guard payload.count <= Q_PERIAPT_CONNECTION_MAX_PAYLOAD_BYTES else {
            throw QPeriaptSDKError(operation: "request payload", code: Q_PERIAPT_ERR_LENGTH)
        }
        busy = true
        defer { busy = false }
        do {
            try Task.checkCancellation()
            let sequence = try engine.sendRequest(payload)
            try await drive(until: UInt32(Q_PERIAPT_CONNECTION_RESPONSE_READY))
            let result = try engine.takeResponse(expectedSequence: sequence)
            try Task.checkCancellation()
            return result
        } catch {
            try await failAndClose(error)
        }
    }

    /// Abort outstanding I/O and revoke the native owner. Repeated close is safe.
    public func close() async throws {
        closed = true
        await transport.abort()
        try engine.close()
    }

    /// Send TLS close_notify after completing the outstanding response. Rejects
    /// a busy connection; use close() to cancel a request immediately instead.
    public func shutdown() async throws {
        try admit()
        busy = true
        defer { busy = false }
        do {
            try Task.checkCancellation()
            try engine.shutdown()
            var drained = false
            while true {
                let progress: ConnectionEngine.Progress
                do { progress = try engine.progress() }
                catch let error as QPeriaptSDKError where error.code == Q_PERIAPT_ERR_CLOSED && drained { break }
                guard progress.phase == Q_PERIAPT_CONNECTION_CLOSING, progress.wantsWrite else {
                    throw QPeriaptSDKError(operation: "TLS shutdown progress", code: Q_PERIAPT_ERR_INTERNAL)
                }
                let output = try engine.drain()
                try await transport.send(Data(output), milliseconds: progress.remainingMilliseconds)
                drained = true
            }
            try await close()
        } catch {
            try await failAndClose(error)
        }
    }

    private func admit() throws {
        guard !closed else { throw QPeriaptSDKError(operation: "connection", code: Q_PERIAPT_ERR_CLOSED) }
        guard !busy else { throw QPeriaptSDKError(operation: "connection busy", code: Q_PERIAPT_ERR_NOT_READY) }
    }

    private func drive(until phase: UInt32) async throws {
        while true {
            try Task.checkCancellation()
            let progress = try engine.progress()
            if progress.wantsWrite {
                let output = try engine.drain()
                try await transport.send(Data(output), milliseconds: progress.remainingMilliseconds)
                continue
            }
            if progress.phase == phase { return }
            let (data, endOfInput) = try await transport.receive(milliseconds: progress.remainingMilliseconds)
            if let data, !data.isEmpty { try engine.feed(Array(data)) }
            if endOfInput { try engine.endInput() }
        }
    }

    private func failAndClose(_ error: Error) async throws -> Never {
        // Preserve the operational error if disposal succeeds. A disposal error
        // is observable and replaces it; native storage is never freed mid-borrow.
        try await close()
        throw error
    }
}
