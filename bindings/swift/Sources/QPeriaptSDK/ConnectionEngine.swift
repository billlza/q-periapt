// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPeriapt

/// Absolute native phase budgets, including application policy confirmation.
public struct QPeriaptConnectionLimits: Sendable {
    public var maxConnections: UInt32
    public var handshakeMilliseconds: UInt32
    public var requestMilliseconds: UInt32
    public var idleMilliseconds: UInt32

    public init(maxConnections: UInt32 = 8, handshakeMilliseconds: UInt32 = 10_000,
                requestMilliseconds: UInt32 = 5_000, idleMilliseconds: UInt32 = 30_000) {
        self.maxConnections = maxConnections
        self.handshakeMilliseconds = handshakeMilliseconds
        self.requestMilliseconds = requestMilliseconds
        self.idleMilliseconds = idleMilliseconds
    }
}

/// Standard TLS 1.3 + X25519MLKEM768 with mutual certificate authentication.
/// The peer leaf is pinned in addition to normal certificate/name validation.
/// The verified SDK policy and application context are confirmed inside TLS;
/// this does not change the standard TLS group's combiner or attest the peer.
public final class QPeriaptClient: Sendable {
    private let owned: OwnedHandle

    /// DER private-key bytes are borrowed only during construction. The caller
    /// remains responsible for protecting and erasing all of its Swift copies.
    /// Persist the runtime's trusted policy state before creating this endpoint.
    public init(runtime: QPeriaptRuntime, certificateDER: [UInt8], privateKeyDER: [UInt8],
                peerCertificateDER: [UInt8], applicationContext: [UInt8],
                limits: QPeriaptConnectionLimits = QPeriaptConnectionLimits()) throws {
        guard let size = UInt32(exactly: MemoryLayout<QPeriaptConnectionOptions>.size) else {
            throw QPeriaptSDKError(operation: "connection contract", code: Q_PERIAPT_ERR_LIMITS)
        }
        var endpoint: UInt64 = 0
        let status = runtime.owned.use { handle in
            certificateDER.withInput { certificate in
                privateKeyDER.withInput { privateKey in
                    peerCertificateDER.withInput { peerCertificate in
                        applicationContext.withInput { context in
                            var options = QPeriaptConnectionOptions(
                                struct_size: size,
                                extension_version: UInt32(Q_PERIAPT_SDK_EXTENSION_VERSION),
                                certificate: certificate, private_key: privateKey,
                                peer_certificate: peerCertificate, application_context: context,
                                max_connections: limits.maxConnections,
                                handshake_ms: limits.handshakeMilliseconds,
                                request_ms: limits.requestMilliseconds, idle_ms: limits.idleMilliseconds)
                            return q_periapt_sdk_connection_client_new(handle, &options, &endpoint)
                        }
                    }
                }
            }
        }
        try check(status, "create TLS client")
        owned = OwnedHandle(endpoint, parent: runtime.owned)
    }

    /// Revoke this endpoint and all its connections. During pending establishment
    /// or request I/O the async adapter rechecks native state every 100 ms;
    /// revocation does not require another network event. Already queued TCP
    /// bytes cannot be recalled. Idle connections are checked on their next use.
    public func close() throws { try owned.close() }

    func engine(serverName: String) throws -> ConnectionEngine {
        try owned.use { handle in
            var connection: UInt64 = 0
            let status = Array(serverName.utf8).withInput {
                q_periapt_sdk_connection_connect(handle, $0, &connection)
            }
            try check(status, "create TLS connection")
            return ConnectionEngine(owned: OwnedHandle(connection, parent: owned))
        }
    }
}

// These owners expose no raw handle or key getter. The actor transport adapter
// serializes complete request/response operations; the native registry protects
// each synchronous borrow and disposal even if endpoint/runtime close races it.
final class ConnectionEngine: Sendable {
    private let owned: OwnedHandle
    init(owned: OwnedHandle) { self.owned = owned }

    struct Progress: Sendable {
        let phase: UInt32
        let wantsWrite: Bool
        let remainingMilliseconds: UInt32
    }

    func progress() throws -> Progress {
        try owned.use { handle in
            var value = QPeriaptConnectionProgress(phase: 0, wants_write: 0, remaining_ms: 0)
            try check(q_periapt_sdk_connection_progress(handle, &value), "connection progress")
            guard (1...8).contains(value.phase), value.wants_write <= 1, value.remaining_ms > 0 else {
                throw QPeriaptSDKError(operation: "connection progress contract", code: Q_PERIAPT_ERR_INTERNAL)
            }
            return Progress(phase: value.phase, wantsWrite: value.wants_write == 1,
                            remainingMilliseconds: value.remaining_ms)
        }
    }

    func feed(_ ciphertext: [UInt8]) throws {
        try owned.use { handle in
            try ciphertext.withUnsafeBufferPointer { bytes in
                var offset = 0
                while offset < bytes.count {
                    var consumed: UInt32 = 0
                    let input = QPeriaptInput(data: bytes.baseAddress?.advanced(by: offset),
                                             len: UInt(bytes.count - offset))
                    try check(q_periapt_sdk_connection_feed(handle, input, &consumed), "receive TLS")
                    guard consumed > 0, Int(consumed) <= bytes.count - offset else {
                        throw QPeriaptSDKError(operation: "TLS consumption contract", code: Q_PERIAPT_ERR_INTERNAL)
                    }
                    offset += Int(consumed)
                }
            }
        }
    }

    func drain() throws -> [UInt8] {
        try owned.use { handle in
            var bytes = [UInt8](repeating: 0, count: Int(Q_PERIAPT_CONNECTION_MAX_TLS_IO_BYTES))
            var written: UInt32 = 0
            try check(bytes.withOutput { q_periapt_sdk_connection_drain(handle, $0, &written) }, "send TLS")
            guard written > 0, Int(written) <= bytes.count else {
                throw QPeriaptSDKError(operation: "TLS output contract", code: Q_PERIAPT_ERR_INTERNAL)
            }
            bytes.removeSubrange(Int(written)..<bytes.count)
            return bytes
        }
    }

    func endInput() throws {
        try owned.use { try check(q_periapt_sdk_connection_end_input($0), "TLS end of input") }
    }

    func sendRequest(_ bytes: [UInt8]) throws -> UInt64 {
        try owned.use { handle in
            var sequence: UInt64 = 0
            try check(bytes.withInput { q_periapt_sdk_connection_send_request(handle, $0, &sequence) }, "send request")
            return sequence
        }
    }

    func takeResponse(expectedSequence: UInt64) throws -> [UInt8] {
        try owned.use { handle in
            var count: UInt32 = 0
            try check(q_periapt_sdk_connection_message_size(handle, &count), "response size")
            guard count <= Q_PERIAPT_CONNECTION_MAX_PAYLOAD_BYTES else {
                throw QPeriaptSDKError(operation: "response size contract", code: Q_PERIAPT_ERR_INTERNAL)
            }
            var bytes = [UInt8](repeating: 0, count: max(1, Int(count)))
            var written: UInt32 = 0
            var sequence: UInt64 = 0
            try check(bytes.withOutput {
                q_periapt_sdk_connection_take_response(handle, $0, &written, &sequence)
            }, "receive response")
            guard written == count, sequence == expectedSequence else {
                throw QPeriaptSDKError(operation: "response contract", code: Q_PERIAPT_ERR_INTERNAL)
            }
            bytes.removeSubrange(Int(written)..<bytes.count)
            return bytes
        }
    }

    func shutdown() throws {
        try owned.use { try check(q_periapt_sdk_connection_shutdown($0), "TLS shutdown") }
    }

    func close() throws { try owned.close() }
}
