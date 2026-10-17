// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPeriapt
import Foundation
import Network

/// One bounded, cancellable TCP operation at a time. TLS is implemented by the
/// native engine, so this transport deliberately uses plain TCP parameters.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
actor NetworkTransport {
    enum Event: Sendable {
        case connected
        case sent
        case received(Data?, endOfInput: Bool)
    }
    private enum Operation {
        case start
        case send(Data)
        case receive
    }
    private struct Pending {
        let id: UInt64
        let deadline: UInt64
        let continuation: CheckedContinuation<Event, Error>
    }

    private let connection: NWConnection
    private let checkNativeState: @Sendable () throws -> Void
    // Only pending I/O polls native revocation. Idle connections do not wake,
    // and I/O finishing before the first tick adds no native calls. Preserve
    // the original absolute deadline even if the native phase later changes.
    private static let stateCheckInterval: UInt64 = 100_000_000
    private let queue = DispatchQueue(label: "dev.qperiapt.connection")
    private var started = false
    private var nextID: UInt64 = 1
    private var pending: Pending?
    private var timer: Task<Void, Never>?
    private var failure: Error?

    init(host: String, port: NWEndpoint.Port, checkNativeState: @escaping @Sendable () throws -> Void) {
        self.checkNativeState = checkNativeState
        connection = NWConnection(host: NWEndpoint.Host(host), port: port,
                                  using: NWParameters(tls: nil, tcp: NWProtocolTCP.Options()))
    }

    deinit {
        timer?.cancel()
        connection.cancel()
    }

    func start(milliseconds: UInt32) async throws {
        guard case .connected = try await perform(.start, milliseconds: milliseconds) else {
            throw QPeriaptSDKError(operation: "TCP start contract", code: Q_PERIAPT_ERR_INTERNAL)
        }
    }

    func send(_ data: Data, milliseconds: UInt32, checkingNativeState: Bool = true) async throws {
        guard case .sent = try await perform(.send(data), milliseconds: milliseconds,
                                             checkingNativeState: checkingNativeState) else {
            throw QPeriaptSDKError(operation: "TCP send contract", code: Q_PERIAPT_ERR_INTERNAL)
        }
    }

    func receive(milliseconds: UInt32) async throws -> (Data?, Bool) {
        guard case let .received(data, endOfInput) = try await perform(.receive, milliseconds: milliseconds) else {
            throw QPeriaptSDKError(operation: "TCP receive contract", code: Q_PERIAPT_ERR_INTERNAL)
        }
        return (data, endOfInput)
    }

    func abort() { fail(CancellationError()) }

    private func perform(_ operation: Operation, milliseconds: UInt32,
                         checkingNativeState: Bool = true) async throws -> Event {
        try Task.checkCancellation()
        let event: Event = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Event, Error>) in
                if let failure { continuation.resume(throwing: failure); return }
                guard pending == nil, milliseconds > 0 else {
                    continuation.resume(throwing: QPeriaptSDKError(operation: "TCP admission", code: Q_PERIAPT_ERR_NOT_READY))
                    return
                }
                let (followingID, overflow) = nextID.addingReportingOverflow(1)
                guard !overflow else {
                    continuation.resume(throwing: QPeriaptSDKError(operation: "TCP operation limit", code: Q_PERIAPT_ERR_RESOURCE_LIMIT))
                    return
                }
                let id = nextID
                nextID = followingID
                let budget = UInt64(milliseconds) * 1_000_000
                let (deadline, deadlineOverflow) = DispatchTime.now().uptimeNanoseconds.addingReportingOverflow(budget)
                guard !deadlineOverflow else {
                    continuation.resume(throwing: QPeriaptSDKError(operation: "TCP deadline range", code: Q_PERIAPT_ERR_LIMITS))
                    return
                }
                pending = Pending(id: id, deadline: deadline, continuation: continuation)
                timer = Task { [weak self] in
                    do {
                        var delay = checkingNativeState ? min(budget, Self.stateCheckInterval) : budget
                        while true {
                            try await Task.sleep(nanoseconds: delay)
                            guard let next = await self?.timerTick(id: id, checkingNativeState: checkingNativeState) else { return }
                            delay = next
                        }
                    }
                    catch is CancellationError { return }
                    catch { await self?.timerFailed(id: id, error: error); return }
                }
                switch operation {
                case .start:
                    guard !started else {
                        fail(QPeriaptSDKError(operation: "TCP already started", code: Q_PERIAPT_ERR_NOT_READY))
                        return
                    }
                    started = true
                    connection.stateUpdateHandler = { [weak self] state in
                        Task { await self?.stateChanged(state, startID: id) }
                    }
                    connection.start(queue: queue)
                case let .send(data):
                    connection.send(content: data, completion: .contentProcessed { [weak self] error in
                        Task { await self?.sent(id: id, error: error) }
                    })
                case .receive:
                    connection.receive(minimumIncompleteLength: 1,
                                       maximumLength: Int(Q_PERIAPT_CONNECTION_MAX_TLS_IO_BYTES)) {
                        [weak self] data, _, complete, error in
                        Task { await self?.received(id: id, data: data, complete: complete, error: error) }
                    }
                }
            }
        } onCancel: {
            Task { await self.abort() }
        }
        try Task.checkCancellation()
        return event
    }

    private func stateChanged(_ state: NWConnection.State, startID: UInt64) {
        switch state {
        case .ready: succeed(id: startID, event: .connected)
        case let .waiting(error), let .failed(error): fail(error)
        case .cancelled: fail(CancellationError())
        default: break // setup/preparing are progress notifications, not completion.
        }
    }

    private func sent(id: UInt64, error: NWError?) {
        guard pending?.id == id else { return } // Late callback after cancellation/completion.
        if let error { fail(error) }
        else { succeed(id: id, event: .sent) }
    }

    private func received(id: UInt64, data: Data?, complete: Bool, error: NWError?) {
        guard pending?.id == id else { return }
        if let error { fail(error); return }
        guard complete || !(data?.isEmpty ?? true),
              (data?.count ?? 0) <= Q_PERIAPT_CONNECTION_MAX_TLS_IO_BYTES else {
            fail(QPeriaptSDKError(operation: "TCP input contract", code: Q_PERIAPT_ERR_IO))
            return
        }
        succeed(id: id, event: .received(data, endOfInput: complete))
    }

    private func timerTick(id: UInt64, checkingNativeState: Bool) -> UInt64? {
        guard let operation = pending, operation.id == id else { return nil }
        if checkingNativeState {
            do { try checkNativeState() }
            catch { fail(error); return nil }
        }
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < operation.deadline else {
            fail(QPeriaptSDKError(operation: "connection deadline", code: Q_PERIAPT_ERR_TIMEOUT))
            return nil
        }
        let remaining = operation.deadline - now
        return checkingNativeState ? min(remaining, Self.stateCheckInterval) : remaining
    }

    private func timerFailed(id: UInt64, error: Error) {
        guard pending?.id == id else { return }
        fail(error)
    }

    private func succeed(id: UInt64, event: Event) {
        guard let operation = pending, operation.id == id, failure == nil else { return }
        pending = nil
        timer?.cancel()
        timer = nil
        operation.continuation.resume(returning: event)
    }

    private func fail(_ error: Error) {
        guard failure == nil else { return }
        failure = error
        timer?.cancel()
        timer = nil
        let operation = pending
        pending = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        operation?.continuation.resume(throwing: error)
    }
}
