// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

/// Only this reference cell is mutable. All state changes are protected by lock;
/// native calls and releases run outside it. A transfer moves the existing
/// NativeOwner reference, preserving its one destructor and immutable handle.
final class OwnerTransferReference: @unchecked Sendable {
    private let lock = NSLock()
    private var native: NativeOwner?
    private var borrowed = 0
    private var transferring = false
    private var transferred = false
    private let label: String
    init(_ native: NativeOwner, label: String) { self.native = native; self.label = label }

    private func closed() -> ContinuityFailure {
        ContinuityFailure(code: Int32(QPC_CLOSED), message: "\(label) owner is closed or transferred", truncated: false)
    }
    private func busy() -> ContinuityFailure {
        ContinuityFailure(code: Int32(QPC_BUSY), message: "\(label) owner has an active call or transfer", truncated: false)
    }
    func call<T>(cancellation: Bool = false, _ body: (NativeOwner) throws -> T) throws -> T {
        let owner = try lock.withLock {
            guard let native else { throw closed() }
            guard !transferring || cancellation else { throw busy() }
            borrowed += 1
            return native
        }
        defer { lock.withLock { borrowed -= 1 } }
        return try withExtendedLifetime((self, owner)) { try body(owner) }
    }
    func transfer<T>(_ body: (NativeOwner) throws -> T) throws -> T {
        let owner = try lock.withLock {
            guard let native else { throw closed() }
            guard !transferring && borrowed == 0 else { throw busy() }
            transferring = true
            return native
        }
        defer { lock.withLock { transferring = false } }
        return try withExtendedLifetime((self, owner)) {
            let successor = try body(owner)
            lock.withLock {
                native = nil
                transferred = true
            }
            return successor
        }
    }
    func close() throws {
        let owner: NativeOwner? = try lock.withLock {
            if transferred { return nil }
            guard let native else { throw closed() }
            guard !transferring else { throw busy() }
            borrowed += 1
            return native
        }
        guard let owner else { return }
        defer { lock.withLock { borrowed -= 1 } }
        try withExtendedLifetime((self, owner)) {
            do { try owner.close() }
            catch let failure as ContinuityFailure where failure.code == QPC_CLOSED {
                lock.withLock { native = nil }
                throw failure
            }
            lock.withLock { native = nil }
        }
    }
}
