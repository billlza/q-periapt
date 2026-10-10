// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner

public extension ContinuityDevice {
    /// Admit an independently pinned current roster for a known remote account.
    /// This cannot update the local account, replace policy or create a session.
    /// The returned checkpoint is current state, not a transaction receipt.
    /// After an I/O, witness or cancellation error, reopen the original parent
    /// and retry the same target; absence of a result never proves no commit.
    func admitPeerRoster(roster: [UInt8], pin: AccountPin) throws -> RosterCheckpoint {
        guard (1...65536).contains(roster.count) else { throw ContinuityBoundaryError.inputLength }
        return try call { handle in
            var raw = qpc_roster_checkpoint_v1(), error = qpc_error_v1()
            let code = pin.withNative { pin in
                roster.withUnsafeBufferPointer {
                    qpc_device_v1_admit_peer_roster(handle, $0.baseAddress, $0.count, pin, &raw, &error)
                }
            }
            try checked(code, &error)
            return try renewalCheckpoint(&raw)
        }
    }
}
