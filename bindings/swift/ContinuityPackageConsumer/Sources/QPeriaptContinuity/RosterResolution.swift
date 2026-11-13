// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner

/// Historical facts about the original target, never current permission.
public enum RosterRefreshOutcome: UInt32, Sendable {
    case committed = 1
    case expiredUncommitted = 2
    case supersededUncommitted = 3
    /// A higher head does not reveal whether the target previously committed.
    case supersededUnknown = 4
}

public struct RosterRefreshResolution: Sendable, Equatable {
    public let outcome: RosterRefreshOutcome
    public let journal: JournalID
    public let previous: RosterCheckpoint
    public let target: RosterCheckpoint
    public let observed: RosterCheckpoint
    public let observedAt: UInt64
}

func decodeRosterRefreshResolution(_ raw: inout qpc_roster_refresh_resolution_v1) throws -> RosterRefreshResolution {
    let journal = withUnsafeBytes(of: &raw.journal) { Array($0) }
    guard raw.reserved == 0, raw.observed_at > 0,
          let outcome = RosterRefreshOutcome(rawValue: raw.outcome),
          journal.contains(where: { $0 != 0 }) else { throw ContinuityBoundaryError.malformedOutput }
    func checkpoint(_ raw: inout qpc_roster_checkpoint_v1) throws -> RosterCheckpoint {
        let digest = withUnsafeBytes(of: &raw.digest) { Array($0) }
        guard raw.version > 0, raw.version < UInt64.max, digest.contains(where: { $0 != 0 }) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        return try RosterCheckpoint(version: raw.version, digest: digest)
    }
    let previous = try checkpoint(&raw.previous), target = try checkpoint(&raw.target), observed = try checkpoint(&raw.observed)
    guard previous.version < target.version, observed.version >= previous.version,
          observed.version != previous.version || observed == previous else {
        throw ContinuityBoundaryError.malformedOutput
    }
    let valid: Bool
    switch outcome {
    case .committed: valid = observed == target
    case .expiredUncommitted: valid = observed.version < target.version
    case .supersededUncommitted: valid = observed.version == target.version && observed != target
    case .supersededUnknown: valid = observed.version > target.version
    }
    guard valid else { throw ContinuityBoundaryError.malformedOutput }
    return RosterRefreshResolution(outcome: outcome, journal: try JournalID(bytes: journal),
        previous: previous, target: target, observed: observed, observedAt: raw.observed_at)
}
