// SPDX-License-Identifier: Apache-2.0 OR MIT
// Same-host public fixture records; not a portable network or SDK API.
import QPeriaptContinuity
private struct FixtureError: Error { let message:String; init(_ message:String) { self.message=message } }
private func require(_ value:@autoclosure () throws -> Bool,_ message:String) throws { guard try value() else { throw FixtureError(message) } }
public struct IndependentRequestFixture {
    var bytes: [UInt8]
    var offset = 0
    mutating func take(_ count: Int) throws -> [UInt8] {
        try require(count >= 0 && offset <= bytes.count && count <= bytes.count - offset, "truncated independent request")
        defer { offset += count }; return Array(bytes[offset..<(offset + count)])
    }
    mutating func u32() throws -> UInt32 { try take(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) } }
    mutating func u64() throws -> UInt64 { try take(8).withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) } }
    mutating func roster() throws -> RosterCheckpoint { try RosterCheckpoint(version: u64(), digest: take(32)) }
    mutating func policy() throws -> PolicyCheckpoint { try PolicyCheckpoint(version: u64(), digest: take(32)) }
    mutating func blob() throws -> [UInt8] {
        let length = Int(try u32()), value = try take(8192)
        try require((1...8192).contains(length) && value.dropFirst(length).allSatisfy({ $0 == 0 }), "invalid public record tail")
        return Array(value.prefix(length))
    }
    public static func read(_ bytes: [UInt8]) throws -> PolicyRenewalRequest {
        try require(bytes.count == 33176, "independent request fixture width")
        var r = Self(bytes: bytes)
        let operation = try PolicyRenewalID(bytes: r.take(32)), journal = try JournalID(bytes: r.take(32))
        let owner = try r.take(32), original = try r.take(32), current = try r.take(32)
        let roster = try r.roster(), originalPolicy = try r.policy(), previousPolicy = try r.policy(), authorization = try r.take(32)
        let previous: PolicyAuthorizationID?
        switch try r.u32() {
        case 0: try require(authorization.allSatisfy({ $0 == 0 }), "absent authorization nonzero"); previous = nil
        case 1: previous = try PolicyAuthorizationID(bytes: authorization)
        default: throw FixtureError("unknown optional authorization")
        }
        try require(r.u32() == 0, "reserved scope word")
        let scope = try PolicyRenewalScope(operation: operation, journal: journal, originalOwner: owner,
            originalCredential: original, currentCredential: current, currentRoster: roster,
            originalPolicy: originalPolicy, previousPolicy: previousPolicy, previousAuthorization: previous)
        let value = try PolicyRenewalRequest(scope: scope, account: AccountID(bytes: r.take(32)), originalRosterCheckpoint: r.roster(),
            originalCredential: r.blob(), originalRoster: r.blob(), currentCredential: r.blob(), currentRoster: r.blob())
        try require(r.offset == bytes.count, "trailing independent request fixture"); return value
    }
    private static func number<T: FixedWidthInteger>(_ value: T) -> [UInt8] { var value = value; return withUnsafeBytes(of: &value) { Array($0) } }
    public static func write(_ r: PolicyRenewalRequest) throws -> [UInt8] {
        let s = r.scope
        var bytes = s.operation.bytes + s.journal.bytes + s.originalOwner + s.originalCredential + s.currentCredential
        bytes += number(s.currentRoster.version) + s.currentRoster.digest
        bytes += number(s.originalPolicy.version) + s.originalPolicy.digest
        bytes += number(s.previousPolicy.version) + s.previousPolicy.digest
        bytes += s.previousAuthorization?.bytes ?? [UInt8](repeating: 0, count: 32)
        bytes += number(UInt32(s.previousAuthorization == nil ? 0 : 1)) + number(UInt32(0))
        bytes += r.account.bytes + number(r.originalRosterCheckpoint.version) + r.originalRosterCheckpoint.digest
        for value in [r.originalCredential, r.originalRoster, r.currentCredential, r.currentRoster] {
            bytes += number(UInt32(value.count)) + value + [UInt8](repeating: 0, count: 8192 - value.count)
        }
        try require(bytes.count == 33176, "encoded independent request width"); return bytes
    }
}
