// SPDX-License-Identifier: Apache-2.0 OR MIT
// Explicit same-host fixture fields, not a portable network format or an approval.
import QPeriaptContinuity

public enum CredentialRequestFixture {
    public static func write(_ value: CredentialRenewalRequest) -> [UInt8] {
        func number<T: FixedWidthInteger>(_ value: T) -> [UInt8] {
            var value = value; return withUnsafeBytes(of: &value) { Array($0) }
        }
        var output = value.operation.bytes + value.journal.bytes + value.originalOwner + value.originalPolicyDigest
        output += number(value.currentPolicy.version) + value.currentPolicy.digest
        output += value.currentPolicyAuthorization?.bytes ?? [UInt8](repeating: 0, count: 32)
        output += number(UInt32(value.currentPolicyAuthorization == nil ? 0 : 1)) + number(UInt32(0))
        output += number(value.previousRosterCheckpoint.version) + value.previousRosterCheckpoint.digest
        output += number(value.originalRosterCheckpoint.version) + value.originalRosterCheckpoint.digest
        output += number(value.previousValidFrom) + number(value.previousValidUntil) + value.account.bytes
        for record in [value.originalCredential, value.originalRoster, value.previousCredential, value.previousRoster] {
            output += number(UInt32(record.count)) + record + [UInt8](repeating: 0, count: 8192 - record.count)
        }
        return output
    }
}
