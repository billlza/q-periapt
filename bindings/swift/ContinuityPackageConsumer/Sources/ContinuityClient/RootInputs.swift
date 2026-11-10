// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity
import Darwin

struct RootInputs {
    let records: EnrollmentInputs
    let oldPath: String, targetPath: String, registryPath: String
    let original: EnrollmentIntent, target: EnrollmentIntent
    let scope: RootReplacementScope, trust: AccountAuthorityTrust
    let plan: RootReplacementPlan, witness: WitnessCarrier
    init(_ args: [String]) throws {
        records = EnrollmentInputs(records: FixtureRecords(path: args[1], maximumBytes: 8_388_608))
        oldPath = args[2]; targetPath = args[3]; registryPath = args[4]
        original = try EnrollmentInputs(records: FixtureRecords(path: oldPath)).intent()
        target = try EnrollmentInputs(records: FixtureRecords(path: targetPath)).intent()
        let revision = try records.exact("revision", count: 8)
        scope = try RootReplacementScope(checkpoint: AccountAuthorityCheckpoint(
            application: ApplicationAccountID(bytes: records.exact("application", count: 32)),
            revision: records.counter(revision[...]), account: AccountID(bytes: records.exact("account", count: 32))),
            witness: records.exact("witness-id", count: 32), publicKey: records.exact("witness-public", count: 1985))
        trust = try AccountAuthorityTrust(identity: AccountAuthorityID(bytes: records.exact("registry-id", count: 32)),
            family: records.exact("family", count: 32), witness: scope.witness, publicKey: scope.publicKey)
        plan = try RootReplacementPlan(approvedBytes: records.read("approved-plan", maximum: 131072))
        witness = .signedTCP(address: args[5], timeoutMilliseconds: 3000)
    }
    func transition() throws -> RootReplacementTransition {
        try RootReplacementTransition(original: plan,
            independentlyApprovedNext: RootReplacementPlan(approvedBytes: records.read("alternative-approved", maximum: 131072)),
            noncommitReceipt: records.read("original-noncommit", maximum: 131072),
            freezeReceipt: records.read("alternative-receipt", maximum: 131072))
    }
    func adoption() throws -> RootReplacementAdoption {
        try RootReplacementAdoption(original: plan,
            independentlyApprovedWinner: RootReplacementProposal(approvedBytes: records.read("alternative-approved", maximum: 65536)),
            noncommitReceipt: records.read("original-noncommit", maximum: 131072),
            retirementReceipt: records.read("alternative-receipt", maximum: 131072))
    }
    func resume(_ root: ContinuityAccountAuthority, route: String) throws {
        switch route {
        case "original": try root.resumeRootReplacement(path: oldPath, intent: original, scope: scope, plan: plan)
        case "transition": try root.resumeRootTransition(path: oldPath, intent: original, scope: scope, approval: transition())
        case "adoption": try root.resumeRootAdoption(path: oldPath, intent: original, scope: scope, approval: adoption())
        default: throw ProbeFailure.contract("unknown root recovery route")
        }
    }
    func checkpoint(_ value: AccountAuthorityCheckpoint) throws {
        try require(value.application == scope.checkpoint.application && value.revision == scope.checkpoint.revision + 1 &&
            value.account.bytes == records.exact("target-account", count: 32), "root successor checkpoint differs")
    }
}
func rootNumber(_ path: String, _ name: String, _ value: UInt64) throws {
    var number = value.bigEndian
    try EnrollmentInputs(records: FixtureRecords(path: path)).publish(name, withUnsafeBytes(of: &number) { Array($0) })
}
func rootPause(_ path: String, _ mode: String) throws {
    try rootNumber(path, "cut-" + mode, UInt64(getpid()))
    let deadline = ContinuousClock.now.advanced(by: .seconds(30))
    while ContinuousClock.now < deadline { Thread.sleep(forTimeInterval: 0.01) }
    throw ProbeFailure.contract("owned root process was not killed within its cut window")
}
func rootThreadObservation(_ path: String, _ mode: String) throws {
    try rootNumber(path, "process-" + mode, UInt64(getpid()))
    try rootNumber(path, "stack-" + mode, UInt64(pthread_get_stacksize_np(pthread_self())))
    var defaults = pthread_attr_t(), size = 0
    try require(pthread_attr_init(&defaults) == 0, "pthread attributes")
    let result = pthread_attr_getstacksize(&defaults, &size)
    try require(pthread_attr_destroy(&defaults) == 0 && result == 0 && size > 0, "pthread default stack")
    try rootNumber(path, "stack-default-" + mode, UInt64(size))
}
