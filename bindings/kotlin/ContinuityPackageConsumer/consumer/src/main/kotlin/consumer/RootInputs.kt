// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.ByteBuffer
import java.nio.file.Path

internal class RootInputs(args: List<String>) {
    val publicPath: Path = Path.of(args[1])
    val records = FixtureRecords(publicPath, 8_388_608)
    val oldPath = args[2]; val targetPath = args[3]; val registryPath = args[4]
    val original = enrollmentIntent(FixtureRecords(Path.of(oldPath)))
    val target = enrollmentIntent(FixtureRecords(Path.of(targetPath)))
    val scope = RootReplacementScope(AccountAuthorityCheckpoint(ApplicationAccountID(records.enrollmentExact("application", 32)),
        enrollmentCounter(records.enrollmentExact("revision", 8)), AccountID(records.enrollmentExact("account", 32))),
        records.enrollmentExact("witness-id", 32), records.enrollmentExact("witness-public", 1985))
    val trust = AccountAuthorityTrust(AccountAuthorityID(records.enrollmentExact("registry-id", 32)),
        records.enrollmentExact("family", 32), scope.witness.encoded(), scope.publicKey.encoded())
    val plan = RootReplacementPlan(records.read("approved-plan"))
    val witness = WitnessCarrier.SignedTCP(args[5], 3000)
    fun transition() = RootReplacementTransition(plan, RootReplacementPlan(records.read("alternative-approved")),
        records.read("original-noncommit"), records.read("alternative-receipt"))
    fun adoption() = RootReplacementAdoption(plan, RootReplacementProposal(records.read("alternative-approved")),
        records.read("original-noncommit"), records.read("alternative-receipt"))
    fun resume(root: ContinuityAccountAuthority, route: String) = when (route) {
        "original" -> root.resumeRootReplacement(oldPath, original, scope, plan)
        "transition" -> root.resumeRootTransition(oldPath, original, scope, transition())
        "adoption" -> root.resumeRootAdoption(oldPath, original, scope, adoption())
        else -> error("unknown root recovery route")
    }
    fun checkpoint(value: AccountAuthorityCheckpoint) {
        val next = Counter64.parse((scope.checkpoint.revision.toString().toBigInteger() + java.math.BigInteger.ONE).toString())
        check(value.application == scope.checkpoint.application && value.revision == next &&
            value.account.encoded().contentEquals(records.enrollmentExact("target-account", 32))) { "root successor checkpoint differs" }
    }
}
internal fun rootNumber(path: Path, name: String, value: Long) {
    FixtureRecords(path).retain(name, ByteBuffer.allocate(8).putLong(value).array(), true)
}
internal fun rootPause(path: Path, mode: String): Nothing {
    rootNumber(path, "cut-$mode", ProcessHandle.current().pid())
    output("root-cut-ready:$mode")
    val end = System.nanoTime() + 30_000_000_000L
    while (System.nanoTime() < end) Thread.sleep(10)
    error("owned root process was not killed within its cut window")
}
