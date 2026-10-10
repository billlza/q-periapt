// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer
import dev.qperiapt.continuity.*
import java.nio.file.Path

internal fun witnessedRosterEnrollment(owner: ContinuityEnrollment, path: String, records: FixtureRecords, mode: String): String {
    val operation = RosterRefreshID(records.enrollmentExact("roster-operation", 32))
    fun select(): RosterPolicySource {
        val flag = records.enrollmentExact("roster-policy-source", 1)[0].toInt(); check(flag in 0..1)
        if (flag == 1) { val target = Path.of(path).resolve("independent-sdk"); owner.selectContinuedPolicy(target.toString(), policyDocument(target)) }
        return if (flag == 1) RosterPolicySource.SELECTED else RosterPolicySource.ORIGINAL
    }
    fun retained() = RosterRefreshProposal.fromRetained(records.enrollmentExact("roster-proposal", 417))
    fun bytes(value: ByteArray) = value.joinToString("") { "%02x".format(it) }
    fun progress(value: RosterRefreshProgress): String {
        val phase: Int; val retired: Boolean; val scope: RosterRefreshScope
        when(value) {
            RosterRefreshProgress.Absent -> { val zero = "0".repeat(64); return listOf("0", "0", zero, "0", zero, "0", zero, "0", zero, "0", zero).joinToString("\n") }
            is RosterRefreshProgress.Staged -> { phase = 1; retired = false; scope = value.scope }
            is RosterRefreshProgress.AbandonedBeforePreparation -> { phase = 5; retired = false; scope = value.scope }
            is RosterRefreshProgress.Reserved -> { check(value.proposal == retained()); phase = 2; retired = false; scope = value.proposal.scope }
            is RosterRefreshProgress.Applied -> { check(value.proposal == retained()); phase = 3; retired = value.retired; scope = value.proposal.scope }
            is RosterRefreshProgress.Closed -> { check(value.proposal == retained()); phase = 4; retired = value.retired; scope = value.proposal.scope }
        }
        return listOf(phase.toString(), if(retired) "1" else "0", hex(scope.operation), scope.previous.version.toString(), bytes(scope.previous.digest.encoded()),
            scope.target.version.toString(), bytes(scope.target.digest.encoded()), scope.policy.version.toString(), bytes(scope.policy.digest.encoded()),
            if(scope.policyAuthorization == null) "0" else "1", bytes(scope.policyAuthorization?.encoded() ?: ByteArray(32))).joinToString("\n")
    }
    when(mode) {
        "progress" -> return progress(owner.witnessedRosterRefreshProgress())
        "prepare", "prepare-lost", "prepare-wrong-policy" -> {
            val source = select(); val original = enrollmentPin(records, false)
            val target = RosterCheckpoint(Counter64.parse(java.lang.Long.toUnsignedString(java.nio.ByteBuffer.wrap(records.enrollmentExact("roster-target-version", 8)).long)), records.enrollmentExact("roster-target-digest", 32))
            val pin = AccountPin(original.account, original.root.encoded(), original.family.encoded(), target)
            val certificate = records.read("grant-certificate"); val roster = records.read("roster-target")
            val prepare = { owner.prepareWitnessedRosterRefresh(operation, if(mode == "prepare-wrong-policy") RosterPolicySource.ORIGINAL else source, certificate, roster, pin) }
            if(mode != "prepare") {
                val expected = if(mode == "prepare-lost") 218 else 103
                refused(setOf(expected)) { prepare() }; refused(setOf(2)) { owner.status() }; return "roster-refused:$expected"
            }
            val proposal = prepare(); check(prepare() == proposal); check(records.retain("roster-proposal", proposal.encoded(), true)); return "roster-prepared"
        }
        "recover", "recover-absent" -> {
            val result = owner.recoverWitnessedRosterRefreshPreparation()
            if(mode == "recover-absent") { check(result == null); return "roster-local-absence" }
            check(result == retained()); return "roster-exact-preparation"
        }
        "abandon", "abandon-refused" -> {
            if(mode == "abandon-refused") { refused(setOf(211)) { owner.abandonUnpreparedRosterRefresh(operation) }; return "roster-abandon-refused" }
            val value = owner.abandonUnpreparedRosterRefresh(operation); check(value is RosterRefreshProgress.AbandonedBeforePreparation); return progress(value)
        }
    }
    check(mode in setOf("commit", "commit-lost", "close", "close-lost", "reconcile", "substitute", "cancelled"))
    val wire = retained().encoded(); if(mode == "substitute") wire[416] = (wire[416].toInt() xor 1).toByte()
    val proposal = RosterRefreshProposal.fromRetained(wire); if(mode == "cancelled") owner.cancel()
    val command: () -> RosterRefreshState = when(mode) {
        "commit", "commit-lost" -> { val source = select(); { owner.commitWitnessedRosterRefresh(proposal, source) } }
        "close", "close-lost" -> { { owner.closeWitnessedRosterRefresh(proposal) } }
        else -> { { owner.reconcileWitnessedRosterRefresh(proposal) } }
    }
    val expected = if(mode == "substitute") 211 else if(mode == "cancelled") 302 else if(mode.endsWith("-lost")) 218 else 0
    if(expected != 0) { refused(setOf(expected)) { command() }; refused(setOf(if(expected == 302) 302 else 2)) { owner.status() }; return "roster-refused:$expected" }
    return "roster-state:${command().code}"
}
