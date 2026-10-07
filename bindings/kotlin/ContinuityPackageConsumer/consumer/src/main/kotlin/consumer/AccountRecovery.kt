// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.file.Path

private fun accountSnapshot(owner: ContinuityRecoveryOwner, operation: AccountOperationID,
                            files: FixtureRecords, create: Boolean): AccountAbandonmentID {
    val h = owner.beginAccountCleanup()
    check(h.operation == operation && h.memberCount in 1..32) { "account report scope" }
    val lines = mutableListOf("QPC-C-ACCOUNT-LOSS/1", "batch ${hex(h.operation)}", "report ${hex(h.report)}",
        "members ${h.memberCount}")
    for (member in 0 until h.memberCount) {
        val m = owner.accountMemberAt(member)
        lines.add("member $member ${bytes(m.device)} ${bytes(m.context)} ${hex(m.session)} " +
            "${m.role.code} ${m.generation} ${m.confirmedEpoch} ${m.sendingEpoch} ${m.receivingEpoch} " +
            "${present(m.pendingEpoch)} ${m.pendingEpoch ?: Counter64.ZERO} ${m.epochCount}")
        val r = owner.accountReservation(member)
        lines.add("reserved $member ${hex(r.message)} ${r.plaintextBytes} ${r.associatedDataBytes}")
        for (i in 0 until m.epochCount) {
            val e = owner.accountEpochAt(member, i)
            check(e.unconfirmedCount <= 64 && e.deliveryCount <= 128 && e.skippedCount <= 128) { "account epoch fixture bounds" }
            val (resolution, report) = when (val value = e.resolution) {
                EpochResolution.Unrequested -> 0 to "0".repeat(64)
                is EpochResolution.Pending -> 1 to hex(value.report)
                is EpochResolution.Acknowledged -> 2 to hex(value.report)
            }
            lines.add("epoch $member $i ${e.epoch} ${e.acknowledgedBefore} ${e.sent} ${e.consumedBefore} ${e.received} " +
                "${present(e.peerSent)} ${e.peerSent ?: Counter64.ZERO} $resolution $report " +
                "${e.unconfirmedCount} ${e.deliveryCount} ${e.skippedCount}")
            for (j in 0 until e.unconfirmedCount) {
                val u = owner.accountUnconfirmedAt(member, i, j)
                lines.add("unconfirmed $member $i $j ${hex(u.message)} ${bytes(u.ciphertextDigest)}")
            }
            for (j in 0 until e.deliveryCount) {
                val d = owner.accountDeliveryAt(member, i, j)
                lines.add("delivery $member $i $j ${hex(d.message)} ${d.index} ${d.plaintextBytes}")
            }
            for (j in 0 until e.skippedCount) lines.add("skipped $member $i $j ${owner.accountSkippedPosition(member, i, j)}")
            refused(setOf(1)) { owner.accountUnconfirmedAt(member, i, e.unconfirmedCount) }
            refused(setOf(1)) { owner.accountDeliveryAt(member, i, e.deliveryCount) }
            refused(setOf(1)) { owner.accountSkippedPosition(member, i, e.skippedCount) }
        }
        refused(setOf(1)) { owner.accountEpochAt(member, m.epochCount) }
    }
    refused(setOf(1)) { owner.accountMemberAt(h.memberCount) }
    refused(setOf(1)) { owner.accountReservation(h.memberCount) }
    refused(setOf(1)) { owner.accountEpochAt(h.memberCount, 0) }
    refused(setOf(1)) { owner.accountUnconfirmedAt(h.memberCount, 0, 0) }
    refused(setOf(1)) { owner.accountDeliveryAt(h.memberCount, 0, 0) }
    refused(setOf(1)) { owner.accountSkippedPosition(h.memberCount, 0, 0) }
    val encoded = (lines.joinToString("\n") + "\n").toByteArray()
    check(encoded.size <= 1048576) { "account report size" }
    files.retain("c-account-loss-report", encoded, create)
    check(owner.accountCleanupStatus() == AccountStatus.Abandoning(h.report)) { "account pending report identity" }
    return h.report
}

private fun savedAccountReport(files: FixtureRecords, operation: AccountOperationID): AccountAbandonmentID {
    val record = files.read("c-account-loss-report")
    val prefix = "QPC-C-ACCOUNT-LOSS/1\nbatch ${hex(operation)}\nreport ".toByteArray()
    check(record.size >= prefix.size + 65 && record.copyOfRange(0, prefix.size).contentEquals(prefix) &&
        record[prefix.size + 64] == 10.toByte()) { "saved account report identity" }
    return AccountAbandonmentID(decode(String(record, prefix.size, 64, Charsets.US_ASCII)))
}

internal fun recoverAccount(args: List<String>, witness: WitnessCarrier): String {
    require(args.size == 3)
    val mode = args[0]; val path = args[1]
    val operation = AccountOperationID(decode(args[2]))
    val owner = ContinuityRecoveryOwner.open(path, witness)
    val response = owner.use {
        if (mode == "recover-account-reject") {
            val code = refusal { owner.selectAccount(operation) }
            check(code in setOf(216, 211, 218)) { "account witness refusal differs" }
            refused(setOf(202)) { owner.sessionCount() }
            return@use "account-selection-refused:$code"
        }
        if (mode == "recover-account-retired" || mode == "recover-account-absent") {
            val expected = if (mode == "recover-account-retired") 112 else 201
            refused(setOf(expected)) { owner.selectAccount(operation) }
            refused(setOf(202)) { owner.sessionCount() }
            return@use "account-selection-refused:$expected"
        }
        owner.selectAccount(operation)
        refused(setOf(108)) { owner.sessionCount() }
        refused(setOf(108)) { owner.begin() }
        refused(setOf(108)) { owner.restoreIndex() }
        refused(setOf(108)) { owner.accountMemberAt(0) }
        val current = owner.accountCleanupStatus()
        val files = FixtureRecords(Path.of(path))
        when (mode) {
            "recover-account-results", "recover-account-settled-retire" -> {
                val result = owner.reconcileAccount()
                check(result.operation == operation) { "original reconciliation scope" }
                val lines = mutableListOf("QPC-C-RECONCILIATION/1", "batch ${hex(operation)}", "members ${result.members.size}")
                result.members.forEachIndexed { index, member ->
                    lines.add("member $index ${bytes(member.device)} ${hex(member.session)} ${hex(member.message)} ${member.state.code}")
                }
                val text = lines.joinToString("\n")
                if (mode == "recover-account-settled-retire") {
                    check(result.members.none { it.state == AccountMemberState.COMMITTED || it.state == AccountMemberState.RESOLUTION_PENDING }) {
                        "unsettled original member"
                    }
                    val bytes = (text + "\n").toByteArray(Charsets.UTF_8)
                    files.retain("c-account-reconciliation", bytes, true)
                    files.retain("c-account-reconciliation", bytes, false)
                    owner.retireAccount(); owner.retireAccount()
                    check(owner.accountCleanupStatus() == AccountStatus.Retired) { "original batch not retired" }
                    refused(setOf(112)) { owner.reconcileAccount() }
                } else refused(setOf(215)) { owner.retireAccount() }
                text
            }
            "recover-account-committed" -> {
                check(current == AccountStatus.Committed) { "committed account fixture missing" }
                refused(setOf(211)) { owner.beginAccountCleanup() }
                refused(setOf(215)) { owner.retireAccount() }
                check(owner.accountCleanupStatus() == AccountStatus.Committed) { "committed account was relabelled" }
                "account-committed-not-abandoned"
            }
            "recover-account-witness-freeze" -> {
                check(current == AccountStatus.Reserved) { "account reservation missing" }
                refused(setOf(218)) { owner.beginAccountCleanup() }
                "account-freeze-outcome-unavailable"
            }
            "recover-account-freeze", "recover-account-freeze-reconcile" -> {
                val previous = if (mode == "recover-account-freeze-reconcile") {
                    check(current is AccountStatus.Abandoning) { "unknown freeze not reconciled" }
                    current.report
                } else {
                    check(current == AccountStatus.Reserved) { "account reservation missing" }
                    null
                }
                refused(setOf(215)) { owner.retireAccount() }
                val report = accountSnapshot(owner, operation, files, true)
                if (previous != null) check(previous == report) { "unknown freeze report changed" }
                val wrong = report.encoded(); wrong[0] = if (wrong[0] == 1.toByte()) 2 else 1
                refused(setOf(211)) { owner.acknowledgeAccount(AccountAbandonmentID(wrong)) }
                check(owner.accountCleanupStatus() == AccountStatus.Abandoning(report)) { "wrong account report changed state" }
                owner.cancel()
                refused(setOf(302)) { owner.acknowledgeAccount(report) }
                refused(setOf(302)) { owner.retireAccount() }
                owner.accountMemberAt(0)
                "account-frozen:${hex(report)}"
            }
            "recover-account-witness-ack" -> {
                check(current is AccountStatus.Abandoning) { "account frozen state missing" }
                val report = accountSnapshot(owner, operation, files, false)
                refused(setOf(218)) { owner.acknowledgeAccount(report) }
                "account-acknowledgement-outcome-unavailable"
            }
            "recover-account-ack-reconcile" -> {
                val report = savedAccountReport(files, operation)
                check(current == AccountStatus.Abandoned(report)) { "unknown acknowledgement changed report" }
                owner.acknowledgeAccount(report); owner.acknowledgeAccount(report)
                check(owner.accountCleanupStatus() == AccountStatus.Abandoned(report)) { "account acknowledgement identity" }
                "account-acknowledged:${hex(report)}"
            }
            "recover-account-ack" -> {
                check(current is AccountStatus.Abandoning) { "account frozen state missing" }
                val report = accountSnapshot(owner, operation, files, false)
                owner.acknowledgeAccount(report); owner.acknowledgeAccount(report)
                check(owner.accountCleanupStatus() == AccountStatus.Abandoned(report)) { "account acknowledgement identity" }
                "account-acknowledged:${hex(report)}"
            }
            "recover-account-retire-reconcile" -> {
                savedAccountReport(files, operation)
                check(current == AccountStatus.Retired) { "unknown retirement not reconciled" }
                owner.retireAccount(); owner.retireAccount()
                check(owner.accountCleanupStatus() == AccountStatus.Retired) { "retired account changed" }
                refused(setOf(112)) { owner.beginAccountCleanup() }
                "account-retired"
            }
            "recover-account-witness-retire" -> {
                val report = savedAccountReport(files, operation)
                check(current == AccountStatus.Abandoned(report)) { "account terminal report differs" }
                refused(setOf(218)) { owner.retireAccount() }
                "account-retirement-outcome-unavailable"
            }
            "recover-account-retire" -> {
                val report = savedAccountReport(files, operation)
                check(current == AccountStatus.Abandoned(report)) { "account terminal report differs" }
                owner.retireAccount(); owner.retireAccount()
                check(owner.accountCleanupStatus() == AccountStatus.Retired) { "account retirement not reconciled" }
                refused(setOf(112)) { owner.beginAccountCleanup() }
                "account-retired"
            }
            else -> error("unknown account recovery mode")
        }
    }
    refused(setOf(2)) { owner.cancel() }
    return response
}
