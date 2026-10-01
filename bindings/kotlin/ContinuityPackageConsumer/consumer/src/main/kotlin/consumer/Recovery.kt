// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.file.Path
import java.util.HexFormat
import kotlin.system.exitProcess

private fun bytes(value: PublicBytes) = HexFormat.of().formatHex(value.encoded())
private fun present(value: Counter64?) = if (value == null) 0 else 1
private fun savedReport(files: FixtureRecords): ClosureReportID {
    val record = files.read("c-loss-report")
    val prefix = "QPC-C-LOSS/1\nreport ".toByteArray()
    check(record.size >= prefix.size + 65 && record.copyOfRange(0, prefix.size).contentEquals(prefix) &&
        record[prefix.size + 64] == 10.toByte()) { "saved report identity" }
    return ClosureReportID(decode(String(record, prefix.size, 64, Charsets.US_ASCII)))
}
private fun snapshot(owner: ContinuityRecoveryOwner, files: FixtureRecords, create: Boolean): ClosureReportID {
    val h = owner.begin()
    check(h.role == SessionRole.RESPONDER && h.peerGeneration == Counter64.of(1) && h.epochCount <= 4 && h.reservedCount <= 4) {
        "report outside fixture scope"
    }
    val lines = mutableListOf("QPC-C-LOSS/1", "report ${hex(h.report)}",
        "header ${hex(h.session)} ${bytes(h.context)} ${bytes(h.peerAccount)} ${bytes(h.peerDevice)} " +
            "${h.role.code} ${h.peerGeneration} ${h.confirmedEpoch} ${h.sendingEpoch} ${h.receivingEpoch} " +
            "${present(h.pendingEpoch)} ${h.pendingEpoch ?: Counter64.ZERO} ${h.reservedCount} ${h.epochCount}")
    for (i in 0 until h.reservedCount) {
        val r = owner.reservationAt(i)
        lines.add("reserved $i ${hex(r.message)} ${r.plaintextBytes} ${r.associatedDataBytes}")
    }
    refused(setOf(1)) { owner.reservationAt(h.reservedCount) }
    for (i in 0 until h.epochCount) {
        val e = owner.epochAt(i)
        check(e.unconfirmedCount <= 64 && e.deliveryCount <= 128 && e.skippedCount <= 128) { "epoch fixture bounds" }
        val (resolution, report) = when (val r = e.resolution) {
            EpochResolution.Unrequested -> 0 to "0".repeat(64)
            is EpochResolution.Pending -> 1 to hex(r.report)
            is EpochResolution.Acknowledged -> 2 to hex(r.report)
        }
        lines.add("epoch $i ${e.epoch} ${e.acknowledgedBefore} ${e.sent} ${e.consumedBefore} ${e.received} " +
            "${present(e.peerSent)} ${e.peerSent ?: Counter64.ZERO} $resolution $report " +
            "${e.unconfirmedCount} ${e.deliveryCount} ${e.skippedCount}")
        for (j in 0 until e.unconfirmedCount) {
            val u = owner.unconfirmedAt(i, j)
            lines.add("unconfirmed $i $j ${hex(u.message)} ${bytes(u.ciphertextDigest)}")
        }
        for (j in 0 until e.deliveryCount) {
            val d = owner.deliveryAt(i, j)
            lines.add("delivery $i $j ${hex(d.message)} ${d.index} ${d.plaintextBytes}")
        }
        for (j in 0 until e.skippedCount) lines.add("skipped $i $j ${owner.skippedPosition(i, j)}")
        refused(setOf(1)) { owner.unconfirmedAt(i, e.unconfirmedCount) }
        refused(setOf(1)) { owner.deliveryAt(i, e.deliveryCount) }
        refused(setOf(1)) { owner.skippedPosition(i, e.skippedCount) }
    }
    refused(setOf(1)) { owner.epochAt(h.epochCount) }
    files.retain("c-loss-report", (lines.joinToString("\n") + "\n").toByteArray(), create)
    check(owner.status() == ClosureStatus.Pending(h.report)) { "pending report identity differs" }
    return h.report
}
private fun refusal(action: () -> Unit): Int {
    try { action() } catch (failure: ContinuityFailure) { return failure.code }
    error("required witness admission was bypassed")
}
internal fun recover(args: List<String>, witness: WitnessCarrier): String {
    require(args.size in 2..3)
    val mode = args[0]; val path = args[1]
    if (mode == "recover-kind") {
        require(args.size == 2)
        checkNativeKindSeparation(path, witness)
        return "operational-owner-not-recovery"
    }
    val owner = ContinuityRecoveryOwner.open(path, witness)
    val response = owner.use {
        val count = owner.sessionCount()
        val files = FixtureRecords(Path.of(path))
        when (mode) {
            "recover-list" -> { require(args.size == 2); "catalogue:$count" }
            "recover-reject-select" -> {
                check(args.size == 3 && count == 1L)
                val code = refusal { owner.select(SessionID(decode(args[2]))) }
                refused(setOf(202)) { owner.sessionCount() }
                "selection-refused:$code"
            }
            "recover-reject-archive" -> {
                check(args.size == 2 && count == 0L)
                val code = refusal { owner.selectArchive(files.read("c-closure-archive")) }
                refused(setOf(202)) { owner.sessionCount() }
                "archive-refused:$code"
            }
            "recover-tamper" -> {
                check(args.size == 2 && count == 1L)
                val archive = files.read("native-closure-archive")
                check(archive.size == 362)
                val invalid = try { owner.selectArchive(archive.copyOf(361)); false }
                    catch (_: IllegalArgumentException) { true }
                check(invalid && owner.sessionCount() == 1L) { "invalid archive consumed discovery" }
                archive[archive.lastIndex] = (archive.last().toInt() xor 1).toByte()
                refused(setOf(208)) { owner.selectArchive(archive) }
                refused(setOf(202)) { owner.sessionCount() }
                "tampered-archive-refused"
            }
            "recover-archive" -> {
                check(args.size == 2 && count == 0L)
                owner.selectArchive(files.read("c-closure-archive"))
                val report = savedReport(files)
                check(owner.status() == ClosureStatus.Closed(report)) { "archive restored operational state" }
                owner.restoreIndex(); owner.restoreIndex()
                check(owner.retire(report) && !owner.retire(report)) { "restored row retirement differs" }
                "archive-closed-metadata-only"
            }
            else -> {
                check(args.size == 3 && count == 1L)
                val session = SessionID(decode(args[2]))
                check(owner.sessionAt(0) == session)
                refused(setOf(1)) { owner.sessionAt(1) }
                if (mode == "recover-missing") {
                    val missing = session.encoded(); missing[31] = (missing[31].toInt() xor 1).toByte()
                    refused(setOf(201)) { owner.select(SessionID(missing)) }
                    refused(setOf(202)) { owner.sessionCount() }
                    "missing-session-refused"
                } else {
                    owner.select(session)
                    refused(setOf(108)) { owner.select(session) }
                    files.retain("c-closure-archive", owner.archive(), true)
                    when (mode) {
                        "recover-cancel" -> {
                            check(owner.status() == ClosureStatus.Open)
                            owner.cancel()
                            refused(setOf(302)) { owner.begin() }
                            if (witness == WitnessCarrier.Local) check(owner.status() == ClosureStatus.Open)
                            else refused(setOf(218)) { owner.status() }
                            refused(setOf(302)) { owner.restoreIndex() }
                            "cancelled-cleanup-not-frozen"
                        }
                        "recover-witness-failed-freeze" -> {
                            check(witness != WitnessCarrier.Local)
                            refused(setOf(218)) { owner.begin() }
                            "witness-freeze-outcome-unavailable"
                        }
                        "recover-freeze" -> { snapshot(owner, files, true); exitProcess(77) }
                        "recover-ack-crash" -> {
                            val report = snapshot(owner, files, false)
                            val wrong = report.encoded(); wrong[0] = (wrong[0].toInt() xor 1).toByte()
                            refused(setOf(211)) { owner.acknowledge(ClosureReportID(wrong)) }
                            check(owner.status() == ClosureStatus.Pending(report))
                            owner.acknowledge(report)
                            check(owner.status() == ClosureStatus.Closed(report))
                            refused(setOf(112)) { owner.begin() }
                            exitProcess(77)
                        }
                        "recover-finish" -> {
                            val report = savedReport(files)
                            check(owner.status() == ClosureStatus.Closed(report)) { "unknown ACK not reconciled" }
                            owner.acknowledge(report)
                            check(owner.retire(report) && !owner.retire(report))
                            "original-report-closed-retired"
                        }
                        else -> error("unknown recovery mode")
                    }
                }
            }
        }
    }
    refused(setOf(2)) { owner.cancel() }
    return response
}
