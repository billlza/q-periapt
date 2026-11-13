// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.ByteBuffer
import java.nio.file.Path

/** Eight real JVM cleanup processes. Native Rust independently handles replacement
 * authority, reconstructs the full report, and checks fresh-generation TLS. */
internal fun retirementCommand(args: List<String>): String {
    require(args.size == 3) { "retirement arguments" }
    val path = args[1]; val mode = args[2]; val records = FixtureRecords(Path.of(path), 8_388_608)
    fun exact(name: String, size: Int): ByteArray = records.read(name).also { check(it.size == size) { "retirement input width: $name" } }
    fun counter(bytes: ByteArray): Counter64 = Counter64.parse(java.lang.Long.toUnsignedString(ByteBuffer.wrap(bytes).long))
    fun publish(name: String, bytes: ByteArray) { check(records.retain(name, bytes, true)) { "retirement output already exists: $name" } }
    publish("retirement-process-$mode", ByteBuffer.allocate(8).putLong(ProcessHandle.current().pid()).array())
    val validity = exact("enrollment-validity", 16)
    val intent = EnrollmentIntent(exact("local-root", 1985), exact("local-device", 16), counter(exact("local-generation", 8)),
        exact("family", 32), counter(validity.copyOfRange(0, 8)), counter(validity.copyOfRange(8, 16)))
    val authority = RetiredEnrollmentAuthority(exact("witness-id", 32), exact("witness-public", 1985),
        records.read("retirement-proposal"), exact("witness-subject", 96), exact("retirement-receipt", 3754))
    fun openOwner(): ContinuityRetiredEnrollment = ContinuityRetiredEnrollment.open(path, intent, authority)
    fun expected(proposal: RetiredReportProposal?) {
        val value = checkNotNull(proposal) { "retirement proposal absent" }; val original = exact("retirement-report-proposal", 353)
        check(value.bytes.encoded().contentEquals(original) && value.report.encoded().contentEquals(original.copyOfRange(321, 353)))
    }
    fun prepareAck(owner: ContinuityRetiredEnrollment) {
        expected(owner.prepareAcknowledgement(exact("retirement-inventory-receipt", 3690),
            exact("retirement-report-receipt", 3730), records.read("retirement-host-report")))
        expected(owner.acknowledgementProposal())
    }
    var owner = openOwner()
    try {
        when (mode) {
            "inventory" -> {
                publish("retirement-inventory", owner.inventory().bytes.encoded())
                try { owner.prepareReport(ByteArray(3689)); error("short receipt accepted") }
                catch (failure: IllegalArgumentException) { check(failure.message == "invalid inventory receipt width") }
                owner.inventory()
                refused(setOf(101)) { owner.prepareReport(ByteArray(3690)) }
                refused(setOf(2)) { owner.inventory() }
                owner.close(); owner = openOwner(); owner.cancel()
                refused(setOf(302)) { owner.inventory() }
                ContinuityRetiredEnrollment.prepareOpen(path, intent, authority).use { pending ->
                    refused(setOf(6)) { pending.inventory() }; pending.cancel()
                    refused(setOf(302)) { pending.finishOpen() }
                }
            }
            "prepare-report" -> {
                val proposal = owner.prepareReport(exact("retirement-inventory-receipt", 3690))
                publish("retirement-report-proposal", proposal.bytes.encoded()); expected(owner.reportProposal())
            }
            "report", "report-reopen" -> {
                val report = owner.loadReport(exact("retirement-inventory-receipt", 3690), exact("retirement-report-receipt", 3730))
                val original = exact("retirement-report-proposal", 353)
                check(report.viewCount == 1 && report.report.encoded().contentEquals(original.copyOfRange(321, 353)))
                if (mode == "report") { publish("retirement-host-report", report.canonicalBytes.encoded()); Runtime.getRuntime().halt(77) }
                check(records.read("retirement-host-report").contentEquals(report.canonicalBytes.encoded()))
                publish("retirement-report-reopened", report.report.encoded())
            }
            "prepare-ack" -> prepareAck(owner)
            "erase-journal" -> {
                refused(setOf(102)) { owner.eraseJournal(exact("retirement-report-receipt", 3730)) }
                refused(setOf(2)) { owner.journalState() }
                owner.close(); owner = openOwner()
                check(owner.journalState() == RetiredErasureState.RETAINED) { "wrong-purpose receipt erased journal" }
                owner.eraseJournal(exact("retirement-ack", 3730)); Runtime.getRuntime().halt(77)
            }
            "erase-signer" -> {
                check(owner.journalState() == RetiredErasureState.ERASED)
                owner.prepareSignerErasure(exact("retirement-ack", 3730)); check(owner.signerState() == RetiredErasureState.RETAINED)
                owner.eraseSigner(); Runtime.getRuntime().halt(77)
            }
            "verify" -> {
                prepareAck(owner); publish("retirement-host-report-verified", records.read("retirement-host-report"))
                check(owner.journalState() == RetiredErasureState.ERASED && owner.signerState() == RetiredErasureState.ERASED)
                owner.eraseSigner(); refused(setOf(2)) { owner.signerState() }
                publish("retirement-verified", exact("retirement-report-proposal", 353).copyOfRange(321, 353))
            }
            else -> error("unknown retirement stage")
        }
    } catch (failure: Throwable) {
        try { owner.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
        throw failure
    }
    owner.close()
    return "retirement-stage-pass:$mode"
}
