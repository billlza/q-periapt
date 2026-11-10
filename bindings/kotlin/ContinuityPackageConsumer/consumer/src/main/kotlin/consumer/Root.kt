// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.lang.management.ManagementFactory
import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference

internal fun rootCommand(args: List<String>): String {
    require(args.size == 6 || args.size == 8)
    val parts = args[0].split(':'); require(parts.size in 1..2)
    val route = if (parts.size == 1) "original" else parts[0]; val mode = parts.last()
    require(route in setOf("original", "transition", "adoption"))
    val traffic = mode.startsWith("traffic-"); require(args.size == if (traffic) 8 else 6)
    val input = RootInputs(args); rootNumber(input.publicPath, "process-$mode", ProcessHandle.current().pid())
    if (mode == "verify") {
        rootCollectedController(input, route)
        return "root-stage-pass:$mode"
    }
    var successor: ContinuityDevice? = null
    return AutoCloseable { successor?.close() }.use {
        ContinuityAccountAuthority.prepareOpen(input.registryPath, input.trust).use { root ->
            root.finishOpen()
            if (mode == "traffic-authorize-peer") {
                rootAuthorizePeer(root, input, args[6]); return "root-stage-pass:$mode"
            }
            if (mode == "begin") {
                ContinuityEnrollment.prepareResume(input.oldPath, input.original, input.witness).use { enrollment ->
                    enrollment.finishOpen(); enrollment.selectAccountAuthority(root, input.scope.checkpoint)
                    enrollment.activate().use { device ->
                        root.beginRootReplacement(device, input.scope, input.plan)
                        refused(setOf(2)) { device.nextPublication() }
                    }
                }
            } else input.resume(root, route)
            val state = root.rootReplacementState()
            when (mode) {
                "begin", "preparing" -> check(state == RootReplacementState.PREPARING)
                "freeze", "freeze-retry", "freeze-original" -> {
                    val proposal = root.bindRootFreeze(input.records.read("freeze-receipt")).bytes.encoded()
                    if (mode == "freeze-retry") check(proposal.contentEquals(input.records.read("bound-proposal")))
                    else input.records.retain(if (mode == "freeze") "bound-proposal" else "original-bound-proposal", proposal, true)
                }
                "transition", "transition-retry" -> {
                    val proposal = root.transitionRoot(input.transition()).bytes.encoded()
                    if (mode == "transition") input.records.retain("bound-proposal", proposal, true)
                    else check(proposal.contentEquals(input.records.read("bound-proposal")))
                }
                "adopt", "adopt-retry" -> input.checkpoint(root.adoptRoot(input.adoption()))
                "retain", "retain-retry" -> input.checkpoint(root.retainRootRetirement(input.records.read("retirement-receipt")))
                else -> {
                    check(state == RootReplacementState.COMMITTED) { "cleanup without committed root" }
                    ContinuityEnrollment.prepareResume(input.targetPath, input.target, input.witness).use { enrollment ->
                        enrollment.finishOpen()
                        if (mode == "activation-unknown") {
                            refused(setOf(218)) { root.activateRootSuccessor(enrollment) }
                            refused(setOf(2)) { root.rootReplacementState() }; refused(setOf(2)) { enrollment.status() }
                            return "root-stage-pass:$mode"
                        }
                        val device = root.activateRootSuccessor(enrollment); successor = device
                        if (traffic) rootTraffic(device, input, mode, args[6], args[7])
                        else {
                            val before = device.nextPublication(); rootCleanup(root, input.records, mode)
                            check(before == device.nextPublication()) { "historical cleanup changed successor publication" }
                        }
                    }
                }
            }
            if (mode in setOf("begin", "freeze", "freeze-original", "transition", "adopt", "retain", "inventory", "report", "prepare-ack", "journal", "signer")) {
                rootPause(input.publicPath, mode)
            }
        }
        successor?.let { device -> refused(setOf(202)) { device.nextPublication() } }
        "root-stage-pass:$mode"
    }
}

private fun rootCleanup(root: ContinuityAccountAuthority, records: FixtureRecords, mode: String) {
    when (mode) {
        "inventory" -> records.retain("inventory", root.retiredInventory().bytes.encoded(), true)
        "prepare-report" -> records.retain("report-proposal", root.prepareRetiredReport(records.read("inventory-receipt")).bytes.encoded(), true)
        "report", "prepare-ack" -> {
            val inventory = records.read("inventory-receipt"); val reportReceipt = records.read("report-receipt")
            val report = root.loadRetiredReport(inventory, reportReceipt).canonicalBytes.encoded()
            if (mode == "report") records.retain("host-report", report, true)
            else {
                val original = records.read("host-report"); check(original.contentEquals(report))
                val ack = root.prepareRetiredAcknowledgement(inventory, reportReceipt, original)
                check(ack.bytes.encoded().contentEquals(records.read("report-proposal"))) { "ACK changed original report identity" }
            }
        }
        "journal" -> {
            root.eraseRetiredJournal(records.read("host-ack")); check(root.retiredJournalState() == RetiredErasureState.ERASED)
        }
        "signer" -> { root.prepareRetiredSignerErasure(records.read("host-ack")); root.eraseRetiredSigner() }
        "verify" -> Unit
        else -> error("unknown root cleanup stage")
    }
    if (mode == "signer" || mode == "verify") {
        check(root.retiredSignerState() == RetiredErasureState.ERASED && root.retiredJournalState() == RetiredErasureState.ERASED)
    }
}
private data class DetachedRoot(val device: ContinuityDevice, val root: WeakReference<ContinuityAccountAuthority>)
private fun detachedRoot(input: RootInputs, route: String, queue: ReferenceQueue<ContinuityAccountAuthority>): DetachedRoot {
    val root = ContinuityAccountAuthority.prepareOpen(input.registryPath, input.trust)
    var device: ContinuityDevice? = null
    try {
        root.finishOpen(); input.resume(root, route); check(root.rootReplacementState() == RootReplacementState.COMMITTED)
        val successor = ContinuityEnrollment.prepareResume(input.targetPath, input.target, input.witness).use { enrollment ->
            enrollment.finishOpen(); root.activateRootSuccessor(enrollment)
        }
        device = successor
        val before = successor.nextPublication(); rootCleanup(root, input.records, "verify")
        check(before == successor.nextPublication())
        return DetachedRoot(successor, WeakReference(root, queue))
    } catch (failure: Throwable) {
        try { device?.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
        try { root.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
        throw failure
    }
}
private fun rootCollectedController(input: RootInputs, route: String) {
    val queue = ReferenceQueue<ContinuityAccountAuthority>(); val transferred = detachedRoot(input, route, queue)
    transferred.device.use { device ->
        val before = collectionCount(); var queued = false; var revoked = false
        for (round in 0 until 32) {
            pressure(); if (queue.poll() === transferred.root) queued = true
            try { device.nextPublication() } catch (failure: ContinuityFailure) {
                check(failure.code == 202) { "collected registry returned another native outcome" }; revoked = true
            }
            if (queued && revoked) break
            Thread.sleep(10)
        }
        val collections = collectionCount() - before
        check(queued && revoked && transferred.root.get() == null && collections > 0) { "registry Cleaner did not revoke successor within the bound" }
        val names = ManagementFactory.getGarbageCollectorMXBeans().map { it.name }.toSet()
        val collector = when (names) {
            setOf("Copy", "MarkSweepCompact") -> "Serial"
            setOf("G1 Young Generation", "G1 Concurrent GC", "G1 Old Generation") -> "G1"
            else -> error("unrecognized garbage collector: $names")
        }
        input.records.retain("root-gc-collector", collector.toByteArray(), true)
        rootNumber(input.publicPath, "gc-revokes-successor", 1); rootNumber(input.publicPath, "gc-collections", collections)
    }
}
