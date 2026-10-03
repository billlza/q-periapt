// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference
import java.util.HexFormat

private data class SetupTransfer(val device: ContinuityDevice, val old: WeakReference<ContinuitySetup>)
private fun transferSetup(path: String, witness: WitnessCarrier, queue: ReferenceQueue<ContinuitySetup>): SetupTransfer =
    ContinuitySetup.resume(path, witness).use { setup ->
        val old = WeakReference(setup, queue)
        val device = setup.activate()
        try {
            setup.close()
            refused(setOf(2)) { setup.status() }
            refused(setOf(2)) { setup.prepareStorage() }
            refused(setOf(2)) { setup.activate() }
            refused(setOf(2)) { setup.cancel() }
            SetupTransfer(device, old)
        } catch (failure: Throwable) {
            try { device.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
            throw failure
        }
    }

internal fun setup(args: List<String>, witness: WitnessCarrier): String {
    require(args.size in 2..3) { "setup arguments" }
    val mode = args[0]
    val cancelled = mode == "setup-cancel"
    val preCancelled = mode == "setup-pre-cancel"
    require(mode in setOf("setup-create", "setup-status", "setup-storage", "setup-activate", "setup-device", "setup-pre-cancel", "setup-cancel"))
    if (cancelled) require(args.size == 3 && witness != WitnessCarrier.Local) { "setup cancellation barrier missing" }
    val expected = if (!cancelled && args.size == 3) args[2].toInt().also { require(it in 1..10000) } else null
    if (mode == "setup-device") {
        fun operation(): AccountOperationID = ContinuityDevice.open(args[1], witness).use { it.nextAccountOperation() }
        return if (expected == null) "setup-device\n${hex(operation())}" else {
            refused(setOf(expected)) { operation() }
            "setup-refused:$expected"
        }
    }
    if (mode == "setup-activate" && expected == null) {
        val queue = ReferenceQueue<ContinuitySetup>()
        val transfer = transferSetup(args[1], witness, queue)
        val batch = transfer.device.use { device ->
            val before = collectionCount()
            var queued = false
            for (round in 0 until 32) {
                pressure()
                val observed = queue.poll()
                if (observed != null) {
                    check(observed === transfer.old && queue.poll() == null) { "unexpected setup reference queued" }
                    queued = true
                    break
                }
                Thread.sleep(10)
            }
            check(queued && transfer.old.get() == null && collectionCount() > before) { "old setup was not collected within 32 GC rounds" }
            device.nextAccountOperation()
        }
        refused(setOf(2)) { transfer.device.nextAccountOperation() }
        return "setup-activated\n${hex(batch)}\nsetup-transfer:closed-alias-released-device-live"
    }
    val setup = if (mode == "setup-create" || preCancelled) ContinuitySetup.prepareCreate(args[1], witness)
        else ContinuitySetup.prepareResume(args[1], witness)
    return setup.use { owner ->
        fun operation(): String {
            if (preCancelled) owner.cancel()
            owner.finishOpen()
            return when (mode) {
                "setup-cancel" -> {
                    val elapsed = cancelledInvocation(218, {
                        waitMarker(args[2])
                        refused(setOf(3)) { owner.close() }
                        refused(setOf(3)) { owner.status() }
                        refused(setOf(3)) { owner.prepareStorage() }
                        refused(setOf(3)) { owner.activate() }
                    }, owner::cancel) { owner.activate().use { error("cancelled setup activation reported success") } }
                    refused(setOf(2)) { owner.status() }
                    "setup-cancelled:218:${cancellationMilliseconds(elapsed)}"
                }
                "setup-storage" -> when (val result = owner.prepareStorage()) {
                    is InstallationPreparation.Local -> "setup-prepared:1\n${hex(result.journal)}\n${"0".repeat(192)}\n${"0".repeat(64)}"
                    is InstallationPreparation.RequiresEnrollment -> {
                        val genesis = result.genesis
                        "setup-prepared:2\n${hex(genesis.journal)}\n${HexFormat.of().formatHex(genesis.subject.encoded())}\n${HexFormat.of().formatHex(genesis.imageDigest.encoded())}"
                    }
                }
                "setup-activate" -> owner.activate().use { error("expected refused setup activation succeeded") }
                else -> {
                    val status = owner.status()
                    "setup-status:${if (status.phase == InstallationPhase.CREATING) 1 else 2}\n${hex(status.journal)}"
                }
            }
        }
        if (expected == null) operation() else {
            refused(setOf(expected)) { operation() }
            "setup-refused:$expected"
        }
    }
}
