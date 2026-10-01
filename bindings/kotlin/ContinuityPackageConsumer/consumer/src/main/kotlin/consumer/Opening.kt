// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.lang.ref.Reference
import java.nio.file.Path

/** Dispatch in the test executable keeps the public authorities distinct. */
internal sealed interface PreparedInvocation : AutoCloseable {
    fun finish()
    fun cancel()
    fun rejectWork(code: Int)
    fun inspect()
    class Operational(private val owner: ContinuityOwner) : PreparedInvocation {
        override fun finish() = owner.finishOpen()
        override fun cancel() = owner.cancel()
        override fun close() = owner.close()
        override fun rejectWork(code: Int) = refused(setOf(code)) { owner.listen("127.0.0.1:0") }
        override fun inspect() = Unit
    }
    class Recovery(private val owner: ContinuityRecoveryOwner) : PreparedInvocation {
        override fun finish() = owner.finishOpen()
        override fun cancel() = owner.cancel()
        override fun close() = owner.close()
        override fun rejectWork(code: Int) = refused(setOf(code)) { owner.sessionCount() }
        override fun inspect() { owner.sessionCount() }
    }
}

internal fun opening(args: List<String>, selected: WitnessCarrier, interruptController: Boolean): String {
    require(args.size >= 3)
    val mode = args[0]; val kind = args[2]
    val cancelled = mode == "opening-cancel"
    require(mode in setOf("opening-cancel", "opening-pre-cancel", "opening-prepare"))
    require(args.size == if (cancelled) 4 else 3)
    require(kind in setOf("operational", "recovery") && (!cancelled || kind == "operational"))
    var path = args[1]; var witness = selected
    val owner: PreparedInvocation = if (kind == "operational") {
        PreparedInvocation.Operational(ContinuityOwner.prepare(path, PrekeyQuality.ONE_TIME_BOTH, witness))
    } else PreparedInvocation.Recovery(ContinuityRecoveryOwner.prepare(path, witness))
    // Activation follows closure of the preparation call's native arena and
    // reassignment of the caller's value references. It must use original input.
    path = "changed-after-prepare"
    witness = WitnessCarrier.SignedTCP("changed-after-prepare", 1)
    try {
        val response = owner.use {
            owner.rejectWork(6)
            val number = if (kind == "operational") 1 else 2
            when (mode) {
                "opening-pre-cancel" -> {
                    owner.cancel()
                    refused(setOf(302)) { owner.finish() }
                    refused(setOf(2)) { owner.finish() }
                    owner.rejectWork(2)
                    "prepared-pre-cancel:$number"
                }
                "opening-cancel" -> {
                    var beforeInterruption = 0L
                    val elapsed = try {
                        val nanos = cancelledInvocation(218, {
                            waitMarker(args[3])
                            refused(setOf(3)) { owner.close() }
                            refused(setOf(3)) { owner.finish() }
                            owner.rejectWork(3)
                            if (interruptController) {
                                beforeInterruption = System.nanoTime()
                                Thread.currentThread().interrupt()
                                Thread.sleep(1) // Actual JVM interruption of the controlling thread.
                                error("control interruption was ignored")
                            }
                        }, owner::cancel, owner::finish)
                        check(!interruptController) { "control interruption was lost" }
                        nanos
                    } catch (failure: InterruptedException) {
                        val native = failure.suppressed.singleOrNull()
                        if (!interruptController || !Thread.currentThread().isInterrupted ||
                            native !is ContinuityFailure || native.code != 218 || beforeInterruption == 0L) {
                            throw IllegalStateException("interrupted control did not retain its native outcome and interrupt flag", failure)
                        }
                        System.nanoTime() - beforeInterruption
                    }
                    refused(setOf(2)) { owner.finish() }
                    owner.rejectWork(2)
                    "prepared-cancelled:218:${cancellationMilliseconds(elapsed)}"
                }
                else -> {
                    owner.finish()
                    refused(setOf(6)) { owner.finish() }
                    owner.inspect()
                    "prepared-open:$number"
                }
            }
        }
        refused(setOf(2)) { owner.cancel() }
        if (cancelled && interruptController) {
            // The flag survives the native checks and owner close above. Clear
            // it explicitly in this test host before writing the public receipt;
            // interruptible NIO must not turn that receipt into a partial write.
            check(Thread.interrupted()) { "owner cleanup lost the controlling thread's interrupt flag" }
            val carrier = when (selected) {
                is WitnessCarrier.SignedTCP -> "tcp"
                is WitnessCarrier.MutualTLS -> "tls"
                WitnessCarrier.Local -> error("interruption fixture requires a network witness")
            }
            FixtureRecords(Path.of(args[1])).retain("kotlin-opening-controller-interrupted-$carrier",
                "QPC-JVM-INTERRUPT/1\ncontrol-interrupted native-218 joined flag-retained owner-closed\n".toByteArray(), true)
        }
        return response
    } finally {
        Reference.reachabilityFence(path)
        Reference.reachabilityFence(witness)
    }
}
