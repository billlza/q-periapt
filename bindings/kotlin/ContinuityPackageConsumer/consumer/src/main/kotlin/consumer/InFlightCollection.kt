// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.lang.ref.WeakReference
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicReference

/** Test executable only. Neither the caller nor its upcall retains the public
 * owner after closeFromCallback returns. The SDK must keep the native owner
 * alive across its downcall, independently of this weak observation.
 */
internal class UnrootedInvocation(owner: ContinuityOwner, path: String, private val mode: String) :
    ServingOwner, AutoCloseable {
    private val invocation = AtomicReference<ContinuityOwner?>(owner)
    private val control = AtomicReference<ContinuityOwner?>(owner)
    private val weak = WeakReference(owner)
    private val records = FixtureRecords(Path.of(path))
    private var retained: ApplicationDelivery? = null
    private var original: ByteArray? = null
    private var callbackCollections = 0L

    override fun listen(address: String) = requireNotNull(control.get()).listen(address)
    override fun cancel() = requireNotNull(control.get()).cancel()
    override fun serveRekey(session: SessionID) = requireNotNull(control.get()).serveRekey(session)
    // Keep this call free of a post-return use of the public owner. The stress
    // JVM explicitly compiles this method and both SDK downcall frames.
    override fun serve(commit: ApplicationCommit) = requireNotNull(invocation.getAndSet(null)).serve(commit)
    override fun closeFromCallback() {
        val owner = requireNotNull(control.getAndSet(null))
        check(invocation.get() == null)
        refused(setOf(3)) { owner.close() }
    }
    private fun copied(delivery: ApplicationDelivery) =
        delivery.session.encoded() + delivery.message.encoded() + delivery.plaintext()

    override fun observeDelivery(delivery: ApplicationDelivery) {
        check(retained == null && original == null)
        retained = delivery
        original = copied(delivery)
        // Mutating returned copies must not invalidate the owned delivery.
        delivery.session.encoded().fill(0)
        delivery.message.encoded().fill(0)
        delivery.plaintext().fill(0)
        val before = collectionCount()
        for (round in 0 until 32) {
            pressure()
            Thread.sleep(10)
            if (weak.get() == null) break
        }
        check(weak.get() == null) { "public owner remained rooted during native callback" }
        // Allow the Cleaner to run while the downcall is still BUSY. A missing
        // reachability fence must be observable here or at the slot-drain check.
        repeat(4) { pressure(); Thread.sleep(10) }
        callbackCollections = collectionCount() - before
        check(callbackCollections in 5..1024 && copied(delivery).contentEquals(requireNotNull(original))) {
            "callback GC did not preserve its owned delivery"
        }
        records.retain("kotlin-gc-callback-$mode-${hex(delivery.message)}",
            ("QPC-JVM-INFLIGHT/1 callback collections=$callbackCollections\n").toByteArray() +
                requireNotNull(original), true)
    }

    fun afterReturn() {
        val delivery = retained ?: return
        check(invocation.get() == null && control.get() == null && weak.get() == null)
        // The FFM arena has now closed. Its copied IDs and plaintext must remain
        // usable, and every native slot must be available again.
        requireNativeOwnerTableDrained()
        check(copied(delivery).contentEquals(requireNotNull(original))) { "delivery escaped with borrowed native memory" }
        records.retain("kotlin-gc-return-$mode-${hex(delivery.message)}",
            "QPC-JVM-INFLIGHT/1 returned slots=64 copied-delivery-valid\n".toByteArray() +
                requireNotNull(original), true)
    }

    override fun close() {
        // Callback-free bootstrap, duplicate, rekey and cancellation paths still
        // use explicit close. Callback paths have deliberately released both refs.
        invocation.set(null)
        control.getAndSet(null)?.close()
    }
}

internal fun serveUnrooted(path: String, mode: String, session: String?, witness: WitnessCarrier): String {
    check(Runtime.getRuntime().maxMemory() in (64L * 1024 * 1024)..(128L * 1024 * 1024)) {
        "in-flight GC fixture requires its explicit bounded heap"
    }
    // Initialize the bridge before compiling the frames used for the real call.
    repeat(32) {
        ContinuityOwner.prepare("/absent-continuity-gc-probe", PrekeyQuality.ONE_TIME_BOTH).use { pending ->
            refused(setOf(6)) { pending.serve { error("pending owner invoked application") } }
        }
    }
    return UnrootedInvocation(ContinuityOwner.open(path, PrekeyQuality.ONE_TIME_BOTH, witness), path, mode).use {
        val result = serve(it, path, mode, session)
        it.afterReturn()
        result
    }
}
