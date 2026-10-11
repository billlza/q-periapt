// SPDX-License-Identifier: Apache-2.0 OR MIT
package configuration

import dev.qperiapt.continuity.*
import java.lang.management.ManagementFactory
import java.lang.ref.Reference
import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference
import java.nio.ByteBuffer
import java.nio.file.Path

internal fun selectRegistry(path: String, source: Path, enrollment: ContinuityEnrollment,
                            replayAssociation: Boolean): ContinuityAccountAuthority {
    val input = Path.of(path)
    val trust = AccountAuthorityTrust(AccountAuthorityID(exact(input, "registry-id", 32)),
        exact(input, "family", 32), exact(input, "witness-id", 32), exact(input, "witness-public", 1985))
    val checkpoint = AccountAuthorityCheckpoint(ApplicationAccountID(exact(input, "application", 32)),
        counter(exact(input, "revision", 8)), AccountID(exact(input, "account", 32)))
    val registry = ContinuityAccountAuthority.prepareOpen(path, trust)
    try {
        registry.finishOpen()
        check(registry.checkpoint(checkpoint.application) == checkpoint) { "original registry checkpoint differs" }
        if (replayAssociation) {
            val pin = AccountPin(checkpoint.account, exact(source, "enrollment-root", 1985), trust.family.encoded(),
                RosterCheckpoint(counter(exact(source, "trusted-roster-version", 8)), exact(source, "trusted-roster-digest", 32)))
            check(registry.associate(checkpoint.application, pin, load(source, "grant-certificate", 8192),
                load(source, "grant-roster", 65536)) == checkpoint) { "original approved association changed" }
        }
        enrollment.selectAccountAuthority(registry, checkpoint)
        return registry
    } catch (failure: Throwable) {
        try { registry.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
        throw failure
    }
}

private fun forgetRegistry(path: String, source: Path, enrollment: ContinuityEnrollment,
                           queue: ReferenceQueue<ContinuityAccountAuthority>): WeakReference<ContinuityAccountAuthority> {
    val registry = selectRegistry(path, source, enrollment, false)
    try { return WeakReference(registry, queue) } catch (failure: Throwable) {
        try { registry.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
        throw failure
    }
}

private fun collectionCount(): Long = ManagementFactory.getGarbageCollectorMXBeans().sumOf {
    it.collectionCount.also { count -> check(count >= 0) { "GC collection counts unavailable" } }
}

/** Exactly one live enrollment owns one of the 64 native slots. The registry's
 * native close drops its resource before removing the slot. Reacquiring all 63
 * remaining slots therefore observes completed native cleanup, not just a weak
 * reference being queued. Pending controls perform no installation I/O.
 */
private fun reclaimedRegistrySlot() {
    val pending = ArrayList<ContinuityDevice>()
    try {
        repeat(63) { pending.add(ContinuityDevice.prepare("/absent-registry-gc-control")) }
        expect(4) { ContinuityDevice.prepare("/absent-registry-gc-control").use { it.cancel() } }
    } catch (failure: Throwable) { closeAll(pending, failure); throw failure }
    closeAll(pending)
}

internal fun collectRegistry(path: String, source: Path, enrollment: ContinuityEnrollment): ByteArray {
    check(Runtime.getRuntime().maxMemory() in 64L * 1024 * 1024..128L * 1024 * 1024) { "registry GC requires its bounded heap" }
    val before = collectionCount()
    val queue = ReferenceQueue<ContinuityAccountAuthority>()
    val weak = forgetRegistry(path, source, enrollment, queue)
    var queued = false
    try {
        repeat(32) { round ->
            pressure()
            queue.poll()?.let { collected -> check(!queued && collected === weak); queued = true }
            check(queue.poll() == null) { "duplicate registry collection" }
            if (queued) {
                check(weak.get() == null)
                try {
                    reclaimedRegistrySlot()
                    val observed = collectionCount() - before
                    check(observed in 1..1024) { "registry GC was not observed" }
                    return ByteBuffer.allocate(16).putLong(observed).putInt(round + 1).putInt(63).array()
                } catch (failure: ContinuityFailure) {
                    if (failure.code != 4 || failure.suppressed.isNotEmpty()) throw failure
                }
            }
            Thread.sleep(10)
        }
        error("collected registry did not return its native slot within 32 GC rounds")
    } finally { Reference.reachabilityFence(enrollment) }
}
