// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.ContinuityFailure
import dev.qperiapt.continuity.ContinuityOwner
import dev.qperiapt.continuity.ContinuityRecoveryOwner
import dev.qperiapt.continuity.PrekeyQuality
import java.lang.management.ManagementFactory
import java.lang.ref.Reference
import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

private const val OWNER_CAPACITY = 64
private const val GC_ROUNDS = 32
private const val OWNER_ROUNDS = 16
private const val ABSENT_INSTALLATION = "/absent-continuity-gc-probe"

private class PendingOwners : AutoCloseable {
    val values = ArrayList<PreparedInvocation>()
    fun fill() {
        repeat(OWNER_CAPACITY) { index ->
            values.add(if (index % 2 == 0) PreparedInvocation.Operational(
                ContinuityOwner.prepare(ABSENT_INSTALLATION, PrekeyQuality.ONE_TIME_BOTH))
            else PreparedInvocation.Recovery(ContinuityRecoveryOwner.prepare(ABSENT_INSTALLATION)))
        }
    }
    override fun close() {
        var failure: Throwable? = null
        for (owner in values) try { owner.close() } catch (error: Throwable) {
            if (failure == null) failure = error else failure.addSuppressed(error)
        }
        failure?.let { throw it }
    }
}

private fun capacityMustBeFull() {
    refused(setOf(4)) {
        ContinuityRecoveryOwner.prepare(ABSENT_INSTALLATION).use { it.cancel() }
    }
}

/** Return only weak references. The native Cleaner must not retain this graph. */
private fun forgetOwners(queue: ReferenceQueue<PreparedInvocation>): List<WeakReference<PreparedInvocation>> {
    val owners = PendingOwners()
    try {
        owners.fill()
        capacityMustBeFull()
        return owners.values.map { WeakReference(it, queue) }
    } catch (failure: Throwable) {
        try { owners.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
        throw failure
    }
}

internal fun pressure() {
    val buffers = Array(8) { index -> ByteArray(1024 * 1024) { index.toByte() } }
    check(buffers.sumOf { it.first().toInt() + it.last().toInt() } == 56)
    System.gc()
    Reference.reachabilityFence(buffers)
}

internal fun collectionCount(): Long = ManagementFactory.getGarbageCollectorMXBeans().sumOf {
    val count = it.collectionCount
    check(count >= 0) { "GC collection counts are unavailable" }
    count
}

/** Called only after an unrooted native invocation has returned. A prematurely
 * disposed BUSY owner must not silently strand any of the shared 64 slots.
 */
internal fun requireNativeOwnerTableDrained() {
    repeat(GC_ROUNDS) {
        pressure()
        try {
            PendingOwners().use { pool -> pool.fill(); capacityMustBeFull() }
            return
        } catch (failure: ContinuityFailure) {
            if (failure.code != 4 || failure.suppressed.isNotEmpty()) throw failure
        }
        Thread.sleep(10)
    }
    error("returned native invocation did not release its original owner slot within $GC_ROUNDS GC rounds")
}

/** Bounded test-only observation of the nondeterministic Cleaner backstop.
 * Only native capacity status 4 is retried. No installation, protocol operation
 * or production API is retried; every partially acquired pool is closed.
 */
private fun reclaimedPool(queue: ReferenceQueue<PreparedInvocation>,
                          references: List<WeakReference<PreparedInvocation>>): PendingOwners {
    val remaining = references.toMutableSet()
    repeat(GC_ROUNDS) {
        pressure()
        while (true) {
            val reference = queue.poll() ?: break
            check(remaining.remove(reference)) { "unexpected or repeated collected owner graph" }
        }
        if (remaining.isEmpty()) {
            check(references.all { it.get() == null })
            val pool = PendingOwners()
            try { pool.fill(); return pool } catch (failure: Throwable) {
                try { pool.close() } catch (disposal: Throwable) {
                    failure.addSuppressed(disposal)
                    throw failure
                }
                if (failure !is ContinuityFailure || failure.code != 4) throw failure
            }
        }
        Thread.sleep(10)
    }
    error("collected owner graphs did not release all original native slots within $GC_ROUNDS GC rounds")
}

private fun sentinel(queue: ReferenceQueue<Any>) = WeakReference(Any(), queue)

private fun gcOwnerRound(): Long {
    check(Files.notExists(Path.of(ABSENT_INSTALLATION), NOFOLLOW_LINKS)) { "GC fixture installation unexpectedly exists" }
    check(Runtime.getRuntime().maxMemory() in (64L * 1024 * 1024)..(128L * 1024 * 1024)) {
        "GC fixture requires its explicit bounded heap"
    }
    val before = collectionCount()
    val queue = ReferenceQueue<PreparedInvocation>()
    val forgotten = forgetOwners(queue)
    val restored = reclaimedPool(queue, forgotten)
    restored.use {
        capacityMustBeFull()
        val sentinelQueue = ReferenceQueue<Any>()
        val control = sentinel(sentinelQueue)
        var collected = false
        for (round in 0 until GC_ROUNDS) {
            pressure()
            if (sentinelQueue.poll() === control) { collected = true; break }
            Thread.sleep(10)
        }
        check(collected && control.get() == null) { "live-owner GC control did not collect its sentinel" }
        // These strong owner graphs must still own every native slot after an
        // observed collection of the unreachable control object.
        capacityMustBeFull()
        for (owner in restored.values) owner.rejectWork(6)
    }
    PendingOwners().use { replacements ->
        replacements.fill()
        capacityMustBeFull()
        for (stale in restored.values) {
            refused(setOf(2)) { stale.cancel() }
            refused(setOf(2)) { stale.finish() }
            refused(setOf(2)) { stale.close() }
        }
        for (owner in replacements.values) {
            owner.rejectWork(6)
            // The original C entry points distinguish missing operational
            // configuration (500) from recovery private-file admission (203).
            // A stale cancel/close must not change either outcome to 302/2.
            val admissionFailure = when (owner) {
                is PreparedInvocation.Operational -> 500
                is PreparedInvocation.Recovery -> 203
            }
            refused(setOf(admissionFailure)) { owner.finish() }
            owner.rejectWork(2)
        }
    }
    ContinuityRecoveryOwner.prepare(ABSENT_INSTALLATION).use {
        it.cancel()
        refused(setOf(302)) { it.finishOpen() }
    }
    val collections = collectionCount() - before
    check(collections in 2..1024) { "GC fixture did not observe its bounded collection workload" }
    return collections
}

internal fun gcOwnerCapacity(): String {
    var collections = 0L
    repeat(OWNER_ROUNDS) { round ->
        try { collections += gcOwnerRound() } catch (failure: Throwable) {
            throw IllegalStateException("prepared-owner GC round ${round + 1} failed", failure)
        }
    }
    val count = OWNER_CAPACITY * OWNER_ROUNDS
    return "QPC-JVM-GC/1 rounds=$OWNER_ROUNDS forgotten=$count queued=$count live=$count stale=$count collections=$collections"
}
