// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.ContinuityFailure
import java.util.concurrent.atomic.AtomicReference

/** Test-owned worker only. Always join the native invocation and the thread,
 * including barrier/cancel failure or interruption of this controlling thread.
 * The enclosing native fixture bounds and reaps the whole consumer process.
 */
internal fun cancelledInvocation(expected: Int, barrier: () -> Unit, cancel: () -> Unit,
                                 operation: () -> Unit): Long {
    val outcome = AtomicReference<Throwable?>()
    val worker = Thread({
        try { operation() } catch (failure: Throwable) { outcome.set(failure) }
    }, "continuity-consumer-operation")
    worker.start()
    val barrierFailure = try { barrier(); null } catch (failure: Throwable) { failure }
    val started = System.nanoTime()
    val cancelFailure = try { cancel(); null } catch (failure: Throwable) { failure }
    var interrupted: InterruptedException? = null
    while (true) {
        try { worker.join(); break }
        catch (failure: InterruptedException) {
            if (interrupted == null) interrupted = failure else interrupted.addSuppressed(failure)
        }
    }
    val elapsed = System.nanoTime() - started
    if (interrupted != null || barrierFailure is InterruptedException || cancelFailure is InterruptedException) {
        Thread.currentThread().interrupt()
    }
    val workerFailure = outcome.get()
    val controlFailure = barrierFailure ?: cancelFailure ?: interrupted
    if (controlFailure != null) {
        for (failure in listOf(barrierFailure, cancelFailure, interrupted, workerFailure)) {
            if (failure != null && failure !== controlFailure) controlFailure.addSuppressed(failure)
        }
        throw controlFailure
    }
    if (workerFailure !is ContinuityFailure || workerFailure.code != expected) {
        throw IllegalStateException("cancelled invocation did not retain status $expected", workerFailure)
    }
    return elapsed
}

internal fun cancellationMilliseconds(nanoseconds: Long): Long {
    check(nanoseconds in 0 until 1_000_000_000L) { "cancellation exceeded its one-second observation bound" }
    return nanoseconds / 1_000_000L
}
