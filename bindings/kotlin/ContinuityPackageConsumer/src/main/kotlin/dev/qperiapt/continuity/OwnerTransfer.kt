// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.lang.ref.Reference

/** Move the existing owning reference, preserving its one Cleaner and immutable
 * handle. No native call or release runs under this cell's monitor.
 */
internal class OwnerTransfer(private var native: NativeOwner?, private val operation: String) {
    private val monitor = Any()
    private var borrowed = 0
    private var transferring = false
    private var transferred = false
    private fun closed() = ContinuityFailure(operation, 2, "$operation owner is closed or transferred", false)
    private fun busy() = ContinuityFailure(operation, 3, "$operation owner has an active call or transfer", false)
    fun <T> call(cancellation: Boolean = false, body: (NativeOwner) -> T): T {
        val owner = synchronized(monitor) {
            val owner = native ?: throw closed()
            if (transferring && !cancellation) throw busy()
            borrowed += 1
            owner
        }
        try { return body(owner) } finally {
            synchronized(monitor) { borrowed -= 1 }
            Reference.reachabilityFence(owner)
            Reference.reachabilityFence(this)
        }
    }
    fun <T> transfer(body: (NativeOwner) -> T): T {
        val owner = synchronized(monitor) {
            val owner = native ?: throw closed()
            if (transferring || borrowed != 0) throw busy()
            transferring = true
            owner
        }
        try {
            val successor = body(owner)
            synchronized(monitor) {
                native = null
                transferred = true
            }
            return successor
        } finally {
            synchronized(monitor) { transferring = false }
            Reference.reachabilityFence(owner)
            Reference.reachabilityFence(this)
        }
    }
    fun close() {
        val owner = synchronized(monitor) {
            if (transferred) return
            val owner = native ?: throw closed()
            if (transferring) throw busy()
            borrowed += 1
            owner
        }
        try {
            try { owner.close() } catch (failure: ContinuityFailure) {
                if (failure.code == 2) synchronized(monitor) { native = null }
                throw failure
            }
            synchronized(monitor) { native = null }
        } finally {
            synchronized(monitor) { borrowed -= 1 }
            Reference.reachabilityFence(owner)
            Reference.reachabilityFence(this)
        }
    }
}
