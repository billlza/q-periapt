// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.lang.ref.Cleaner
import java.lang.ref.Reference
import java.util.concurrent.atomic.AtomicBoolean
import java.util.logging.Level
import java.util.logging.Logger

/** Neither the cleaner action nor native code retains its registered JVM owner. */
private class NativeOwner private constructor(private val handle: Long) : AutoCloseable {
    private class Release(private val handle: Long) : Runnable {
        val disposed = AtomicBoolean(false)
        override fun run() {
            if (!disposed.compareAndSet(false, true)) return
            try {
                ContinuityNative.simple(handle, "close")
            } catch (failure: ContinuityFailure) {
                if (failure.code != 2) logger.log(Level.SEVERE, "Continuity disposal failed with native status {0}", failure.code)
            } catch (failure: Throwable) {
                logger.log(Level.SEVERE, "Continuity disposal failed", failure)
            }
        }
    }
    private val release = Release(handle)
    private val cleanable = cleaner.register(this, release)
    fun <T> call(body: (Long) -> T): T = try { body(handle) } finally { Reference.reachabilityFence(this) }
    override fun close() = call {
        ContinuityNative.simple(it, "close") // BUSY/unknown failure leaves the owner registered and callable.
        release.disposed.set(true)
        cleanable.clean()
    }
    companion object {
        private val cleaner = Cleaner.create()
        private val logger = Logger.getLogger("dev.qperiapt.continuity")
        fun <T> prepare(path: String, kind: Int, quality: Int, witness: WitnessCarrier, wrap: (NativeOwner) -> T): T {
            val handle = ContinuityNative.prepare(path, kind, quality, witness)
            return try { wrap(NativeOwner(handle)) } catch (failure: Throwable) {
                try { ContinuityNative.simple(handle, "close") } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
    }
}

/**
 * One operational reference to the ORIGINAL private installation. All operations
 * are synchronous; the native registry returns BUSY rather than blocking cancel
 * behind another JVM call. Use close/use deterministically; Cleaner is a backstop.
 * Unknown results require reopening original state and reconciling the SAME ID.
 */
class ContinuityOwner private constructor(private val native: NativeOwner) : AutoCloseable {
    companion object {
        fun prepare(path: String, quality: PrekeyQuality, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityOwner =
            NativeOwner.prepare(path, 1, quality.code, witness, ::ContinuityOwner)
        fun open(path: String, quality: PrekeyQuality, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityOwner {
            val owner = prepare(path, quality, witness)
            try { owner.finishOpen(); return owner } catch (failure: Throwable) {
                try { owner.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
    }
    /** Activate once on this thread. Another thread may cancel this known pending owner. */
    fun finishOpen() = native.call { ContinuityNative.simple(it, "finish_open") }
    /** One-way; cancel, join active work, close and reopen the original installation. */
    fun cancel() = native.call { ContinuityNative.simple(it, "cancel") }
    /** BUSY leaves ownership intact. A successful close is visible to all aliases. */
    override fun close() = native.close()
    fun establish(peer: String, request: InitiationID): Establishment = native.call { ContinuityNative.establish(it, peer, request) }
    fun nextMessage(session: SessionID): MessageID = native.call { ContinuityNative.next(it, session) }
    fun messageStatus(session: SessionID, message: MessageID): MessageStatus = native.call { ContinuityNative.messageStatus(it, session, message) }
    fun send(peer: String, session: SessionID, message: MessageID, plaintext: ByteArray, associatedData: ByteArray): SendResult =
        native.call { ContinuityNative.send(it, peer, session, message, plaintext, associatedData) }
    fun rekey(peer: String, session: SessionID, target: Counter64): Counter64 = native.call { ContinuityNative.rekey(it, peer, session, target) }
    fun listen(address: String): Int = native.call { ContinuityNative.listen(it, address) }
    /** The callback receives owned copies, and must commit effect and deduplication durably together. */
    fun serve(commit: ApplicationCommit): Served = native.call { ContinuityNative.serve(it, commit) }
    fun serveRekey(session: SessionID): Counter64 = native.call { ContinuityNative.serveRekey(it, session) }
}

/** Cleanup-only authority. This type has no operational method or handle conversion. */
class ContinuityRecoveryOwner private constructor(private val native: NativeOwner) : AutoCloseable {
    companion object {
        fun prepare(path: String, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityRecoveryOwner =
            NativeOwner.prepare(path, 2, 0, witness, ::ContinuityRecoveryOwner)
        fun open(path: String, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityRecoveryOwner {
            val owner = prepare(path, witness)
            try { owner.finishOpen(); return owner } catch (failure: Throwable) {
                try { owner.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
    }
    fun finishOpen() = native.call { ContinuityNative.simple(it, "finish_open") }
    fun cancel() = native.call { ContinuityNative.simple(it, "cancel") }
    override fun close() = native.close()
    fun sessionCount(): Long = native.call { ContinuityNative.sessionCount(it) }
    fun sessionAt(index: Long): SessionID = native.call { ContinuityNative.sessionAt(it, index) }
    fun select(session: SessionID) = native.call { ContinuityNative.idOperation(it, "select", session) }
    fun selectArchive(archive: ByteArray) = native.call { ContinuityNative.selectArchive(it, archive) }
    fun archive(): ByteArray = native.call { ContinuityNative.archive(it) }
    /** Permanently freeze before reading every nested field; this is not an acknowledgement. */
    fun begin(): ClosureHeader = native.call { ContinuityNative.begin(it) }
    fun status(): ClosureStatus = native.call { ContinuityNative.status(it) }
    fun reservationAt(index: Long): ReservedLoss = native.call { ContinuityNative.reservation(it, index) }
    fun epochAt(index: Long): ClosureEpoch = native.call { ContinuityNative.epoch(it, index) }
    fun unconfirmedAt(epoch: Long, index: Long): UnconfirmedLoss = native.call { ContinuityNative.unconfirmed(it, epoch, index) }
    fun deliveryAt(epoch: Long, index: Long): DeliveryLoss = native.call { ContinuityNative.delivery(it, epoch, index) }
    fun skippedPosition(epoch: Long, index: Long): Counter64 = native.call { ContinuityNative.skipped(it, epoch, index) }
    /** Call only after the host has durably retained the complete original report and its ID. */
    fun acknowledge(report: ClosureReportID) = native.call { ContinuityNative.idOperation(it, "acknowledge", report) }
    fun retire(report: ClosureReportID): Boolean = native.call { ContinuityNative.retire(it, report) }
    fun restoreIndex() = native.call { ContinuityNative.simple(it, "restore_index") }
}
