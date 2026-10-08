// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.lang.ref.Cleaner
import java.lang.ref.Reference
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.logging.Level
import java.util.logging.Logger

/** Neither the cleaner action nor native code retains its registered JVM owner. */
internal class NativeOwner private constructor(private val handle: Long, parent: NativeOwner? = null) : AutoCloseable {
    // The cleaner action owns only an upstream parent, never its registered child.
    // Atomic snapshots remain strong through native return even if another close
    // clears the stored reference. No native call runs under a JVM monitor.
    private class Release(private val handle: Long, parent: NativeOwner?) : Runnable {
        val disposed = AtomicBoolean(false)
        val parent = AtomicReference(parent)
        override fun run() {
            if (!disposed.compareAndSet(false, true)) return
            val retainedParent = parent.getAndSet(null)
            try {
                ContinuityNative.simple(handle, "close")
            } catch (failure: ContinuityFailure) {
                if (failure.code != 2) logger.log(Level.SEVERE, "Continuity disposal failed with native status {0}", failure.code)
            } catch (failure: Throwable) {
                logger.log(Level.SEVERE, "Continuity disposal failed", failure)
            } finally {
                Reference.reachabilityFence(retainedParent)
            }
        }
    }
    private val release = Release(handle, parent)
    private val cleanable = cleaner.register(this, release)
    @JvmSynthetic fun <T> call(body: (Long) -> T): T {
        val parent = release.parent.get()
        try { return body(handle) } finally {
            Reference.reachabilityFence(parent)
            Reference.reachabilityFence(this)
        }
    }
    override fun close() = call {
        try {
            ContinuityNative.simple(it, "close")
        } catch (failure: ContinuityFailure) {
            if (failure.code == 2) disposed()
            throw failure // BUSY/unknown failure preserves the parent and original diagnostic.
        }
        disposed()
    }
    private fun disposed() {
        release.disposed.set(true)
        release.parent.set(null)
        cleanable.clean()
    }
    companion object {
        private val cleaner = Cleaner.create()
        private val logger = Logger.getLogger("dev.qperiapt.continuity")
        @JvmSynthetic internal fun <T> prepare(path: String, kind: Int, quality: Int, witness: WitnessCarrier, wrap: (NativeOwner) -> T,
                                              session: SessionID? = null, setup: SetupIntent? = null,
                                              enrollment: EnrollmentPreparation? = null): T {
            val handle = ContinuityNative.prepare(path, kind, quality, witness, session, setup, enrollment)
            return try { wrap(NativeOwner(handle)) } catch (failure: Throwable) {
                try { ContinuityNative.simple(handle, "close") } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
        @JvmSynthetic internal fun <T> preparePeer(parent: NativeOwner, path: String, quality: PrekeyQuality,
                                                 role: BootstrapRole, session: SessionID?, wrap: (NativeOwner) -> T): T = parent.call {
            val handle = ContinuityNative.preparePeer(it, path, quality, role, session)
            try { wrap(NativeOwner(handle, parent)) } catch (failure: Throwable) {
                try { ContinuityNative.simple(handle, "close") } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
        @JvmSynthetic internal fun <T> prepareRetired(path: String, intent: EnrollmentIntent,
            authority: RetiredEnrollmentAuthority, wrap: (NativeOwner) -> T): T {
            val handle = ContinuityNative.prepareRetired(path, intent, authority)
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
        @JvmSynthetic internal fun preparePeer(parent: NativeOwner, path: String, quality: PrekeyQuality,
                                              role: BootstrapRole, session: SessionID?): ContinuityOwner =
            NativeOwner.preparePeer(parent, path, quality, role, session, ::ContinuityOwner)
        fun prepare(path: String, quality: PrekeyQuality, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityOwner =
            NativeOwner.prepare(path, 1, quality.code, witness, ::ContinuityOwner)
        fun open(path: String, quality: PrekeyQuality, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityOwner {
            val owner = prepare(path, quality, witness)
            try { owner.finishOpen(); return owner } catch (failure: Throwable) {
                try { owner.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
        /** Copy an explicit existing-session selection; finishOpen performs all durable admission. */
        fun prepareReopen(path: String, quality: PrekeyQuality, session: SessionID,
                          witness: WitnessCarrier = WitnessCarrier.Local): ContinuityOwner =
            NativeOwner.prepare(path, 1, quality.code, witness, ::ContinuityOwner, session)
        /** Restore original Active state; never create missing state or retry fresh admission. */
        fun reopen(path: String, quality: PrekeyQuality, session: SessionID,
                   witness: WitnessCarrier = WitnessCarrier.Local): ContinuityOwner {
            val owner = prepareReopen(path, quality, session, witness)
            try { owner.finishOpen(); return owner } catch (failure: Throwable) {
                try { owner.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
    }
    @JvmSynthetic internal fun <T> call(body: (Long) -> T): T = native.call(body)
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
    /** Consumes discovery and authenticates every original member before recovery writes. */
    fun selectAccount(operation: AccountOperationID) = native.call { ContinuityNative.idOperation(it, "select_account", operation) }
    /** Permanently freezes the whole account; read all members and nested entries before host acknowledgement. */
    fun beginAccountCleanup(): AccountCleanupHeader = native.call { ContinuityNative.accountBegin(it) }
    /** Fresh aggregate status; it never infers delivery or cached witness permission. */
    fun accountCleanupStatus(): AccountStatus = native.call { ContinuityNative.accountCleanupStatus(it) }
    /** Reconcile ALL original members in one native observation. Reserved or
     * unresolved abandonment is refused; failures never become empty results. */
    fun reconcileAccount(): AccountReconciliation = native.call { ContinuityNative.accountReconciliation(it) }
    fun accountMemberAt(member: Long): AccountCleanupMember = native.call { ContinuityNative.accountMember(it, member) }
    fun accountReservation(member: Long): ReservedLoss = native.call { ContinuityNative.accountReservation(it, member) }
    fun accountEpochAt(member: Long, epoch: Long): ClosureEpoch = native.call { ContinuityNative.accountEpoch(it, member, epoch) }
    fun accountUnconfirmedAt(member: Long, epoch: Long, index: Long): UnconfirmedLoss =
        native.call { ContinuityNative.accountUnconfirmed(it, member, epoch, index) }
    fun accountDeliveryAt(member: Long, epoch: Long, index: Long): DeliveryLoss =
        native.call { ContinuityNative.accountDelivery(it, member, epoch, index) }
    /** A skipped position does not prove a peer ever sent that message. */
    fun accountSkippedPosition(member: Long, epoch: Long, index: Long): Counter64 =
        native.call { ContinuityNative.accountSkipped(it, member, epoch, index) }
    /** Only after the complete report and original IDs are durable in one deduplicated host transaction. */
    fun acknowledgeAccount(report: AccountAbandonmentID) = native.call { ContinuityNative.idOperation(it, "account_acknowledge", report) }
    /** Retires acknowledged abandonment or a committed batch whose EVERY original
     * member is settled. Persist needed complete results first; original session
     * records and consumed capacity remain. */
    fun retireAccount() = native.call { ContinuityNative.simple(it, "account_retire") }
}
