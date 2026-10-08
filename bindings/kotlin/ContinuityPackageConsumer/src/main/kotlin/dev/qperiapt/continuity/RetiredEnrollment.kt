// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

/** Independently retained pin and original replacement proof. Width validation
 * here grants no trust; native preparation authenticates the exact old subject. */
class RetiredEnrollmentAuthority(witness: ByteArray, publicKey: ByteArray, replacement: ByteArray,
                                 subject: ByteArray, receipt: ByteArray) {
    init {
        require(witness.size == 32 && publicKey.size == 1985 && replacement.size in 1..57794 &&
                subject.size == 96 && receipt.size == 3754) { "invalid retirement authority width" }
    }
    val witness = PublicBytes(witness)
    val publicKey = PublicBytes(publicKey)
    val replacement = PublicBytes(replacement)
    val subject = PublicBytes(subject)
    val receipt = PublicBytes(receipt)
}
class RetiredReportID(bytes: ByteArray) : ContinuityID(bytes)

/** Original public expectation; the bytes alone confer no witness authority. */
class RetiredInventory private constructor(val bytes: PublicBytes) {
    companion object {
        @JvmSynthetic internal fun decode(bytes: ByteArray): RetiredInventory {
            if (bytes.size != 313 || !bytes.copyOfRange(0, 8).contentEquals("QPRCLP01".toByteArray(Charsets.US_ASCII))) {
                throw ContinuityBoundaryFailure("malformed original retirement inventory")
            }
            return RetiredInventory(PublicBytes(bytes))
        }
    }
}
/** Original inventory plus its separately returned keyed report ID. */
class RetiredReportProposal private constructor(val bytes: PublicBytes, val inventory: RetiredInventory,
                                               val report: RetiredReportID) {
    companion object {
        @JvmSynthetic internal fun decode(bytes: ByteArray): RetiredReportProposal {
            if (bytes.size != 353 || !bytes.copyOfRange(0, 8).contentEquals("QPRRPT01".toByteArray(Charsets.US_ASCII)) ||
                bytes.copyOfRange(321, 353).all { it == 0.toByte() }) {
                throw ContinuityBoundaryFailure("malformed original retirement report proposal")
            }
            return RetiredReportProposal(PublicBytes(bytes), RetiredInventory.decode(bytes.copyOfRange(8, 321)),
                RetiredReportID(bytes.copyOfRange(321, 353)))
        }
    }
}
/** Complete private host metadata. Loading it performs no durable host accounting. */
class RetiredDeviceReport private constructor(val report: RetiredReportID, val viewCount: Int,
                                             val canonicalBytes: PublicBytes) {
    companion object {
        @JvmSynthetic internal fun decode(length: Long, views: Int, reserved: Int,
                                           report: ByteArray, bytes: ByteArray): RetiredDeviceReport {
            if (length !in 323L..8388608L || bytes.size.toLong() != length || views !in 1..2 || reserved != 0 ||
                report.size != 32 || report.all { it == 0.toByte() } ||
                (!bytes.copyOfRange(0, 8).contentEquals("QPRDMD01".toByteArray(Charsets.US_ASCII)) &&
                    !bytes.copyOfRange(0, 8).contentEquals("QPRDMD02".toByteArray(Charsets.US_ASCII)))) {
                throw ContinuityBoundaryFailure("malformed complete retirement report")
            }
            return RetiredDeviceReport(RetiredReportID(report), views, PublicBytes(bytes))
        }
    }
}
/** Logical state only; old pages, backups and wrapping keys remain separate. */
enum class RetiredErasureState { RETAINED, ERASED }

/** Restricted original enrollment. No operational device, signer or raw handle.
 * Native failures after admission consume the resource. Close and reopen exact
 * original inputs after unknown outcomes; never reset or select another backup. */
class ContinuityRetiredEnrollment private constructor(private val native: NativeOwner) : AutoCloseable {
    companion object {
        fun prepareOpen(path: String, intent: EnrollmentIntent, authority: RetiredEnrollmentAuthority): ContinuityRetiredEnrollment =
            NativeOwner.prepareRetired(path, intent, authority, ::ContinuityRetiredEnrollment)
        fun open(path: String, intent: EnrollmentIntent, authority: RetiredEnrollmentAuthority): ContinuityRetiredEnrollment {
            val owner = prepareOpen(path, intent, authority)
            try { owner.finishOpen(); return owner } catch (failure: Throwable) {
                try { owner.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
    }
    fun finishOpen() = native.call { ContinuityNative.simple(it, "finish_open") }
    fun cancel() = native.call { ContinuityNative.simple(it, "cancel") }
    override fun close() = native.close()
    fun inventory(): RetiredInventory = native.call { ContinuityNative.retiredInventory(it) }
    fun prepareReport(inventoryReceipt: ByteArray): RetiredReportProposal =
        native.call { ContinuityNative.prepareRetiredReport(it, inventoryReceipt) }
    /** Null is local absence, never proof that the witness did not commit. */
    fun reportProposal(): RetiredReportProposal? = native.call { ContinuityNative.retiredProposal(it, false) }
    fun acknowledgementProposal(): RetiredReportProposal? = native.call { ContinuityNative.retiredProposal(it, true) }
    fun loadReport(inventoryReceipt: ByteArray, reportReceipt: ByteArray): RetiredDeviceReport =
        native.call { ContinuityNative.loadRetiredReport(it, inventoryReceipt, reportReceipt) }
    /** First durably retain the complete report/proposal and account by report ID. */
    fun prepareAcknowledgement(inventoryReceipt: ByteArray, reportReceipt: ByteArray,
                               recordedReport: ByteArray): RetiredReportProposal =
        native.call { ContinuityNative.prepareRetiredAcknowledgement(it, inventoryReceipt, reportReceipt, recordedReport) }
    fun journalState(): RetiredErasureState = native.call { ContinuityNative.retiredState(it, false) }
    fun signerState(): RetiredErasureState = native.call { ContinuityNative.retiredState(it, true) }
    fun eraseJournal(hostAcknowledgement: ByteArray) = native.call {
        ContinuityNative.retiredReceipt(it, hostAcknowledgement, "retired_erase_journal")
    }
    fun prepareSignerErasure(hostAcknowledgement: ByteArray) = native.call {
        ContinuityNative.retiredReceipt(it, hostAcknowledgement, "retired_prepare_signer_erasure")
    }
    /** Consumes the native resource even on success; close the registry handle. */
    fun eraseSigner() = native.call { ContinuityNative.simple(it, "retired_erase_signer") }
}
