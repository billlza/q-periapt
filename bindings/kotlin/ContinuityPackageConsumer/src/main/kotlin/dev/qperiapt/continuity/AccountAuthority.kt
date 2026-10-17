// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

class AccountAuthorityID(bytes: ByteArray) : ContinuityID(bytes)
class ApplicationAccountID(bytes: ByteArray) : ContinuityID(bytes)

/** Original host registry identity and independently supplied witness pin. */
class AccountAuthorityTrust(val identity: AccountAuthorityID, family: ByteArray,
                            witness: ByteArray, publicKey: ByteArray) {
    val family = PublicBytes(family)
    val witness = PublicBytes(witness)
    val publicKey = PublicBytes(publicKey)
    init {
        require(family.size == 32 && witness.size == 32 && publicKey.size == 1985) { "invalid authority input width" }
        require(listOf(identity.encoded(), this.family.encoded(), this.witness.encoded()).all { bytes ->
            bytes.any { it != 0.toByte() }
        }) { "zero authority scope" }
    }
}

/** Expected public mapping; it grants no authority without the original live store. */
data class AccountAuthorityCheckpoint(val application: ApplicationAccountID, val revision: Counter64, val account: AccountID) {
    init {
        require(revision != Counter64.ZERO && revision.bits() != -1L &&
            application.encoded().any { it != 0.toByte() } && account.encoded().any { it != 0.toByte() }) {
            "invalid authority checkpoint"
        }
    }
}

/** Host-owned registry. Keep it reachable until all selected children finish.
 * Use close/use deterministically; Cleaner is a backstop. Children never retain
 * this registry. Close/final cleanup revokes admission, and reopening does not
 * revive previously selected children. Cancel affects this owner's calls only.
 */
class ContinuityAccountAuthority private constructor(private val native: NativeOwner) : AutoCloseable {
    companion object {
        fun provisionWrappingKey(path: String) = AccountAuthorityNative.provisionKey(path)
        fun prepareCreate(path: String, trust: AccountAuthorityTrust): ContinuityAccountAuthority =
            NativeOwner.prepareOwned({ AccountAuthorityNative.prepare(path, trust, true) }, ::ContinuityAccountAuthority)
        fun prepareOpen(path: String, trust: AccountAuthorityTrust): ContinuityAccountAuthority =
            NativeOwner.prepareOwned({ AccountAuthorityNative.prepare(path, trust, false) }, ::ContinuityAccountAuthority)
    }
    fun finishOpen() = native.call { ContinuityNative.simple(it, "finish_open") }
    fun cancel() = native.call { ContinuityNative.simple(it, "cancel") }
    override fun close() = native.close()
    fun checkpoint(application: ApplicationAccountID): AccountAuthorityCheckpoint =
        native.call { AccountAuthorityNative.checkpoint(it, application) }
    fun associate(application: ApplicationAccountID, pin: AccountPin, certificate: ByteArray, roster: ByteArray): AccountAuthorityCheckpoint {
        require(certificate.size in 1..8192 && roster.size in 1..65536) { "invalid authority association width" }
        require(application.encoded().any { it != 0.toByte() }) { "zero application account" }
        val copiedCertificate = certificate.clone(); val copiedRoster = roster.clone()
        return native.call { AccountAuthorityNative.associate(it, application, pin, copiedCertificate, copiedRoster) }
    }
    @JvmSynthetic internal fun select(enrollment: NativeOwner, checkpoint: AccountAuthorityCheckpoint) =
        native.call { registry -> enrollment.call { AccountAuthorityNative.select(it, registry, checkpoint) } }

    /** Convert this original registry to the root controller. Old device aliases
     * lose authority. Keep the registry reachable throughout successor use. */
    fun beginRootReplacement(device: ContinuityDevice, scope: RootReplacementScope, plan: RootReplacementPlan) =
        native.call { registry -> device.call { RootReplacementNative.begin(registry, it, scope, plan) } }
    /** Reopen exact original inputs. A selected alternative requires its matching resume. */
    fun resumeRootReplacement(path: String, intent: EnrollmentIntent, scope: RootReplacementScope, plan: RootReplacementPlan) =
        native.call { RootReplacementNative.resume(it, path, intent, scope, plan) }
    fun rootReplacementState(): RootReplacementState = native.call { RootReplacementNative.state(it) }
    fun bindRootFreeze(receipt: ByteArray): RootReplacementProposal {
        require(receipt.size in 1..131072) { "invalid root freeze receipt width" }
        val copied = receipt.clone()
        return native.call { RootReplacementNative.bindFreeze(it, copied) }
    }
    fun retainRootRetirement(receipt: ByteArray): AccountAuthorityCheckpoint {
        require(receipt.size == 3449) { "invalid root retirement receipt width" }
        val copied = receipt.clone()
        return native.call { RootReplacementNative.retainRetirement(it, copied) }
    }
    /** Permanent noncommit preserves suspension; it does not authorize another target. */
    fun retainRootNoncommit(receipt: ByteArray): RootReplacementState {
        require(receipt.size == 3449) { "invalid root noncommit receipt width" }
        val copied = receipt.clone()
        return native.call { RootReplacementNative.retainNoncommit(it, copied) }
    }
    /** Current successor credentials/policy/witness authority are required. On
     * unknown outcomes close both owners and resume the exact original inputs. */
    fun activateRootSuccessor(enrollment: ContinuityEnrollment): ContinuityDevice =
        native.call { enrollment.activateRootSuccessor(it) }
    fun transitionRoot(approval: RootReplacementTransition): RootReplacementProposal =
        native.call { RootReplacementNative.transition(it, approval) }
    fun adoptRoot(approval: RootReplacementAdoption): AccountAuthorityCheckpoint =
        native.call { RootReplacementNative.adopt(it, approval) }
    fun resumeRootTransition(path: String, intent: EnrollmentIntent, scope: RootReplacementScope,
                             approval: RootReplacementTransition) =
        native.call { RootReplacementNative.resumeTransition(it, path, intent, scope, approval) }
    fun resumeRootAdoption(path: String, intent: EnrollmentIntent, scope: RootReplacementScope,
                           approval: RootReplacementAdoption) =
        native.call { RootReplacementNative.resumeAdoption(it, path, intent, scope, approval) }

    fun retiredInventory(): RetiredInventory = native.call { ContinuityNative.retiredInventory(it) }
    fun prepareRetiredReport(inventoryReceipt: ByteArray): RetiredReportProposal =
        native.call { ContinuityNative.prepareRetiredReport(it, inventoryReceipt) }
    /** Null means local absence, never witness noncommit. */
    fun retiredReportProposal(): RetiredReportProposal? = native.call { ContinuityNative.retiredProposal(it, false) }
    fun retiredAcknowledgementProposal(): RetiredReportProposal? = native.call { ContinuityNative.retiredProposal(it, true) }
    fun loadRetiredReport(inventoryReceipt: ByteArray, reportReceipt: ByteArray): RetiredDeviceReport =
        native.call { ContinuityNative.loadRetiredReport(it, inventoryReceipt, reportReceipt) }
    /** First durably retain the complete report/proposal and account by report ID. */
    fun prepareRetiredAcknowledgement(inventoryReceipt: ByteArray, reportReceipt: ByteArray,
                                      recordedReport: ByteArray): RetiredReportProposal =
        native.call { ContinuityNative.prepareRetiredAcknowledgement(it, inventoryReceipt, reportReceipt, recordedReport) }
    fun retiredJournalState(): RetiredErasureState = native.call { ContinuityNative.retiredState(it, false) }
    fun retiredSignerState(): RetiredErasureState = native.call { ContinuityNative.retiredState(it, true) }
    fun eraseRetiredJournal(hostAcknowledgement: ByteArray) = native.call {
        ContinuityNative.retiredReceipt(it, hostAcknowledgement, "retired_erase_journal")
    }
    fun prepareRetiredSignerErasure(hostAcknowledgement: ByteArray) = native.call {
        ContinuityNative.retiredReceipt(it, hostAcknowledgement, "retired_prepare_signer_erasure")
    }
    /** Erases the historical signer, preserving this controller and its live successor. */
    fun eraseRetiredSigner() = native.call { ContinuityNative.simple(it, "retired_erase_signer") }
}
