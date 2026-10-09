// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.lang.ref.Reference

enum class BootstrapRole(val code: Int) { INITIATOR(1), RESPONDER(2) }
class AccountID(bytes: ByteArray) : ContinuityID(bytes)
class AccountOperationID(bytes: ByteArray) : ContinuityID(bytes)
class AccountAbandonmentID(bytes: ByteArray) : ContinuityID(bytes)

/** Local aggregate state; Committed does not assert remote consumption. */
sealed interface AccountStatus {
    data object Absent : AccountStatus
    data object Reserved : AccountStatus
    data object Committed : AccountStatus
    data object Retired : AccountStatus
    data class Abandoning(val report: AccountAbandonmentID) : AccountStatus
    data class Abandoned(val report: AccountAbandonmentID) : AccountStatus
}
sealed interface AccountDeliveryOutcome {
    data class Consumed(val consumption: Consumption) : AccountDeliveryOutcome
    data object ResolutionPending : AccountDeliveryOutcome
    data object DeliveryUnknown : AccountDeliveryOutcome
    data object HistoryRetired : AccountDeliveryOutcome
    data object ReservationAbandoned : AccountDeliveryOutcome
}
/** Retains a peer wrapper; native admission requires a distinct live child of the selected device. */
data class AccountTarget(val peer: ContinuityOwner, val session: SessionID)
data class AccountDelivery(val device: PublicBytes, val session: SessionID, val message: MessageID,
                           val outcome: AccountDeliveryOutcome, val exchanges: Int)

/** Original Active installation. Live peers retain its native owner, independently
 * of this public wrapper. Explicit device close releases stores and invalidates
 * children. Provisioning and credential renewal are separate operations.
 */
class ContinuityDevice private constructor(private val native: NativeOwner) : AutoCloseable {
    companion object {
        @JvmSynthetic internal fun activated(native: NativeOwner): ContinuityDevice = ContinuityDevice(native)
        fun prepare(path: String, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityDevice =
            NativeOwner.prepare(path, 3, 0, witness, ::ContinuityDevice)
        fun open(path: String, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityDevice {
            val device = prepare(path, witness)
            try { device.finishOpen(); return device } catch (failure: Throwable) {
                try { device.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
    }
    fun finishOpen() = native.call { ContinuityNative.simple(it, "finish_open") }
    fun cancel() = native.call { ContinuityNative.simple(it, "cancel") }
    override fun close() = native.close()
    fun preparePeer(path: String, quality: PrekeyQuality, role: BootstrapRole): ContinuityOwner =
        ContinuityOwner.preparePeer(native, path, quality, role, null)
    fun preparePeerReopen(path: String, quality: PrekeyQuality, role: BootstrapRole, session: SessionID): ContinuityOwner =
        ContinuityOwner.preparePeer(native, path, quality, role, session)
    fun openPeer(path: String, quality: PrekeyQuality, role: BootstrapRole): ContinuityOwner =
        activate(preparePeer(path, quality, role))
    fun reopenPeer(path: String, quality: PrekeyQuality, role: BootstrapRole, session: SessionID): ContinuityOwner =
        activate(preparePeerReopen(path, quality, role, session))
    /** Admit an independently pinned current roster for a known remote account.
     * This cannot update the local account, replace policy or create a session.
     * A checkpoint is current state, not a transaction receipt. After I/O,
     * witness or cancellation failure, reopen the original parent and retry the
     * same target; lack of a returned result never proves no commit. */
    fun admitPeerRoster(roster: ByteArray, pin: AccountPin): RosterCheckpoint {
        require(roster.size in 1..65536) { "peer roster must contain 1..65536 bytes" }
        val copied = roster.clone()
        return native.call { ContinuityNative.admitPeerRoster(it, copied, pin) }
    }
    /** Admit a remote root grant through this original service and exact policy.
     * This cannot renew the local identity or refresh existing peer views. Reopen
     * each original session explicitly; failures retain the original operation.
     */
    fun admitPeerCredentialRenewal(wire: ByteArray, pin: AccountPin, operation: CredentialRenewalID): RosterCheckpoint =
        native.call { ContinuityNative.admitPeerCredentialRenewal(it, wire, pin, operation) }
    private fun activate(peer: ContinuityOwner): ContinuityOwner {
        try { peer.finishOpen(); return peer } catch (failure: Throwable) {
            try { peer.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
            throw failure
        }
    }
    /** Observe and retain with the complete plan before dispatch; no allocation yet. */
    fun nextPublication(): PrekeyPublicationID = native.call { ContinuityNative.nextPublication(it) }
    fun publicationStatus(id: PrekeyPublicationID): PublicationStatus = native.call { ContinuityNative.publicationStatus(it, id) }
    /** Recover the exact original operation after uncertainty; never replace its ID automatically. */
    fun preparePublication(id: PrekeyPublicationID, plan: PublicationPlan): PreparedPublication =
        native.call { ContinuityNative.preparePublication(it, id, plan) }
    fun retirePublication(id: PrekeyPublicationID, artifact: ByteArray): PublicationStatus =
        native.call { ContinuityNative.publicationMutation(it, id, artifact, false) }
    fun abandonPublication(id: PrekeyPublicationID, intent: ByteArray): PublicationStatus =
        native.call { ContinuityNative.publicationMutation(it, id, intent, true) }

    /** Read and retain before sending; this does not reserve or dispatch work. */
    fun nextAccountOperation(): AccountOperationID = native.call { ContinuityNative.nextAccount(it) }
    fun accountStatus(operation: AccountOperationID): AccountStatus = native.call { ContinuityNative.accountStatus(it, operation) }
    /** Reconcile the exact complete input, then deliver one member. Every target
     * stays reachable through return. Retain the same operation after failures;
     * there is no implicit retry, omission or unary fallback.
     */
    fun sendAccountMember(operation: AccountOperationID, account: AccountID, targets: List<AccountTarget>, selected: Int,
                          address: String, plaintext: ByteArray, associatedData: ByteArray): AccountDelivery {
        require(targets.size in 1..32 && selected in targets.indices) { "invalid account target count or selection" }
        val retained = targets.toList()
        try {
            val records = retained.map { target -> target.peer.call { it to target.session } }
            return native.call { ContinuityNative.sendAccountMember(it, operation, account, records, selected,
                address, plaintext, associatedData) }
        } finally {
            Reference.reachabilityFence(retained)
        }
    }
}
