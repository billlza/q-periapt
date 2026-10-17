// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

/** Identity of one immutable whole-account loss report; never peer-delivery proof. */
data class AccountCleanupHeader(
    val operation: AccountOperationID, val report: AccountAbandonmentID, val memberCount: Long,
)

/** One original member, including every retained rekey and epoch counter. */
data class AccountCleanupMember(
    val device: PublicBytes, val context: PublicBytes, val session: SessionID,
    val generation: Counter64, val role: SessionRole, val confirmedEpoch: Counter64,
    val sendingEpoch: Counter64, val receivingEpoch: Counter64, val pendingEpoch: Counter64?,
    val epochCount: Long,
)

/** Historical original-member state, never send authority. Only ACKNOWLEDGED
 * proves authenticated consumption. HISTORY_RETIRED no longer distinguishes an
 * earlier acknowledgement from accounted unknown delivery. */
enum class AccountMemberState(val code: Int) {
    COMMITTED(1), ACKNOWLEDGED(2), RESOLUTION_PENDING(3), DELIVERY_UNKNOWN(4),
    HISTORY_RETIRED(5), RESERVATION_ABANDONED(6),
}
data class AccountReconciledMember(
    val device: PublicBytes, val session: SessionID, val message: MessageID, val state: AccountMemberState,
)
/** Complete original members in canonical device order. Persist needed results
 * before retiring metadata; this observation is not a delivery acknowledgement. */
class AccountReconciliation internal constructor(val operation: AccountOperationID, members: List<AccountReconciledMember>) {
    val members: List<AccountReconciledMember> = java.util.List.copyOf(members)
}
