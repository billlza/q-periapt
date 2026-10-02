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
