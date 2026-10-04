// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

/** Original caller-retained renewal operation; never replace it after an unknown result. */
class CredentialRenewalID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(bytes.any { it != 0.toByte() }) { "credential renewal operation must be nonzero" } }
}

/** Canonical root statement identity, excluding randomized signature bytes. */
class CredentialRenewalStatementID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(bytes.any { it != 0.toByte() }) { "credential renewal statement must be nonzero" } }
}

/** Historical progress only. Pending does not mean uncommitted; Committed does
 * not grant traffic after expiry, revocation or a later successor.
 */
sealed interface CredentialRenewalStatus {
    data object Absent : CredentialRenewalStatus
    data class Pending(val operation: CredentialRenewalID, val statement: CredentialRenewalStatementID) : CredentialRenewalStatus
    data class Committed(val operation: CredentialRenewalID, val statement: CredentialRenewalStatementID,
                         val target: RosterCheckpoint) : CredentialRenewalStatus
    data class ExpiredUncommitted(val operation: CredentialRenewalID, val statement: CredentialRenewalStatementID,
                                  val observedHead: RosterCheckpoint, val observedAt: Counter64) : CredentialRenewalStatus {
        init { require(observedAt != Counter64.ZERO) { "expired renewal observation time must be nonzero" } }
    }
}
