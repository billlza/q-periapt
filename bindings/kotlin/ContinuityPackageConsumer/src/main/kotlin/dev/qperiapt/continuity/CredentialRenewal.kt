// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Original caller-retained renewal operation; never replace it after an unknown result. */
class CredentialRenewalID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(bytes.any { it != 0.toByte() }) { "credential renewal operation must be nonzero" } }
}

/** Canonical root statement identity, excluding randomized signature bytes. */
class CredentialRenewalStatementID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(bytes.any { it != 0.toByte() }) { "credential renewal statement must be nonzero" } }
}

/** Immutable exact public proposal for independent witness approval; not authority. */
class CredentialRenewalProposal private constructor(private val value: ByteArray) {
    val operation = CredentialRenewalID(value.copyOfRange(136, 168))
    val statement = CredentialRenewalStatementID(value.copyOfRange(168, 200))
    fun encoded(): ByteArray = value.clone()
    override fun equals(other: Any?): Boolean = other is CredentialRenewalProposal && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
    companion object {
        @JvmSynthetic internal fun decode(bytes: ByteArray): CredentialRenewalProposal {
            val wire = bytes.clone()
            fun check(valid: Boolean) {
                if (!valid) throw ContinuityBoundaryFailure("malformed credential renewal proposal")
            }
            check(wire.size == 296)
            check(wire.copyOfRange(0, 8).contentEquals("QPCRNP01".toByteArray(Charsets.US_ASCII)))
            for (offset in listOf(8, 40, 72, 104, 136, 168, 216, 264)) {
                check(wire.copyOfRange(offset, offset + 32).any { it != 0.toByte() })
            }
            val input = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN)
            val fence = input.getLong(200); val revision = input.getLong(208)
            check(fence != 0L && fence != -1L && input.getLong(248) == fence)
            check(revision != 0L && java.lang.Long.compareUnsigned(revision, -2L) < 0 && input.getLong(256) == revision + 1)
            check(!wire.copyOfRange(216, 248).contentEquals(wire.copyOfRange(264, 296)))
            return CredentialRenewalProposal(wire)
        }
    }
}

/** Immutable target-free expectation for independent cancellation approval.
 * These bytes do not prove Closed or grant operational/cleanup authority.
 */
class CredentialRenewalCancellation private constructor(private val value: ByteArray) {
    val operation = CredentialRenewalID(value.copyOfRange(136, 168))
    val statement = CredentialRenewalStatementID(value.copyOfRange(168, 200))
    fun encoded(): ByteArray = value.clone()
    override fun equals(other: Any?): Boolean = other is CredentialRenewalCancellation && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
    companion object {
        @JvmSynthetic internal fun decode(bytes: ByteArray): CredentialRenewalCancellation {
            val wire = bytes.clone()
            fun check(valid: Boolean) {
                if (!valid) throw ContinuityBoundaryFailure("malformed credential renewal cancellation")
            }
            check(wire.size == 248)
            check(wire.copyOfRange(0, 8).contentEquals("QPCRNC01".toByteArray(Charsets.US_ASCII)))
            for (offset in listOf(8, 40, 72, 104, 136, 168, 216)) {
                check(wire.copyOfRange(offset, offset + 32).any { it != 0.toByte() })
            }
            val input = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN)
            for (offset in listOf(200, 208)) {
                val value = input.getLong(offset)
                check(value != 0L && value != -1L)
            }
            return CredentialRenewalCancellation(wire)
        }
    }
}

/** Historical progress only. Pending does not mean uncommitted; Committed does
 * not grant traffic after expiry, revocation or a later successor.
 */
sealed interface CredentialRenewalStatus {
    data object Absent : CredentialRenewalStatus
    data class Pending(val operation: CredentialRenewalID, val statement: CredentialRenewalStatementID) : CredentialRenewalStatus
    data class Committed(val operation: CredentialRenewalID, val statement: CredentialRenewalStatementID,
                         val target: RosterCheckpoint) : CredentialRenewalStatus
    data class Closed(val operation: CredentialRenewalID, val statement: CredentialRenewalStatementID,
                      val target: RosterCheckpoint) : CredentialRenewalStatus
    data class ExpiredUncommitted(val operation: CredentialRenewalID, val statement: CredentialRenewalStatementID,
                                  val observedHead: RosterCheckpoint, val observedAt: Counter64) : CredentialRenewalStatus {
        init { require(observedAt != Counter64.ZERO) { "expired renewal observation time must be nonzero" } }
    }
}
