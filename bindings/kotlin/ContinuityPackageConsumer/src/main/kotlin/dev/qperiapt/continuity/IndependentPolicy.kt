// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Complete original policy-only expectation. Parsing grants no approval or
 * current permission. Retain all bytes; an untrusted received descriptor must
 * not replace the original independently retained expectation. */
class IndependentPolicyProposal private constructor(private val value: ByteArray) {
    val operation = PolicyRenewalID(value.copyOfRange(136, 168))
    val statement = PolicyRenewalStatementID(value.copyOfRange(168, 200))
    fun encoded(): ByteArray = value.clone()
    override fun equals(other: Any?): Boolean = other is IndependentPolicyProposal && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()

    companion object {
        fun fromRetained(bytes: ByteArray): IndependentPolicyProposal {
            val wire = bytes.clone()
            require(wire.size == 296) { "independent policy proposal must contain 296 bytes" }
            require(wire.copyOfRange(0, 8).contentEquals("QPPWNP01".toByteArray(Charsets.US_ASCII))) { "independent policy proposal domain differs" }
            for (offset in listOf(8, 40, 72, 104, 136, 168, 216, 264)) {
                require(wire.copyOfRange(offset, offset + 32).any { it != 0.toByte() }) { "independent policy proposal identity is zero" }
            }
            val b = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN)
            val fence = b.getLong(200); val revision = b.getLong(208)
            require(fence != 0L && fence != -1L && b.getLong(248) == fence &&
                revision != 0L && java.lang.Long.compareUnsigned(revision, -2L) < 0 && b.getLong(256) == revision + 1 &&
                !wire.copyOfRange(216, 248).contentEquals(wire.copyOfRange(264, 296))) { "independent policy proposal head transition differs" }
            return IndependentPolicyProposal(wire)
        }
    }
}

/** Exact witness history; no case grants a device or traffic lease. */
enum class IndependentPolicyState(val code: Int) { PREPARED(1), APPLIED(2), CLOSED(3), ACKNOWLEDGED(4), UNAVAILABLE(5) }

/** Local original-operation history. Absence never proves non-commit;
 * retirement describes durable terminal cleanup, not current authority. */
sealed interface IndependentPolicyProgress {
    data object Absent : IndependentPolicyProgress
    data class Reserved(val proposal: IndependentPolicyProposal, val target: PolicyCheckpoint) : IndependentPolicyProgress
    data class Applied(val proposal: IndependentPolicyProposal, val target: PolicyCheckpoint, val retired: Boolean) : IndependentPolicyProgress
    data class Closed(val proposal: IndependentPolicyProposal, val target: PolicyCheckpoint, val retired: Boolean) : IndependentPolicyProgress
}

internal object IndependentPolicyCodec {
    private fun bad(message: String): Nothing = throw ContinuityBoundaryFailure(message)
    private inline fun <T> output(block: () -> T): T = try { block() } catch (failure: IllegalArgumentException) {
        throw ContinuityBoundaryFailure("invalid independent policy native output: ${failure.message}")
    }
    fun proposal(bytes: ByteArray): IndependentPolicyProposal = output { IndependentPolicyProposal.fromRetained(bytes) }
    fun preparation(bytes: ByteArray): IndependentPolicyProposal? {
        if (bytes.size != 304) bad("independent policy preparation width differs")
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder())
        val present = b.int; val reserved = b.int; val wire = bytes.copyOfRange(8, 304)
        if (present !in 0..1 || reserved != 0) bad("independent policy preparation flags differ")
        if (present == 0) {
            if (wire.any { it != 0.toByte() }) bad("absent independent policy preparation contains a proposal")
            return null
        }
        return proposal(wire)
    }
    fun state(code: Int): IndependentPolicyState = when (code) {
        1 -> IndependentPolicyState.PREPARED
        2 -> IndependentPolicyState.APPLIED
        3 -> IndependentPolicyState.CLOSED
        4 -> IndependentPolicyState.ACKNOWLEDGED
        5 -> IndependentPolicyState.UNAVAILABLE
        else -> bad("independent policy witness state differs")
    }
    fun progress(bytes: ByteArray): IndependentPolicyProgress = output {
        if (bytes.size != 344) bad("independent policy progress width differs")
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()); val phase = b.int; val retired = b.int
        if (phase !in 0..3 || retired !in 0..1 || (phase < 2 && retired != 0)) bad("independent policy progress flags differ")
        if (phase == 0) {
            if (bytes.any { it != 0.toByte() }) bad("absent independent policy progress contains fields")
            IndependentPolicyProgress.Absent
        } else {
            val proposal = proposal(bytes.copyOfRange(8, 304))
            val target = PolicyCheckpoint(Counter64.fromBits(b.getLong(304)), bytes.copyOfRange(312, 344))
            when (phase) {
                1 -> IndependentPolicyProgress.Reserved(proposal, target)
                2 -> IndependentPolicyProgress.Applied(proposal, target, retired == 1)
                3 -> IndependentPolicyProgress.Closed(proposal, target, retired == 1)
                else -> bad("independent policy progress phase differs")
            }
        }
    }
}
