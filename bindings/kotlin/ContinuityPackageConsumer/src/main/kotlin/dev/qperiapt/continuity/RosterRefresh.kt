// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity
import java.nio.ByteBuffer
import java.nio.ByteOrder

class RosterRefreshID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(encoded().any { it != 0.toByte() }) { "roster operation must be nonzero" } }
}
/** Explicit current policy selection; SELECTED requires selectContinuedPolicy. No fallback. */
enum class RosterPolicySource(val code: Int) { ORIGINAL(0), SELECTED(1) }
data class RosterRefreshScope(val operation: RosterRefreshID, val previous: RosterCheckpoint,
    val target: RosterCheckpoint, val policy: PolicyCheckpoint, val policyAuthorization: PolicyAuthorizationID?) {
    init { require(target.version > previous.version) { "roster target must advance the original predecessor" } }
}
/** Complete original R expectation. Parsing public bytes grants no approval.
 * Retain the entire descriptor independently of incoming witness replies. */
class RosterRefreshProposal private constructor(private val value: ByteArray, val scope: RosterRefreshScope) {
    fun encoded(): ByteArray = value.clone()
    override fun equals(other: Any?): Boolean = other is RosterRefreshProposal && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
    companion object {
        fun fromRetained(bytes: ByteArray): RosterRefreshProposal {
            val wire = bytes.clone()
            require(wire.size == 417) { "roster proposal must contain 417 bytes" }
            require(wire.copyOfRange(0, 8).contentEquals("QPRWNP01".toByteArray(Charsets.US_ASCII))) { "roster proposal domain differs" }
            fun field(offset: Int) = wire.copyOfRange(offset, offset + 32)
            val b = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN)
            for (offset in listOf(8, 40, 72, 104, 337, 385)) require(field(offset).any { it != 0.toByte() }) { "roster proposal identity is zero" }
            val authorization = when (wire[288].toInt()) {
                0 -> { require(field(289).all { it == 0.toByte() }) { "absent roster policy authorization contains bytes" }; null }
                1 -> PolicyAuthorizationID(field(289))
                else -> throw IllegalArgumentException("roster policy authorization flag differs")
            }
            val scope = RosterRefreshScope(RosterRefreshID(field(136)),
                RosterCheckpoint(Counter64.fromBits(b.getLong(168)), field(176)),
                RosterCheckpoint(Counter64.fromBits(b.getLong(208)), field(216)),
                PolicyCheckpoint(Counter64.fromBits(b.getLong(248)), field(256)), authorization)
            val fence = b.getLong(321); val revision = b.getLong(329)
            require((authorization == null) == field(256).contentEquals(field(104)) &&
                fence != 0L && fence != -1L && b.getLong(369) == fence && revision != 0L &&
                java.lang.Long.compareUnsigned(revision, -2L) < 0 && b.getLong(377) == revision + 1 &&
                !field(337).contentEquals(field(385))) { "roster proposal head or policy transition differs" }
            return RosterRefreshProposal(wire, scope)
        }
    }
}
/** Historical witness state; never an operational lease. */
enum class RosterRefreshState(val code: Int) { PREPARED(1), APPLIED(2), CLOSED(3), ACKNOWLEDGED(4), UNAVAILABLE(5) }
sealed interface RosterRefreshProgress {
    data object Absent : RosterRefreshProgress
    data class Staged(val scope: RosterRefreshScope) : RosterRefreshProgress
    data class Reserved(val proposal: RosterRefreshProposal) : RosterRefreshProgress
    data class Applied(val proposal: RosterRefreshProposal, val retired: Boolean) : RosterRefreshProgress
    data class Closed(val proposal: RosterRefreshProposal, val retired: Boolean) : RosterRefreshProgress
    /** Local abandonment before proposal release; never witness Closed. */
    data class AbandonedBeforePreparation(val scope: RosterRefreshScope) : RosterRefreshProgress
}
internal object RosterRefreshCodec {
    private fun bad(message: String): Nothing = throw ContinuityBoundaryFailure(message)
    private inline fun <T> output(block: () -> T): T = try { block() } catch (failure: IllegalArgumentException) {
        throw ContinuityBoundaryFailure("invalid roster native output: ${failure.message}")
    }
    fun proposal(bytes: ByteArray): RosterRefreshProposal = output { RosterRefreshProposal.fromRetained(bytes) }
    fun preparation(bytes: ByteArray): RosterRefreshProposal? {
        if (bytes.size != 424) bad("roster preparation width differs")
        val present = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()).int
        if (present !in 0..1 || bytes.copyOfRange(421, 424).any { it != 0.toByte() }) bad("roster preparation flags differ")
        val wire = bytes.copyOfRange(4, 421)
        if (present == 0) { if (wire.any { it != 0.toByte() }) bad("absent roster preparation contains bytes"); return null }
        return proposal(wire)
    }
    fun state(code: Int): RosterRefreshState = when(code) {
        1 -> RosterRefreshState.PREPARED
        2 -> RosterRefreshState.APPLIED
        3 -> RosterRefreshState.CLOSED
        4 -> RosterRefreshState.ACKNOWLEDGED
        5 -> RosterRefreshState.UNAVAILABLE
        else -> bad("roster witness state differs")
    }
    fun progress(bytes: ByteArray): RosterRefreshProgress = output {
        if (bytes.size != 624) bad("roster progress width differs")
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()); val phase = b.int; val retired = b.int
        if (phase !in 0..5 || retired !in 0..1 || (phase !in 3..4 && retired != 0) ||
            bytes.copyOfRange(617, 624).any { it != 0.toByte() }) bad("roster progress flags differ")
        if (phase == 0) {
            if (bytes.any { it != 0.toByte() }) bad("absent roster progress contains fields")
            RosterRefreshProgress.Absent
        } else {
            fun field(offset: Int) = bytes.copyOfRange(offset, offset + 32)
            val flag = b.getInt(192); val authorization = field(160)
            if (flag !in 0..1 || b.getInt(196) != 0 || (flag == 0 && authorization.any { it != 0.toByte() })) bad("roster scope flags differ")
            val scope = RosterRefreshScope(RosterRefreshID(field(8)),
                RosterCheckpoint(Counter64.fromBits(b.getLong(40)), field(48)),
                RosterCheckpoint(Counter64.fromBits(b.getLong(80)), field(88)),
                PolicyCheckpoint(Counter64.fromBits(b.getLong(120)), field(128)),
                if (flag == 1) PolicyAuthorizationID(authorization) else null)
            val wire = bytes.copyOfRange(200, 617)
            if (phase == 1 || phase == 5) {
                if (wire.any { it != 0.toByte() }) bad("unprepared roster progress invented a proposal")
                if (phase == 1) RosterRefreshProgress.Staged(scope) else RosterRefreshProgress.AbandonedBeforePreparation(scope)
            } else {
                val proposal = proposal(wire)
                if (proposal.scope != scope) bad("roster progress scope differs from retained proposal")
                when (phase) {
                    2 -> RosterRefreshProgress.Reserved(proposal)
                    3 -> RosterRefreshProgress.Applied(proposal, retired == 1)
                    4 -> RosterRefreshProgress.Closed(proposal, retired == 1)
                    else -> bad("roster progress phase differs")
                }
            }
        }
    }
}
