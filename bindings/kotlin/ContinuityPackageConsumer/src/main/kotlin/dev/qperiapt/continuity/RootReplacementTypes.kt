// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

/** Original independent application checkpoint and witness pin. Receipts and
 * proposed successors cannot choose this expectation for the caller. */
class RootReplacementScope(val checkpoint: AccountAuthorityCheckpoint, witness: ByteArray, publicKey: ByteArray) {
    init { require(witness.size == 32 && publicKey.size == 1985) { "invalid root witness input width" } }
    val witness = PublicBytes(witness)
    val publicKey = PublicBytes(publicKey)
    init {
        require(this.witness.encoded().any { it != 0.toByte() }) {
            "invalid root replacement witness scope"
        }
    }
}

/** Independently approved canonical plan. Width/grammar validation grants no
 * authority; native admission verifies it against the retained original owner. */
class RootReplacementPlan(approvedBytes: ByteArray) {
    init { require(approvedBytes.size in 8..131072) { "invalid root plan width" } }
    val bytes = PublicBytes(approvedBytes)
    init { require(rootWire(bytes, 131072, "QPAFPL01")) { "invalid root replacement plan" } }
}

/** Exact bound proposal, or the independently approved committed winner. */
class RootReplacementProposal(approvedBytes: ByteArray) {
    init { require(approvedBytes.size in 8..65536) { "invalid root proposal width" } }
    val bytes = PublicBytes(approvedBytes)
    init { require(rootWire(bytes, 65536, "QPARPL01", "QPARPL02")) { "invalid root replacement proposal" } }
    companion object {
        @JvmSynthetic internal fun decode(bytes: ByteArray): RootReplacementProposal {
            if (bytes.size !in 8..65536 || !rootWire(PublicBytes(bytes), 65536, "QPARPL01", "QPARPL02")) {
                throw ContinuityBoundaryFailure("malformed root replacement proposal")
            }
            return RootReplacementProposal(bytes)
        }
    }
}

private fun rootWire(bytes: PublicBytes, maximum: Int, vararg headers: String): Boolean {
    val encoded = bytes.encoded()
    if (encoded.size !in 8..maximum) return false
    val prefix = encoded.copyOfRange(0, 8)
    return headers.any { prefix.contentEquals(it.toByteArray(Charsets.US_ASCII)) }
}

/** Durable history only. Committed history still requires current successor activation. */
enum class RootReplacementState {
    PREPARING, PENDING, COMMITTED, CLOSED;
    companion object {
        @JvmSynthetic internal fun decode(value: Int): RootReplacementState = when (value) {
            1 -> PREPARING; 2 -> PENDING; 3 -> COMMITTED; 4 -> CLOSED
            else -> throw ContinuityBoundaryFailure("malformed root replacement state")
        }
    }
}

/** Retain these exact inputs across crashes. Noncommit does not authorize a new
 * target: the next plan needs separate independent approval. */
class RootReplacementTransition(val original: RootReplacementPlan, val independentlyApprovedNext: RootReplacementPlan,
                                noncommitReceipt: ByteArray, freezeReceipt: ByteArray) {
    init { require(noncommitReceipt.size == 3449 && freezeReceipt.size in 1..131072) { "invalid root transition receipt width" } }
    val noncommitReceipt = PublicBytes(noncommitReceipt)
    val freezeReceipt = PublicBytes(freezeReceipt)
}

/** Exact independently approved winner and the losing plan's signed noncommit.
 * Historical retirement does not authorize live successor traffic. */
class RootReplacementAdoption(val original: RootReplacementPlan, val independentlyApprovedWinner: RootReplacementProposal,
                              noncommitReceipt: ByteArray, retirementReceipt: ByteArray) {
    init { require(noncommitReceipt.size == 3449 && retirementReceipt.size == 3449) { "invalid root adoption receipt width" } }
    val noncommitReceipt = PublicBytes(noncommitReceipt)
    val retirementReceipt = PublicBytes(retirementReceipt)
}
