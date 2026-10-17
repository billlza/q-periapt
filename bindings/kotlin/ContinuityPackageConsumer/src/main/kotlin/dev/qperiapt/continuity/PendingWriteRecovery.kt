// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Complete original request. Retain every field before independent approval.
 * Metadata contains private account/device linkage; no field grants authority. */
class PendingWriteRecoveryRequest internal constructor(proposal: ByteArray, binding: ByteArray,
                                                      metadata: ByteArray, signedRequest: ByteArray) {
    val proposal = PublicBytes(proposal)
    val binding = PublicBytes(binding)
    val metadata = PublicBytes(metadata)
    val signedRequest = PublicBytes(signedRequest)
    init {
        if (binding.size != 32 || signedRequest.size !in 1..8192 || !PendingWriteShape.valid(proposal, metadata)) {
            throw ContinuityBoundaryFailure("malformed complete pending write request")
        }
    }
}
/** Shape validation only; authentication and current witness checks stay native. */
internal object PendingWriteShape {
    fun valid(proposal: ByteArray, metadata: ByteArray): Boolean {
        if (proposal.size != 393 || metadata.size !in 569..8388608 ||
            !proposal.copyOfRange(0, 8).contentEquals("QPWRPL01".toByteArray(Charsets.US_ASCII)) ||
            !metadata.copyOfRange(0, 8).contentEquals("QPWRMD01".toByteArray(Charsets.US_ASCII)) ||
            !proposal.copyOfRange(8, 361).contentEquals(metadata.copyOfRange(8, 361))) return false
        val input = ByteBuffer.wrap(metadata).order(ByteOrder.BIG_ENDIAN)
        input.position(361)
        repeat(2) {
            if (input.remaining() < 8) return false
            val length = input.long
            if (length < 96 || length > input.remaining().toLong()) return false
            input.position(input.position() + length.toInt())
        }
        return !input.hasRemaining()
    }
}
