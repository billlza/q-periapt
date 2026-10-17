// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import dev.qperiapt.continuity.ContinuityNative.array
import dev.qperiapt.continuity.ContinuityNative.bytes
import dev.qperiapt.continuity.ContinuityNative.invoke
import dev.qperiapt.continuity.ContinuityNative.offset
import dev.qperiapt.continuity.ContinuityNative.struct
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout.JAVA_BYTE
import java.lang.foreign.ValueLayout.JAVA_INT

internal object PendingWriteRecoveryNative {
    private val info = struct("metadata_length" to JAVA_INT, "signed_request_length" to JAVA_INT,
        "proposal" to array(393), "reserved" to array(3), "binding" to array(32))
    @JvmSynthetic internal fun layout(): Pair<Long, Long> = info.byteSize() to offset(info, "binding")
    @JvmSynthetic internal fun request(handle: Long): PendingWriteRecoveryRequest = Arena.ofConfined().use { arena ->
        val header = arena.allocate(info)
        invoke(arena, "pending_write_request", handle, header)
        val metadataLength = header.get(JAVA_INT, offset(info, "metadata_length"))
        val signedLength = header.get(JAVA_INT, offset(info, "signed_request_length"))
        val reserved = header.asSlice(offset(info, "reserved"), 3).toArray(JAVA_BYTE)
        if (metadataLength !in 569..8388608 || signedLength !in 1..8192 || reserved.any { it != 0.toByte() }) {
            throw ContinuityBoundaryFailure("native pending write bounds differ")
        }
        val binding = header.asSlice(offset(info, "binding"), 32)
        val metadata = arena.allocate(metadataLength.toLong()); val signed = arena.allocate(signedLength.toLong())
        invoke(arena, "copy_pending_write_request", handle, binding, metadata, metadataLength.toLong(), signed, signedLength.toLong())
        PendingWriteRecoveryRequest(header.asSlice(offset(info, "proposal"), 393).toArray(JAVA_BYTE),
            binding.toArray(JAVA_BYTE), metadata.toArray(JAVA_BYTE), signed.toArray(JAVA_BYTE))
    }
    @JvmSynthetic internal fun confirm(handle: Long, approved: ByteArray, metadata: ByteArray) {
        require(approved.size == 393 && metadata.size in 1..8388608) { "invalid pending write input width" }
        Arena.ofConfined().use { arena ->
            invoke(arena, "confirm_pending_write_recovery", handle, arena.bytes(approved), approved.size.toLong(),
                arena.bytes(metadata), metadata.size.toLong())
        }
    }
}
