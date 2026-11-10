// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import dev.qperiapt.continuity.ContinuityNative.array
import dev.qperiapt.continuity.ContinuityNative.bytes
import dev.qperiapt.continuity.ContinuityNative.encodeEnrollmentIntent
import dev.qperiapt.continuity.ContinuityNative.invoke
import dev.qperiapt.continuity.ContinuityNative.offset
import dev.qperiapt.continuity.ContinuityNative.struct
import dev.qperiapt.continuity.ContinuityNative.text
import java.lang.foreign.Arena
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout.ADDRESS
import java.lang.foreign.ValueLayout.JAVA_BYTE
import java.lang.foreign.ValueLayout.JAVA_INT
import java.lang.foreign.ValueLayout.JAVA_LONG

/** Root marshalling shares the existing library lookup, error boundary and enrollment encoding. */
internal object RootReplacementNative {
    private val scope = struct("struct_size" to JAVA_INT, "checkpoint" to AccountAuthorityNative.checkpoint,
        "witness" to array(32), "public_key" to ADDRESS, "public_key_length" to JAVA_LONG)
    private val alternative = struct("struct_size" to JAVA_INT, "original" to ADDRESS, "original_length" to JAVA_LONG,
        "approved" to ADDRESS, "approved_length" to JAVA_LONG, "noncommit" to ADDRESS, "noncommit_length" to JAVA_LONG,
        "receipt" to ADDRESS, "receipt_length" to JAVA_LONG)
    @JvmSynthetic internal fun layouts(): Map<String, Long> = mapOf("scope" to scope.byteSize(),
        "checkpoint_offset" to offset(scope, "checkpoint"), "public_key_offset" to offset(scope, "public_key"),
        "alternative" to alternative.byteSize(), "original_offset" to offset(alternative, "original"),
        "receipt_length_offset" to offset(alternative, "receipt_length"))
    private fun blob(arena: Arena, output: MemorySegment, layout: MemoryLayout, name: String, bytes: ByteArray) {
        output.set(ADDRESS, offset(layout, name), arena.bytes(bytes))
        output.set(JAVA_LONG, offset(layout, name + "_length"), bytes.size.toLong())
    }
    @JvmSynthetic internal fun encodeScope(arena: Arena, value: RootReplacementScope): MemorySegment = arena.allocate(scope).also {
        it.set(JAVA_INT, 0, scope.byteSize().toInt())
        AccountAuthorityNative.encode(it.asSlice(offset(scope, "checkpoint"), AccountAuthorityNative.checkpoint.byteSize()), value.checkpoint)
        it.asSlice(offset(scope, "witness"), 32).copyFrom(MemorySegment.ofArray(value.witness.encoded()))
        blob(arena, it, scope, "public_key", value.publicKey.encoded())
    }
    private fun encodeAlternative(arena: Arena, original: PublicBytes, approved: PublicBytes,
                                  noncommit: PublicBytes, receipt: PublicBytes): MemorySegment = arena.allocate(alternative).also {
        it.set(JAVA_INT, 0, alternative.byteSize().toInt())
        for ((name, value) in listOf("original" to original, "approved" to approved, "noncommit" to noncommit, "receipt" to receipt)) {
            blob(arena, it, alternative, name, value.encoded())
        }
    }
    @JvmSynthetic internal fun encodeTransition(arena: Arena, value: RootReplacementTransition): MemorySegment =
        encodeAlternative(arena, value.original.bytes, value.independentlyApprovedNext.bytes, value.noncommitReceipt, value.freezeReceipt)
    private fun encodeAdoption(arena: Arena, value: RootReplacementAdoption): MemorySegment =
        encodeAlternative(arena, value.original.bytes, value.independentlyApprovedWinner.bytes, value.noncommitReceipt, value.retirementReceipt)
    @JvmSynthetic internal fun begin(registry: Long, device: Long, scope: RootReplacementScope, plan: RootReplacementPlan) = Arena.ofConfined().use { arena ->
        val bytes = plan.bytes.encoded()
        invoke(arena, "root_begin", registry, device, encodeScope(arena, scope), arena.bytes(bytes), bytes.size.toLong())
    }
    @JvmSynthetic internal fun resume(registry: Long, path: String, intent: EnrollmentIntent,
                                      scope: RootReplacementScope, plan: RootReplacementPlan) = Arena.ofConfined().use { arena ->
        val pathBytes = text(path, 4096); val bytes = plan.bytes.encoded()
        invoke(arena, "root_resume", registry, arena.bytes(pathBytes), pathBytes.size.toLong(), encodeEnrollmentIntent(arena, intent),
            encodeScope(arena, scope), arena.bytes(bytes), bytes.size.toLong())
    }
    @JvmSynthetic internal fun activate(registry: Long, enrollment: Long) = Arena.ofConfined().use { arena ->
        invoke(arena, "root_activate_successor", registry, enrollment)
    }
    @JvmSynthetic internal fun state(handle: Long): RootReplacementState = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_INT); invoke(arena, "root_state", handle, output)
        RootReplacementState.decode(output.get(JAVA_INT, 0))
    }
    private fun proposal(arena: Arena, operation: String, vararg args: Any): RootReplacementProposal {
        val output = arena.allocate(65536); val written = arena.allocate(JAVA_LONG)
        invoke(arena, operation, *args, output, 65536L, written)
        val count = written.get(JAVA_LONG, 0)
        if (count !in 8L..65536L) throw ContinuityBoundaryFailure("root proposal output width")
        return RootReplacementProposal.decode(output.asSlice(0, count).toArray(JAVA_BYTE))
    }
    @JvmSynthetic internal fun bindFreeze(handle: Long, receipt: ByteArray): RootReplacementProposal = Arena.ofConfined().use { arena ->
        proposal(arena, "root_bind_freeze", handle, arena.bytes(receipt), receipt.size.toLong())
    }
    @JvmSynthetic internal fun retainRetirement(handle: Long, receipt: ByteArray): AccountAuthorityCheckpoint = Arena.ofConfined().use { arena ->
        val output = arena.allocate(AccountAuthorityNative.checkpoint)
        invoke(arena, "root_retain_retirement", handle, arena.bytes(receipt), receipt.size.toLong(), output)
        AccountAuthorityNative.decode(output.toArray(JAVA_BYTE))
    }
    @JvmSynthetic internal fun retainNoncommit(handle: Long, receipt: ByteArray): RootReplacementState = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_INT)
        invoke(arena, "root_retain_noncommit", handle, arena.bytes(receipt), receipt.size.toLong(), output)
        RootReplacementState.decode(output.get(JAVA_INT, 0))
    }
    @JvmSynthetic internal fun transition(handle: Long, approval: RootReplacementTransition): RootReplacementProposal = Arena.ofConfined().use { arena ->
        proposal(arena, "root_transition", handle, encodeTransition(arena, approval))
    }
    @JvmSynthetic internal fun adopt(handle: Long, approval: RootReplacementAdoption): AccountAuthorityCheckpoint = Arena.ofConfined().use { arena ->
        val output = arena.allocate(AccountAuthorityNative.checkpoint)
        invoke(arena, "root_adopt", handle, encodeAdoption(arena, approval), output)
        AccountAuthorityNative.decode(output.toArray(JAVA_BYTE))
    }
    @JvmSynthetic internal fun resumeTransition(registry: Long, path: String, intent: EnrollmentIntent,
        scope: RootReplacementScope, approval: RootReplacementTransition) = Arena.ofConfined().use { arena ->
        resumeAlternative(arena, "root_resume_transition", registry, path, intent, scope, encodeTransition(arena, approval))
    }
    @JvmSynthetic internal fun resumeAdoption(registry: Long, path: String, intent: EnrollmentIntent,
        scope: RootReplacementScope, approval: RootReplacementAdoption) = Arena.ofConfined().use { arena ->
        resumeAlternative(arena, "root_resume_adoption", registry, path, intent, scope, encodeAdoption(arena, approval))
    }
    private fun resumeAlternative(arena: Arena, operation: String, registry: Long, path: String,
                                   intent: EnrollmentIntent, scope: RootReplacementScope, approval: MemorySegment) {
        val pathBytes = text(path, 4096)
        invoke(arena, operation, registry, arena.bytes(pathBytes), pathBytes.size.toLong(),
            encodeEnrollmentIntent(arena, intent), encodeScope(arena, scope), approval)
    }
}
