// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import dev.qperiapt.continuity.ContinuityNative.array
import dev.qperiapt.continuity.ContinuityNative.bytes
import dev.qperiapt.continuity.ContinuityNative.encodeAccountPin
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

/** Registry marshalling shares the one library lookup and strict error decoder. */
internal object AccountAuthorityNative {
    private val options = struct("struct_size" to JAVA_INT, "identity" to array(32),
        "family" to array(32), "witness" to array(32), "public_key" to ADDRESS, "public_key_length" to JAVA_LONG)
    private val checkpoint = struct("application" to array(32), "revision" to JAVA_LONG, "account" to array(32))
    private val association = struct("struct_size" to JAVA_INT, "application" to array(32), "pin" to ADDRESS,
        "certificate" to ADDRESS, "certificate_length" to JAVA_LONG, "roster" to ADDRESS, "roster_length" to JAVA_LONG)
    private val selection = struct("struct_size" to JAVA_INT, "registry" to JAVA_LONG, "checkpoint" to checkpoint)
    private fun copy(target: MemorySegment, layout: MemoryLayout, name: String, bytes: ByteArray) =
        target.asSlice(offset(layout, name), bytes.size.toLong()).copyFrom(MemorySegment.ofArray(bytes))
    private fun encode(target: MemorySegment, value: AccountAuthorityCheckpoint) {
        copy(target, checkpoint, "application", value.application.encoded())
        target.set(JAVA_LONG, offset(checkpoint, "revision"), value.revision.bits())
        copy(target, checkpoint, "account", value.account.encoded())
    }
    @JvmSynthetic internal fun decode(bytes: ByteArray): AccountAuthorityCheckpoint {
        if (bytes.size != checkpoint.byteSize().toInt()) throw ContinuityBoundaryFailure("authority checkpoint width")
        return Arena.ofConfined().use { arena ->
            val input = arena.allocate(checkpoint).also { it.copyFrom(MemorySegment.ofArray(bytes)) }
            val application = input.asSlice(offset(checkpoint, "application"), 32).toArray(JAVA_BYTE)
            val account = input.asSlice(offset(checkpoint, "account"), 32).toArray(JAVA_BYTE)
            val revision = input.get(JAVA_LONG, offset(checkpoint, "revision"))
            if (revision == 0L || revision == -1L || application.all { it == 0.toByte() } || account.all { it == 0.toByte() }) {
                throw ContinuityBoundaryFailure("native authority checkpoint is malformed")
            }
            AccountAuthorityCheckpoint(ApplicationAccountID(application), Counter64.fromBits(revision), AccountID(account))
        }
    }
    @JvmSynthetic internal fun layouts(): Map<String, Long> = mapOf(
        "options" to options.byteSize(), "public_key_offset" to offset(options, "public_key"),
        "checkpoint" to checkpoint.byteSize(), "revision_offset" to offset(checkpoint, "revision"),
        "association" to association.byteSize(), "selection" to selection.byteSize(),
        "selected_checkpoint_offset" to offset(selection, "checkpoint"))
    @JvmSynthetic internal fun provisionKey(path: String) = Arena.ofConfined().use { arena ->
        val pathBytes = text(path, 4096)
        invoke(arena, "authority_key", arena.bytes(pathBytes), pathBytes.size.toLong())
    }
    @JvmSynthetic internal fun prepare(path: String, trust: AccountAuthorityTrust, create: Boolean): Long = Arena.ofConfined().use { arena ->
        val pathBytes = text(path, 4096); val input = arena.allocate(options)
        input.set(JAVA_INT, 0, options.byteSize().toInt())
        copy(input, options, "identity", trust.identity.encoded()); copy(input, options, "family", trust.family.encoded())
        copy(input, options, "witness", trust.witness.encoded())
        val key = trust.publicKey.encoded()
        input.set(ADDRESS, offset(options, "public_key"), arena.bytes(key))
        input.set(JAVA_LONG, offset(options, "public_key_length"), key.size.toLong())
        val output = arena.allocate(JAVA_LONG)
        invoke(arena, if (create) "authority_create" else "authority_open", arena.bytes(pathBytes), pathBytes.size.toLong(), input, output)
        output.get(JAVA_LONG, 0).also { if (it == 0L) throw ContinuityBoundaryFailure("native authority handle is zero") }
    }
    @JvmSynthetic internal fun checkpoint(handle: Long, application: ApplicationAccountID): AccountAuthorityCheckpoint = Arena.ofConfined().use { arena ->
        val output = arena.allocate(checkpoint)
        invoke(arena, "authority_checkpoint", handle, arena.bytes(application.encoded()), output)
        decode(output.toArray(JAVA_BYTE)).also {
            if (it.application != application) throw ContinuityBoundaryFailure("native authority application differs")
        }
    }
    @JvmSynthetic internal fun associate(handle: Long, application: ApplicationAccountID, pin: AccountPin,
                                        certificate: ByteArray, roster: ByteArray): AccountAuthorityCheckpoint = Arena.ofConfined().use { arena ->
        val input = arena.allocate(association); input.set(JAVA_INT, 0, association.byteSize().toInt())
        copy(input, association, "application", application.encoded())
        input.set(ADDRESS, offset(association, "pin"), encodeAccountPin(arena, pin))
        input.set(ADDRESS, offset(association, "certificate"), arena.bytes(certificate))
        input.set(JAVA_LONG, offset(association, "certificate_length"), certificate.size.toLong())
        input.set(ADDRESS, offset(association, "roster"), arena.bytes(roster))
        input.set(JAVA_LONG, offset(association, "roster_length"), roster.size.toLong())
        val output = arena.allocate(checkpoint)
        invoke(arena, "authority_associate", handle, input, output)
        decode(output.toArray(JAVA_BYTE)).also {
            if (it.application != application || it.account != pin.account) throw ContinuityBoundaryFailure("native authority association differs")
        }
    }
    @JvmSynthetic internal fun select(enrollment: Long, registry: Long, expected: AccountAuthorityCheckpoint) = Arena.ofConfined().use { arena ->
        val input = arena.allocate(selection); input.set(JAVA_INT, 0, selection.byteSize().toInt())
        input.set(JAVA_LONG, offset(selection, "registry"), registry)
        encode(input.asSlice(offset(selection, "checkpoint"), checkpoint.byteSize()), expected)
        invoke(arena, "authority_select_enrollment", enrollment, input)
    }
}
