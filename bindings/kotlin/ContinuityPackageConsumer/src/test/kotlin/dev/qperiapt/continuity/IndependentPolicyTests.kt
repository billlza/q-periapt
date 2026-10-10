// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class IndependentPolicyTests {
    private fun proposal(): ByteArray = ByteArray(296) { 1 }.also {
        "QPPWNP01".toByteArray(Charsets.US_ASCII).copyInto(it)
        ByteBuffer.wrap(it).order(ByteOrder.BIG_ENDIAN).apply {
            putLong(200, -2); putLong(248, -2); putLong(208, -3); putLong(256, -2)
        }
        it[295] = 2
    }
    @Test fun independentDescriptorOwnsAllBytesAndRejectsOtherDomains() {
        val bytes = proposal(); val original = bytes.clone(); val parsed = IndependentPolicyProposal.fromRetained(bytes)
        bytes.fill(0); parsed.encoded().fill(0)
        assertContentEquals(original, parsed.encoded())
        assertEquals(PolicyRenewalID(ByteArray(32) { 1 }), parsed.operation)
        assertEquals(PolicyRenewalStatementID(ByteArray(32) { 1 }), parsed.statement)
        val invalid = mutableListOf(original.copyOf(295), original.copyOf(297))
        for (tag in listOf("QPCRNP01", "QPCRNP02", "QPPWNP02")) invalid.add(original.clone().also { tag.toByteArray(Charsets.US_ASCII).copyInto(it) })
        for (offset in listOf(8, 40, 72, 104, 136, 168, 216, 264)) invalid.add(original.clone().also { it.fill(0, offset, offset + 32) })
        for (offset in listOf(200, 208, 248, 256)) invalid.add(original.clone().also { ByteBuffer.wrap(it).order(ByteOrder.BIG_ENDIAN).putLong(offset, -1) })
        invalid.add(original.clone().also { original.copyInto(it, 264, 216, 248) })
        for (wire in invalid) {
            assertFailsWith<IllegalArgumentException> { IndependentPolicyProposal.fromRetained(wire) }
            assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.proposal(wire) }
        }
    }
    @Test fun preparationDistinguishesCanonicalAbsenceAndRejectsDirtyFlags() {
        val bytes = ByteArray(304); val b = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder())
        assertNull(IndependentPolicyCodec.preparation(bytes))
        proposal().copyInto(bytes, 8)
        assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.preparation(bytes) }
        b.putInt(0, 1); assertContentEquals(proposal(), IndependentPolicyCodec.preparation(bytes)?.encoded())
        b.putInt(4, 1); assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.preparation(bytes) }; b.putInt(4, 0)
        for (flag in listOf(2, 257, -1)) { b.putInt(0, flag); assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.preparation(bytes) } }
        for (size in listOf(303, 305)) assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.preparation(ByteArray(size)) }
    }
    @Test fun progressKeepsEveryTerminalAndRetirementStateDistinct() {
        val bytes = ByteArray(344); val b = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder())
        assertEquals(IndependentPolicyProgress.Absent, IndependentPolicyCodec.progress(bytes))
        val parsed = IndependentPolicyProposal.fromRetained(proposal()); parsed.encoded().copyInto(bytes, 8)
        val target = PolicyCheckpoint(Counter64.parse("18446744073709551614"), ByteArray(32) { 9 })
        b.putLong(304, -2); target.digest.encoded().copyInto(bytes, 312)
        assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.progress(bytes) }
        b.putInt(0, 1); assertEquals(IndependentPolicyProgress.Reserved(parsed, target), IndependentPolicyCodec.progress(bytes))
        b.putInt(4, 1); assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.progress(bytes) }
        for (retired in listOf(0, 1)) {
            b.putInt(4, retired); b.putInt(0, 2)
            assertEquals(IndependentPolicyProgress.Applied(parsed, target, retired == 1), IndependentPolicyCodec.progress(bytes))
            b.putInt(0, 3); assertEquals(IndependentPolicyProgress.Closed(parsed, target, retired == 1), IndependentPolicyCodec.progress(bytes))
        }
        for (phase in listOf(4, 256, -1)) { b.putInt(0, phase); assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.progress(bytes) } }
        b.putInt(0, 2); b.putInt(4, 2); assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.progress(bytes) }
        b.putInt(4, 0); b.putLong(304, 0); assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.progress(bytes) }
        for (size in listOf(343, 345)) assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.progress(ByteArray(size)) }
        for (code in listOf(0, 6, 257, -1)) assertFailsWith<ContinuityBoundaryFailure> { IndependentPolicyCodec.state(code) }
        assertEquals(IndependentPolicyState.entries.toList(), (1..5).map(IndependentPolicyCodec::state))
    }
    @Test fun witnessCallsRespectPreparedCancelledAndClosedOwnerBoundaries() {
        val point = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        val root = ByteArray(1952) { 1 } + point.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val intent = EnrollmentIntent(root, ByteArray(16) { 2 }, Counter64.of(1), ByteArray(32) { 3 }, Counter64.ZERO, Counter64.parse("18446744073709551614"))
        ContinuityEnrollment.prepareResume("/unused", intent).use { owner ->
            val parsed = IndependentPolicyProposal.fromRetained(proposal())
            val calls = listOf<() -> Unit>(
                { owner.witnessedPolicyRenewalRequest(parsed.operation) }, { owner.recoverWitnessedPolicyRenewalPreparation() },
                { owner.witnessedPolicyRenewalProgress() }, { owner.commitWitnessedPolicyRenewal(parsed) },
                { owner.reconcileWitnessedPolicyRenewal(parsed) }, { owner.closeWitnessedPolicyRenewal(parsed) })
            for (call in calls) assertEquals(6, assertFailsWith<ContinuityFailure>(block = call).code)
            owner.cancel()
            // Kind admission precedes cancellation; finishOpen is the only
            // operation that consumes the prepared construction request.
            for (call in calls) assertEquals(6, assertFailsWith<ContinuityFailure>(block = call).code)
            assertEquals(302, assertFailsWith<ContinuityFailure> { owner.finishOpen() }.code)
            for (call in calls) assertEquals(2, assertFailsWith<ContinuityFailure>(block = call).code)
        }
    }
}
