// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class RosterRefreshTests {
    private fun proposal(selected: Boolean = false): ByteArray = ByteArray(417) { 1 }.also {
        "QPRWNP01".toByteArray(Charsets.US_ASCII).copyInto(it)
        ByteBuffer.wrap(it).order(ByteOrder.BIG_ENDIAN).apply {
            putLong(168, -3); putLong(208, -2); putLong(248, 3)
            putLong(321, -2); putLong(369, -2); putLong(329, -3); putLong(377, -2)
        }
        it[416] = 2; it[288] = if (selected) 1 else 0
        if (selected) it[256] = 2 else it.fill(0, 289, 321)
    }
    private fun progress(parsed: RosterRefreshProposal): ByteArray = ByteArray(624).also {
        val scope = parsed.scope; val b = ByteBuffer.wrap(it).order(ByteOrder.nativeOrder())
        scope.operation.encoded().copyInto(it, 8)
        b.putLong(40, scope.previous.version.bits()); scope.previous.digest.encoded().copyInto(it, 48)
        b.putLong(80, scope.target.version.bits()); scope.target.digest.encoded().copyInto(it, 88)
        b.putLong(120, scope.policy.version.bits()); scope.policy.digest.encoded().copyInto(it, 128)
        scope.policyAuthorization?.let { value -> b.putInt(192, 1); value.encoded().copyInto(it, 160) }
        parsed.encoded().copyInto(it, 200)
    }
    @Test fun retainedRosterProposalOwnsExactScopeAndRejectsOtherDomains() {
        for (selected in listOf(false, true)) {
            val bytes = proposal(selected); val saved = bytes.clone(); val parsed = RosterRefreshProposal.fromRetained(bytes)
            bytes.fill(0); parsed.encoded().fill(0)
            assertContentEquals(saved, parsed.encoded()); assertEquals(Counter64.fromBits(-2), parsed.scope.target.version)
            assertEquals(selected, parsed.scope.policyAuthorization != null)
            assertEquals(parsed, RosterRefreshCodec.proposal(saved))
        }
        val original = proposal(); val invalid = mutableListOf(original.copyOf(416), original.copyOf(418))
        for (tag in listOf("QPPWNP01", "QPCRNP01", "QPRWNP02")) invalid.add(original.clone().also { tag.toByteArray(Charsets.US_ASCII).copyInto(it) })
        for (offset in listOf(8, 40, 72, 104, 136, 176, 216, 256, 337, 385)) invalid.add(original.clone().also { it.fill(0, offset, offset + 32) })
        for (offset in listOf(168, 208, 248, 321, 329, 369, 377)) invalid.add(original.clone().also { ByteBuffer.wrap(it).order(ByteOrder.BIG_ENDIAN).putLong(offset, -1) })
        for (offset in listOf(288, 289, 256)) invalid.add(original.clone().also { it[offset] = 2 })
        invalid.add(original.clone().also { original.copyInto(it, 385, 337, 369) })
        invalid.add(original.clone().also { original.copyInto(it, 208, 168, 176) })
        for (wire in invalid) {
            assertFailsWith<IllegalArgumentException> { RosterRefreshProposal.fromRetained(wire) }
            assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.proposal(wire) }
        }
    }
    @Test fun rosterPreparationChecksCanonicalAbsenceAndABI() {
        val layouts = ContinuityNative.layouts()
        assertEquals(417L to 1L, layouts["roster_proposal"]); assertEquals(192L to 8L, layouts["roster_scope"])
        assertEquals(424L to 4L, layouts["roster_preparation"]); assertEquals(624L to 8L, layouts["roster_progress"])
        assertEquals(40L to 8L, layouts["roster_target"])
        val bytes = ByteArray(424); val b = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder())
        assertNull(RosterRefreshCodec.preparation(bytes)); proposal().copyInto(bytes, 4)
        assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.preparation(bytes) }
        b.putInt(0, 1); assertContentEquals(proposal(), RosterRefreshCodec.preparation(bytes)?.encoded())
        for (flag in listOf(2, 257, -1)) { b.putInt(0, flag); assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.preparation(bytes) } }
        b.putInt(0, 1); bytes[423] = 1; assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.preparation(bytes) }
    }
    @Test fun rosterProgressPreservesAllSixStatesAndChecksProposalScope() {
        assertEquals(RosterRefreshProgress.Absent, RosterRefreshCodec.progress(ByteArray(624)))
        val parsed = RosterRefreshProposal.fromRetained(proposal(true))
        assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.progress(progress(parsed)) }
        for (phase in listOf(1, 5)) {
            val bytes = progress(parsed); val b = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()); b.putInt(0, phase)
            assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.progress(bytes) }; bytes.fill(0, 200, 617)
            assertEquals(if (phase == 1) RosterRefreshProgress.Staged(parsed.scope) else RosterRefreshProgress.AbandonedBeforePreparation(parsed.scope), RosterRefreshCodec.progress(bytes))
            b.putInt(4, 1); assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.progress(bytes) }
        }
        val bytes = progress(parsed); val b = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()); b.putInt(0, 2)
        assertEquals(RosterRefreshProgress.Reserved(parsed), RosterRefreshCodec.progress(bytes))
        b.putInt(4, 1); assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.progress(bytes) }
        for (retired in listOf(0, 1)) {
            b.putInt(4, retired); b.putInt(0, 3); assertEquals(RosterRefreshProgress.Applied(parsed, retired == 1), RosterRefreshCodec.progress(bytes))
            b.putInt(0, 4); assertEquals(RosterRefreshProgress.Closed(parsed, retired == 1), RosterRefreshCodec.progress(bytes))
        }
        b.putLong(120, 4); assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.progress(bytes) }; b.putLong(120, 3)
        for (offset in listOf(196, 623)) { bytes[offset] = 1; assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.progress(bytes) }; bytes[offset] = 0 }
        for (code in listOf(0, 6, 257, -1)) assertFailsWith<ContinuityBoundaryFailure> { RosterRefreshCodec.state(code) }
        assertEquals(RosterRefreshState.entries.toList(), (1..5).map(RosterRefreshCodec::state))
    }
    @Test fun rosterCallsRespectPreparedCancelledAndClosedOwners() {
        val point = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        val root = ByteArray(1952) { 1 } + point.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val intent = EnrollmentIntent(root, ByteArray(16) { 2 }, Counter64.of(1), ByteArray(32) { 3 }, Counter64.ZERO, Counter64.parse("18446744073709551614"))
        ContinuityEnrollment.prepareResume("/unused", intent).use { owner ->
            val parsed = RosterRefreshProposal.fromRetained(proposal())
            // Canonical account digest of this fixed public-key fixture (identity.rs).
            val account = "65e7d5f0837dbd59929a47ddbc2e93a5cacebdd11efe59129e77dea8afd54d4a".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val pin = AccountPin(AccountID(account), root, ByteArray(32) { 3 }, parsed.scope.target)
            val calls = listOf<() -> Unit>(
                { owner.prepareWitnessedRosterRefresh(parsed.scope.operation, RosterPolicySource.ORIGINAL, byteArrayOf(1), byteArrayOf(1), pin) },
                { owner.recoverWitnessedRosterRefreshPreparation() }, { owner.witnessedRosterRefreshProgress() },
                { owner.abandonUnpreparedRosterRefresh(parsed.scope.operation) },
                { owner.commitWitnessedRosterRefresh(parsed, RosterPolicySource.ORIGINAL) },
                { owner.reconcileWitnessedRosterRefresh(parsed) }, { owner.closeWitnessedRosterRefresh(parsed) })
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
