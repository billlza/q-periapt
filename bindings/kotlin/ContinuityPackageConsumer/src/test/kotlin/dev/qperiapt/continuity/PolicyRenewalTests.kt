// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class PolicyRenewalTests {
    private fun bytes(value: Int = 1) = ByteArray(32) { value.toByte() }
    private fun scope(high: Boolean = false) = PolicyRenewalScope(PolicyRenewalID(bytes()), JournalID(bytes(2)), bytes(3), bytes(4), bytes(5),
        RosterCheckpoint(if (high) Counter64.parse("18446744073709551614") else Counter64.of(2), bytes(6)),
        PolicyCheckpoint(Counter64.of(1), bytes(7)), PolicyCheckpoint(Counter64.of(1), bytes(7)), null)
    private fun request() = PolicyRenewalRequest(scope(), AccountID(bytes(8)), RosterCheckpoint(Counter64.of(1), bytes(9)),
        byteArrayOf(1,2), byteArrayOf(3,4), byteArrayOf(5,6), byteArrayOf(7,8))
    @Test fun nativeLayoutsAndOffsetsMatchTheCanonicalCRecord() {
        val layouts = ContinuityNative.layouts()
        assertEquals(320L to 8L, layouts["policy_renewal_scope"])
        assertEquals(33176L to 8L, layouts["policy_renewal_request"])
        assertEquals(160L to 8L, layouts["policy_renewal_status"])
        assertEquals(mapOf("scope_current_roster" to 160L, "scope_previous_authorization" to 280L,
            "scope_reserved" to 316L, "request_original_checkpoint" to 352L, "request_original_credential" to 392L,
            "status_target" to 72L, "status_observed_at" to 152L), ContinuityNative.policyRenewalOffsets())
    }
    @Test fun retainedRequestOwnsEveryByteAndRoundTripsUnsignedFields() {
        val original = request(); val encoded = PolicyRenewalCodec.encodeRequest(original)
        val decoded = PolicyRenewalCodec.decodeRequest(encoded)
        assertContentEquals(encoded, PolicyRenewalCodec.encodeRequest(decoded))
        encoded.fill(0); decoded.originalCredential.encoded().fill(0)
        assertContentEquals(byteArrayOf(1,2), decoded.originalCredential.encoded())
        val high = PolicyRenewalRequest(scope(true), original.account, original.originalRosterCheckpoint,
            ByteArray(8192) { 9 }, byteArrayOf(3), byteArrayOf(4), byteArrayOf(5))
        val result = PolicyRenewalCodec.decodeRequest(PolicyRenewalCodec.encodeRequest(high))
        assertEquals("18446744073709551614", result.scope.currentRoster.version.toString())
        assertEquals(8192, result.originalCredential.encoded().size)
    }
    @Test fun scopesRejectContradictoryPredecessorsAndNoncanonicalOptions() {
        val s = scope()
        assertFailsWith<IllegalArgumentException> { PolicyRenewalScope(s.operation, s.journal, s.originalOwner.encoded(),
            s.originalCredential.encoded(), s.currentCredential.encoded(), s.currentRoster, s.originalPolicy,
            PolicyCheckpoint(Counter64.of(2), bytes()), null) }
        for (offset in listOf(312, 316)) {
            val wire = PolicyRenewalCodec.encodeRequest(request())
            ByteBuffer.wrap(wire).order(ByteOrder.nativeOrder()).putInt(offset, 1)
            assertFailsWith<ContinuityBoundaryFailure> { PolicyRenewalCodec.decodeRequest(wire) }
        }
        val zero = PolicyRenewalCodec.encodeRequest(request()); zero.fill(0, 32, 64)
        assertFailsWith<ContinuityBoundaryFailure> { PolicyRenewalCodec.decodeRequest(zero) }
        assertFailsWith<IllegalArgumentException> { PolicyRenewalID(bytes(0)) }
        assertFailsWith<IllegalArgumentException> { PolicyRenewalStatementID(byteArrayOf(1)) }
    }
    @Test fun requestRejectsDirtyTailEmptyFieldsAndImpossibleOriginalHead() {
        val tail = PolicyRenewalCodec.encodeRequest(request()); tail[392 + 4 + 8191] = 1
        assertFailsWith<ContinuityBoundaryFailure> { PolicyRenewalCodec.decodeRequest(tail) }
        val empty = PolicyRenewalCodec.encodeRequest(request()); ByteBuffer.wrap(empty).order(ByteOrder.nativeOrder()).putInt(392, 0)
        assertFailsWith<ContinuityBoundaryFailure> { PolicyRenewalCodec.decodeRequest(empty) }
        val head = PolicyRenewalCodec.encodeRequest(request()); ByteBuffer.wrap(head).order(ByteOrder.nativeOrder()).putLong(352, 3)
        assertFailsWith<ContinuityBoundaryFailure> { PolicyRenewalCodec.decodeRequest(head) }
        assertFailsWith<ContinuityBoundaryFailure> { PolicyRenewalCodec.decodeRequest(ByteArray(33175)) }
    }
    private fun status(phase: Int): ByteArray = ByteBuffer.allocate(160).order(ByteOrder.nativeOrder()).apply {
        putInt(phase); putInt(0); put(bytes(1)); put(bytes(2)); putLong(-2); put(bytes(3))
    }.array()
    @Test fun allProgressStatesRemainDistinctIncludingBothAbandonmentReasons() {
        assertEquals(PolicyRenewalStatus.Absent, PolicyRenewalCodec.decodeStatus(ByteArray(160)))
        assertIs<PolicyRenewalStatus.Pending>(PolicyRenewalCodec.decodeStatus(status(1)))
        assertIs<PolicyRenewalStatus.Committed>(PolicyRenewalCodec.decodeStatus(status(2)))
        for ((code, expected) in listOf(1 to PolicyRenewalAbandonment.EXPIRED, 2 to PolicyRenewalAbandonment.ROSTER_ADVANCED)) {
            val wire = status(3); val b = ByteBuffer.wrap(wire).order(ByteOrder.nativeOrder())
            b.putInt(4, code); b.position(112); b.putLong(3); b.put(bytes(4)); b.putLong(-2)
            val decoded = assertIs<PolicyRenewalStatus.AbandonedUncommitted>(PolicyRenewalCodec.decodeStatus(wire))
            assertEquals(expected, decoded.reason); assertEquals(Counter64.of(3), decoded.observedRoster.version)
            assertEquals("18446744073709551614", decoded.observedAt.toString())
        }
    }
    @Test fun malformedStatusesCannotBecomeCommittedOrNoCommit() {
        for (phase in listOf(0, 3, 4, -1)) assertFailsWith<ContinuityBoundaryFailure> { PolicyRenewalCodec.decodeStatus(status(phase)) }
        val pending = status(1); ByteBuffer.wrap(pending).order(ByteOrder.nativeOrder()).putLong(152, 1)
        assertFailsWith<ContinuityBoundaryFailure> { PolicyRenewalCodec.decodeStatus(pending) }
        val committed = status(2); ByteBuffer.wrap(committed).order(ByteOrder.nativeOrder()).putInt(4, 1)
        assertFailsWith<ContinuityBoundaryFailure> { PolicyRenewalCodec.decodeStatus(committed) }
        val zero = status(2); ByteBuffer.wrap(zero).order(ByteOrder.nativeOrder()).putLong(72, 0)
        assertFailsWith<ContinuityBoundaryFailure> { PolicyRenewalCodec.decodeStatus(zero) }
    }
}
