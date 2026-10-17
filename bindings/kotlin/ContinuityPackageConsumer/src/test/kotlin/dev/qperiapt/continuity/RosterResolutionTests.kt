// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RosterResolutionTests {
    private fun cp(version: Long, digest: Byte = version.toByte()): ByteArray =
        ByteBuffer.allocate(40).order(ByteOrder.nativeOrder()).putLong(version).put(ByteArray(32) { digest }).array()
    private fun decode(outcome: Int = 4, reserved: Int = 0, journal: ByteArray = ByteArray(32) { 9 },
        previous: ByteArray = cp(1), target: ByteArray = cp(2), observed: ByteArray = cp(3),
        at: Counter64 = Counter64.of(185)): RosterRefreshResolution =
        ContinuityNative.decodeRosterRefreshResolution(outcome, reserved, journal, previous, target, observed, at)
    @Test fun layoutHasExactSizeAndAlignment() {
        assertEquals(168L to 8L, ContinuityNative.layouts().getValue("roster_resolution"))
    }
    @Test fun allFourOutcomesPreserveUnknownAndUnsignedOrdering() {
        val expected = listOf(RosterRefreshOutcome.COMMITTED, RosterRefreshOutcome.EXPIRED_UNCOMMITTED,
            RosterRefreshOutcome.SUPERSEDED_UNCOMMITTED, RosterRefreshOutcome.SUPERSEDED_UNKNOWN)
        for ((index, actual) in listOf(cp(2), cp(1), cp(2, 3), cp(3)).withIndex()) {
            assertEquals(expected[index], decode(outcome = index + 1, observed = actual).outcome)
        }
        val high = decode(previous = cp(-4), target = cp(-3), observed = cp(-2))
        assertEquals("18446744073709551614", high.observed.version.toString())
    }
    @Test fun malformedAndContradictoryResultsAreRejected() {
        for (outcome in listOf(0, 1, 2, 3, 5)) {
            assertFailsWith<ContinuityBoundaryFailure> { decode(outcome = outcome) }
        }
        assertFailsWith<ContinuityBoundaryFailure> { decode(reserved = 1) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(journal = ByteArray(32)) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(at = Counter64.ZERO) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(previous = cp(3)) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(outcome = 2, observed = cp(1, 9)) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(observed = cp(0)) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(target = cp(2, 0)) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(target = ByteArray(39)) }
    }
    @Test fun resolvedPhaseKeepsOriginalPairAndStillRejectsUnknownPhases() {
        val state = ContinuityNative.decodeEnrollmentStatus(7, ByteArray(32) { 1 }, ByteArray(32) { 2 }, cp(1), cp(2))
        assertEquals(EnrollmentPhase.ROSTER_RESOLVED, state.phase)
        assertEquals(Counter64.of(1), state.refresh?.previous?.version)
        assertEquals(Counter64.of(2), state.refresh?.next?.version)
        assertFailsWith<ContinuityBoundaryFailure> {
            ContinuityNative.decodeEnrollmentStatus(8, ByteArray(32) { 1 }, ByteArray(32) { 2 }, cp(1), cp(2))
        }
    }
}
