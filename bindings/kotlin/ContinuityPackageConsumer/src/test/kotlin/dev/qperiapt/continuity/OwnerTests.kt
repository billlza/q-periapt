// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.charset.CharacterCodingException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class OwnerTests {
    private fun fails(code: Int, action: () -> Unit) {
        assertEquals(code, assertFailsWith<ContinuityFailure>(block = action).code)
    }
    @Test fun identifiersAreTypedImmutablePublicValues() {
        val bytes = ByteArray(32) { it.toByte() }
        val session = SessionID(bytes)
        bytes.fill(7)
        val read = session.encoded()
        assertEquals(0, read[0].toInt())
        read.fill(9)
        assertEquals(SessionID(ByteArray(32) { it.toByte() }), session)
        assertNotEquals<ContinuityID>(MessageID(session.encoded()), session)
        assertFailsWith<IllegalArgumentException> { SessionID(ByteArray(31)) }
        assertEquals(32, InitiationID.random().encoded().size)
    }
    @Test fun unsignedCountersRetainTheirWholeRange() {
        val maximum = Counter64.parse("18446744073709551615")
        assertEquals("18446744073709551615", maximum.toString())
        assertTrue(maximum > Counter64.of(Long.MAX_VALUE))
        assertEquals(maximum, Counter64.fromBits(-1))
        for (value in listOf("-1", "+1", "01", "", "18446744073709551616")) {
            assertFailsWith<IllegalArgumentException> { Counter64.parse(value) }
        }
        assertFailsWith<IllegalArgumentException> { Counter64.of(-1) }
    }
    @Test fun structuresMatchThe64BitNativeContract() {
        assertEquals(mapOf(
            "error" to (524L to 4L), "witness" to (24L to 8L), "options" to (24L to 8L),
            "served" to (72L to 4L), "header" to (200L to 8L), "epoch" to (104L to 8L),
            "reserved" to (48L to 8L), "unconfirmed" to (64L to 1L),
            "delivery" to (48L to 8L), "status" to (36L to 4L),
        ), ContinuityNative.layouts())
    }
    @Test fun pendingOwnersRejectWorkAndCancellationNeverActivates() {
        val owners = listOf(
            ContinuityOwner.prepare("/absent-continuity-jvm-probe", PrekeyQuality.ONE_TIME_BOTH),
            ContinuityOwner.prepareReopen("/absent-continuity-jvm-probe", PrekeyQuality.ONE_TIME_BOTH, SessionID(ByteArray(32) { 73 })),
        )
        for (owner in owners) {
            try {
                fails(101) { owner.messageStatus(SessionID(ByteArray(32)), MessageID(ByteArray(32))) }
                fails(6) { owner.listen("127.0.0.1:0") }
                owner.cancel()
                fails(302) { owner.finishOpen() }
                fails(2) { owner.finishOpen() }
            } finally { owner.close() }
            fails(2) { owner.cancel() }
            fails(2) { owner.close() }
        }
        fails(1) {
            ContinuityOwner.prepareReopen("/absent-continuity-jvm-probe", PrekeyQuality.ONE_TIME_BOTH, SessionID(ByteArray(32)))
        }
    }
    @Test fun failedOpenReleasesTheOriginalOwnerSlot() {
        repeat(128) {
            fails(203) { ContinuityOwner.open("relative", PrekeyQuality.ONE_TIME_BOTH) }
        }
        val owner = ContinuityOwner.prepare("/absent-continuity-jvm-probe", PrekeyQuality.ONE_TIME_BOTH)
        try {
            fails(500) { owner.finishOpen() }
            fails(2) { owner.finishOpen() }
        } finally { owner.close() }
    }
    @Test fun bothKindsShareCapacityAndDrainRemainsAvailable() {
        val owners = mutableListOf<AutoCloseable>()
        try {
            repeat(64) { index ->
                owners.add(if (index % 2 == 0) ContinuityOwner.prepare("/absent-continuity-jvm-probe", PrekeyQuality.ONE_TIME_BOTH)
                    else ContinuityRecoveryOwner.prepare("/absent-continuity-jvm-probe"))
            }
            fails(4) { ContinuityRecoveryOwner.prepare("/absent-continuity-jvm-probe") }
            val first = owners.removeAt(0)
            first.close()
            ContinuityRecoveryOwner.prepare("/absent-continuity-jvm-probe").use { it.cancel() }
        } finally {
            var failure: Throwable? = null
            for (owner in owners) try { owner.close() } catch (error: Throwable) {
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
            failure?.let { throw it }
        }
    }
    @Test fun recoveryCancellationAndClosedStateKeepTheirNativeKinds() {
        val owner = ContinuityRecoveryOwner.prepare("/absent-continuity-jvm-probe")
        try {
            fails(6) { owner.sessionCount() }
            owner.cancel()
            fails(302) { owner.finishOpen() }
        } finally { owner.close() }
        fails(2) { owner.sessionCount() }
    }
    @Test fun textAndApplicationRefusalsCannotSilentlyCoerceInvalidInput() {
        assertFailsWith<IllegalArgumentException> { WitnessCarrier.SignedTCP("127.0.0.1:1", 0) }
        assertFailsWith<IllegalArgumentException> { ApplicationCommitRefusal(0, "not committed") }
        assertFailsWith<CharacterCodingException> {
            ContinuityOwner.prepare("/bad\uD800", PrekeyQuality.ONE_TIME_BOTH)
        }
        assertFailsWith<IllegalArgumentException> {
            ContinuityOwner.prepare("/bad\u0000", PrekeyQuality.ONE_TIME_BOTH)
        }
        val original = byteArrayOf(1, 2, 3)
        val delivery = ApplicationDelivery(SessionID(ByteArray(32)), MessageID(ByteArray(32)), original)
        original.fill(0)
        assertContentEquals(byteArrayOf(1, 2, 3), delivery.plaintext())
    }
}
