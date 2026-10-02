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
            "account_target" to (40L to 8L), "account_delivery" to (88L to 4L),
            "account_cleanup_header" to (72L to 4L), "account_cleanup_member" to (136L to 8L),
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
    @Test fun devicePreparationCannotGrantPeerAuthorityAndSharesCapacity() {
        repeat(128) { ContinuityDevice.prepare("/unused").use { it.cancel() } }
        val devices = mutableListOf<ContinuityDevice>()
        try {
            repeat(64) { devices.add(ContinuityDevice.prepare("/unused")) }
            fails(4) { ContinuityRecoveryOwner.prepare("/unused") }
            val first = devices.removeAt(0)
            first.use {
                fails(6) { it.preparePeer("/unused", PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR) }
                fails(6) { it.nextAccountOperation() }
                it.cancel()
                fails(302) { it.finishOpen() }
            }
            fails(2) { first.preparePeer("/unused", PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.RESPONDER) }
            ContinuityDevice.prepare("/unused").use { it.cancel() }
        } finally {
            var failure: Throwable? = null
            for (device in devices) try { device.close() } catch (error: Throwable) {
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
            failure?.let { throw it }
        }
    }
    @Test fun aggregateStatusPreservesReportsAndRejectsMalformedOutput() {
        val zero = ByteArray(32)
        val report = ByteArray(32) { 9 }
        val id = AccountAbandonmentID(report)
        val states = listOf(AccountStatus.Absent, AccountStatus.Reserved, AccountStatus.Committed,
            AccountStatus.Abandoning(id), AccountStatus.Abandoned(id), AccountStatus.Retired)
        for ((state, value) in states.withIndex()) {
            assertEquals(value, ContinuityNative.decodeAccountStatus(state, if (state in 3..4) report else zero))
            assertFailsWith<ContinuityBoundaryFailure> {
                ContinuityNative.decodeAccountStatus(state, if (state in 3..4) zero else report)
            }
        }
        for (state in listOf(-1, 6, 255, 256, 259)) {
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeAccountStatus(state, zero) }
        }
        assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeAccountStatus(0, byteArrayOf(0)) }
        assertNotEquals<ContinuityID>(AccountOperationID(report), AccountID(report))
    }
    @Test fun accountCleanupCannotAcquireAuthorityFromPendingCancelledOrClosedOwner() {
        val owner = ContinuityRecoveryOwner.prepare("/unused")
        val operation = AccountOperationID(ByteArray(32) { 1 })
        val report = AccountAbandonmentID(ByteArray(32) { 2 })
        val actions: List<() -> Unit> = listOf(
            { owner.selectAccount(operation) }, { owner.beginAccountCleanup() }, { owner.accountCleanupStatus() },
            { owner.accountMemberAt(0) }, { owner.accountReservation(0) }, { owner.accountEpochAt(0, 0) },
            { owner.accountUnconfirmedAt(0, 0, 0) }, { owner.accountDeliveryAt(0, 0, 0) },
            { owner.accountSkippedPosition(0, 0, 0) }, { owner.acknowledgeAccount(report) }, { owner.retireAccount() },
        )
        try {
            for (action in actions) fails(6, action)
            for (index in listOf(-1L, 0x1_0000_0000L)) {
                assertFailsWith<IllegalArgumentException> { owner.accountMemberAt(index) }
                assertFailsWith<IllegalArgumentException> { owner.accountReservation(index) }
                assertFailsWith<IllegalArgumentException> { owner.accountEpochAt(0, index) }
                assertFailsWith<IllegalArgumentException> { owner.accountUnconfirmedAt(0, 0, index) }
                assertFailsWith<IllegalArgumentException> { owner.accountDeliveryAt(0, index, 0) }
                assertFailsWith<IllegalArgumentException> { owner.accountSkippedPosition(index, 0, 0) }
            }
            owner.cancel()
            fails(302) { owner.finishOpen() }
            for (action in actions) fails(2, action)
        } finally { owner.close() }
        for (action in actions) fails(2, action)
    }
    @Test fun accountDeliveryRequiresSelectedSessionAndTypedRetainedOutcomes() {
        val session = SessionID(ByteArray(32) { 7 })
        val device = ByteArray(16) { 1 }
        val message = ByteArray(32) { 2 }
        val outcomes = listOf(AccountDeliveryOutcome.Consumed(Consumption.CONFIRMED),
            AccountDeliveryOutcome.Consumed(Consumption.PREFIX_PENDING), AccountDeliveryOutcome.ResolutionPending,
            AccountDeliveryOutcome.DeliveryUnknown, AccountDeliveryOutcome.HistoryRetired, AccountDeliveryOutcome.ReservationAbandoned)
        for ((index, outcome) in outcomes.withIndex()) {
            val result = ContinuityNative.decodeAccountDelivery(device, session.encoded(), message, index + 1,
                if (index == 1) 1 else 0, session)
            assertEquals(outcome, result.outcome)
            assertEquals(session, result.session)
            assertEquals(MessageID(message), result.message)
        }
        for ((outcome, exchanges) in listOf(2 to 0, 1 to 9, 1 to -1, 7 to 1)) {
            assertFailsWith<ContinuityBoundaryFailure> {
                ContinuityNative.decodeAccountDelivery(device, session.encoded(), message, outcome, exchanges, session)
            }
        }
        for ((observedDevice, observedSession, observedMessage) in listOf(
            Triple(ByteArray(16), session.encoded(), message), Triple(device, ByteArray(32) { 8 }, message),
            Triple(device, session.encoded(), ByteArray(32)), Triple(device, session.encoded(), ByteArray(31)))) {
            assertFailsWith<ContinuityBoundaryFailure> {
                ContinuityNative.decodeAccountDelivery(observedDevice, observedSession, observedMessage, 1, 1, session)
            }
        }
    }
}
