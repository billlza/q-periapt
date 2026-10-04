// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class CredentialRenewalTests {
    private fun checkpoint(version: Long = 1L, digest: ByteArray = ByteArray(32) { 3 }): ByteArray =
        ByteBuffer.allocate(40).order(ByteOrder.nativeOrder()).putLong(version).put(digest).array()

    @Test fun renewalIdentitiesAreDistinctImmutableAndNonzero() {
        val bytes = ByteArray(32) { 1 }
        val operation = CredentialRenewalID(bytes)
        val statement = CredentialRenewalStatementID(bytes)
        bytes.fill(7)
        operation.encoded().fill(9); statement.encoded().fill(8)
        assertContentEquals(ByteArray(32) { 1 }, operation.encoded())
        assertContentEquals(ByteArray(32) { 1 }, statement.encoded())
        assertNotEquals<ContinuityID>(operation, statement)
        for (invalid in listOf(ByteArray(31) { 1 }, ByteArray(33) { 1 }, ByteArray(32))) {
            assertFailsWith<IllegalArgumentException> { CredentialRenewalID(invalid) }
            assertFailsWith<IllegalArgumentException> { CredentialRenewalStatementID(invalid) }
        }
    }

    @Test fun historicalRenewalStatesRetainExactFieldsAndUnsignedTime() {
        // The offsets are the installed 64-bit C header contract, including the
        // four-byte alignment gap before its embedded roster checkpoint.
        assertEquals(mapOf("phase" to 0L, "operation" to 4L, "statement" to 36L,
            "checkpoint" to 72L, "observed_at" to 112L), ContinuityNative.credentialRenewalOffsets())
        val operation = ByteArray(32) { 1 }; val statement = ByteArray(32) { 2 }
        val head = checkpoint(Long.MIN_VALUE)
        val op = CredentialRenewalID(operation); val signed = CredentialRenewalStatementID(statement)
        val target = RosterCheckpoint(Counter64.parse("9223372036854775808"), ByteArray(32) { 3 })
        val maximum = Counter64.parse("18446744073709551615")
        assertEquals(CredentialRenewalStatus.Absent,
            ContinuityNative.decodeCredentialRenewalStatus(0, ByteArray(32), ByteArray(32), ByteArray(40), Counter64.ZERO))
        assertEquals(CredentialRenewalStatus.Pending(op, signed),
            ContinuityNative.decodeCredentialRenewalStatus(1, operation, statement, ByteArray(40), Counter64.ZERO))
        assertEquals(CredentialRenewalStatus.Committed(op, signed, target),
            ContinuityNative.decodeCredentialRenewalStatus(2, operation, statement, head, Counter64.ZERO))
        val expired = ContinuityNative.decodeCredentialRenewalStatus(3, operation, statement, head, maximum)
        operation.fill(0); statement.fill(0); head.fill(0)
        assertEquals(CredentialRenewalStatus.ExpiredUncommitted(op, signed, target, maximum), expired)
        assertFailsWith<IllegalArgumentException> {
            CredentialRenewalStatus.ExpiredUncommitted(op, signed, target, Counter64.ZERO)
        }
    }

    @Test fun contradictoryRenewalFieldsNeverBecomeAnAbsentOrSuccessfulResult() {
        val op = ByteArray(32) { 1 }; val signed = ByteArray(32) { 2 }; val zero = ByteArray(32)
        fun refused(phase: Int, operation: ByteArray, statement: ByteArray, head: ByteArray, at: Counter64) {
            assertFailsWith<ContinuityBoundaryFailure> {
                ContinuityNative.decodeCredentialRenewalStatus(phase, operation, statement, head, at)
            }
        }
        for (phase in listOf(-1, 4, Int.MAX_VALUE)) refused(phase, zero, zero, ByteArray(40), Counter64.ZERO)
        refused(0, op, zero, ByteArray(40), Counter64.ZERO)
        refused(0, zero, signed, ByteArray(40), Counter64.ZERO)
        refused(0, zero, zero, checkpoint(), Counter64.ZERO)
        refused(0, zero, zero, ByteArray(40), Counter64.of(1))
        for (phase in 1..3) {
            val head = if (phase == 1) ByteArray(40) else checkpoint()
            val at = if (phase == 3) Counter64.of(1) else Counter64.ZERO
            refused(phase, zero, signed, head, at)
            refused(phase, op, zero, head, at)
            refused(phase, ByteArray(31), signed, head, at)
            refused(phase, op, ByteArray(33), head, at)
            refused(phase, op, signed, ByteArray(39), at)
        }
        refused(1, op, signed, checkpoint(), Counter64.ZERO)
        refused(1, op, signed, ByteArray(40), Counter64.of(1))
        refused(2, op, signed, checkpoint(), Counter64.of(1))
        refused(3, op, signed, checkpoint(), Counter64.ZERO)
        for (head in listOf(checkpoint(0), checkpoint(-1), checkpoint(1, zero))) {
            refused(2, op, signed, head, Counter64.ZERO)
            refused(3, op, signed, head, Counter64.of(1))
        }
    }

    @Test fun grantLengthChecksPreserveOwnersAndInclusiveLimitReachesNativeAdmission() {
        val point = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        val root = ByteArray(1952) { 1 } + point.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val intent = EnrollmentIntent(root, ByteArray(16) { 2 }, Counter64.of(1), ByteArray(32) { 3 },
            Counter64.ZERO, Counter64.parse("18446744073709551614"))
        // A structurally valid public key with a deliberately different account
        // exercises real C Scope refusal before any storage or grant is admitted.
        val pin = AccountPin(AccountID(ByteArray(32) { 1 }), root, intent.family.encoded(),
            RosterCheckpoint(Counter64.of(1), ByteArray(32) { 2 }))
        val operation = CredentialRenewalID(ByteArray(32) { 4 })
        val statement = CredentialRenewalStatementID(ByteArray(32) { 5 })
        ContinuityEnrollment.prepareResume("/unused", intent).use { owner ->
            for (length in listOf(0, 65537)) {
                assertFailsWith<IllegalArgumentException> { owner.stageCredentialRenewal(ByteArray(length), pin, operation) }
            }
            for (length in listOf(1, 65536)) {
                assertEquals(103, assertFailsWith<ContinuityFailure> {
                    owner.stageCredentialRenewal(ByteArray(length), pin, operation)
                }.code)
            }
            assertEquals(6, assertFailsWith<ContinuityFailure> { owner.credentialRenewalStatus() }.code)
            assertEquals(6, assertFailsWith<ContinuityFailure> { owner.reconcileExpiredCredentialRenewal(operation, statement) }.code)
            owner.cancel()
            assertEquals(302, assertFailsWith<ContinuityFailure> { owner.finishOpen() }.code)
            assertEquals(2, assertFailsWith<ContinuityFailure> { owner.credentialRenewalStatus() }.code)
        }
        ContinuityDevice.prepare("/unused").use { owner ->
            for (length in listOf(0, 65537)) {
                assertFailsWith<IllegalArgumentException> { owner.admitPeerCredentialRenewal(ByteArray(length), pin, operation) }
            }
            for (length in listOf(1, 65536)) {
                assertEquals(103, assertFailsWith<ContinuityFailure> {
                    owner.admitPeerCredentialRenewal(ByteArray(length), pin, operation)
                }.code)
            }
            owner.cancel()
            assertEquals(302, assertFailsWith<ContinuityFailure> { owner.finishOpen() }.code)
        }
    }
}
