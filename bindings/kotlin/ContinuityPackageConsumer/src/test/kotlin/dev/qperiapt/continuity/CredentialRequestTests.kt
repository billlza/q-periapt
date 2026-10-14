// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class CredentialRequestTests {
    private fun request(): ByteArray = ByteArray(33120).also { bytes ->
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder())
        for (offset in listOf(0,32,64,96,136,216,256,304)) bytes.fill(7, offset, offset + 32)
        b.putLong(128, -2); b.putLong(208, -2); b.putLong(248, -2); b.putLong(288, 0); b.putLong(296, -2)
        for (offset in listOf(336,8532,16728,24924)) { b.putInt(offset, 2); bytes[offset + 4] = 1; bytes[offset + 5] = 2 }
    }
    @Test fun credentialIssuerRequestLayoutAndOwnedUnsignedInputsMatchNative() {
        assertEquals(33120L to 8L, ContinuityNative.layouts()["credential_renewal_request"])
        assertEquals(mapOf("operation" to 0L,"journal" to 32L,"original_owner" to 64L,"original_policy_digest" to 96L,
            "current_policy" to 128L,"current_policy_authorization" to 168L,"has_current_policy_authorization" to 200L,"reserved" to 204L,
            "previous_roster_checkpoint" to 208L,"original_roster_checkpoint" to 248L,"previous_valid_from" to 288L,
            "previous_valid_until" to 296L,"account" to 304L,"original_credential" to 336L,"original_roster" to 8532L,
            "previous_credential" to 16728L,"previous_roster" to 24924L), ContinuityNative.credentialRequestOffsets())
        val bytes = request(); val decoded = CredentialRequestCodec.decode(bytes); bytes.fill(0)
        decoded.originalOwner.encoded().fill(0); decoded.previousRoster.encoded().fill(0)
        assertContentEquals(ByteArray(32) { 7 }, decoded.originalOwner.encoded())
        assertContentEquals(byteArrayOf(1,2), decoded.previousRoster.encoded())
        assertEquals(Counter64.parse("18446744073709551614"), decoded.previousValidUntil)
        assertEquals(decoded.originalRosterCheckpoint, decoded.previousRosterCheckpoint)
        assertNull(decoded.currentPolicyAuthorization)
        val adopted = request().also { it.fill(9,168,200); ByteBuffer.wrap(it).order(ByteOrder.nativeOrder()).putInt(200,1) }
        assertEquals(PolicyAuthorizationID(ByteArray(32) { 9 }), CredentialRequestCodec.decode(adopted).currentPolicyAuthorization)
    }
    @Test fun issuerRequestRejectsContradictoryAuthorizationPredecessorValidityAndRecordTails() {
        val original = request(); val invalid = mutableListOf(original.copyOf(33119), original + byteArrayOf(0))
        for (offset in listOf(0,32,64,96,136,216,256,304)) invalid += original.clone().also { it.fill(0,offset,offset+32) }
        for ((offset,value) in listOf(200 to 2,200 to -1,204 to 1,336 to 0,8532 to 8193,16728 to -1)) invalid += original.clone().also { ByteBuffer.wrap(it).order(ByteOrder.nativeOrder()).putInt(offset,value) }
        for (offset in listOf(168,138,256,350,33119)) invalid += original.clone().also { it[offset] = (it[offset].toInt() xor 1).toByte() }
        invalid += original.clone().also { ByteBuffer.wrap(it).order(ByteOrder.nativeOrder()).putInt(200,1) }
        for ((offset,value) in listOf(128 to 0L,208 to 0L,248 to -1L,208 to 1L,288 to -2L,296 to -1L)) invalid += original.clone().also { ByteBuffer.wrap(it).order(ByteOrder.nativeOrder()).putLong(offset,value) }
        for (bytes in invalid) assertFailsWith<ContinuityBoundaryFailure> { CredentialRequestCodec.decode(bytes) }
    }
    @Test fun issuerSnapshotCallsPreservePreparedCancelledAndClosedOwnerBoundaries() {
        val point = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        val root = ByteArray(1952) { 1 } + point.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val intent = EnrollmentIntent(root, ByteArray(16) { 2 }, Counter64.of(1), ByteArray(32) { 3 }, Counter64.ZERO, Counter64.parse("18446744073709551614"))
        val operation = CredentialRenewalID(ByteArray(32) { 7 })
        ContinuityEnrollment.prepareResume("/unused", intent).use { owner ->
            val calls = listOf<() -> Unit>({ owner.credentialRenewalRequest(operation) },{ owner.witnessedCredentialRenewalRequest(operation) })
            for (call in calls) assertEquals(6, assertFailsWith<ContinuityFailure>(block=call).code)
            owner.cancel()
            for (call in calls) assertEquals(6, assertFailsWith<ContinuityFailure>(block=call).code)
            assertEquals(302, assertFailsWith<ContinuityFailure> { owner.finishOpen() }.code)
            for (call in calls) assertEquals(2, assertFailsWith<ContinuityFailure>(block=call).code)
        }
    }
}
