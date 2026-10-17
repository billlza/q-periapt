// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout.ADDRESS
import java.lang.foreign.ValueLayout.JAVA_BYTE
import java.lang.foreign.ValueLayout.JAVA_INT
import java.lang.foreign.ValueLayout.JAVA_LONG
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RootReplacementTests {
    private fun scope() = RootReplacementScope(AccountAuthorityCheckpoint(ApplicationAccountID(ByteArray(32) { 1 }),
        Counter64.parse("1"), AccountID(ByteArray(32) { 2 })), ByteArray(32) { 3 }, ByteArray(1985) { 4 })
    @Test fun rootLayoutsAndAllFourIndependentInputsMatchNative() {
        assertEquals(mapOf("scope" to 128L, "checkpoint_offset" to 8L, "public_key_offset" to 112L,
            "alternative" to 72L, "original_offset" to 8L, "receipt_length_offset" to 64L), RootReplacementNative.layouts())
        // These are grammar/ownership fixtures, not fabricated signed authorizations.
        val original = "QPAFPL01original".toByteArray(); val next = "QPAFPL01next".toByteArray()
        val noncommit = ByteArray(3449) { 5 }; val freeze = ByteArray(5725) { 6 }
        val approval = RootReplacementTransition(RootReplacementPlan(original), RootReplacementPlan(next), noncommit, freeze)
        original[8] = 99; next[8] = 99; noncommit[0] = 99; freeze[0] = 99
        Arena.ofConfined().use { arena ->
            val selected = RootReplacementNative.encodeScope(arena, scope())
            assertEquals(128, selected.get(JAVA_INT, 0)); assertEquals(1L, selected.get(JAVA_LONG, 40))
            assertEquals(1985L, selected.get(JAVA_LONG, 120))
            assertEquals(4.toByte(), selected.get(ADDRESS, 112).reinterpret(1985).get(JAVA_BYTE, 0))
            val encoded = RootReplacementNative.encodeTransition(arena, approval)
            assertEquals(72, encoded.get(JAVA_INT, 0))
            assertEquals('o'.code.toByte(), encoded.get(ADDRESS, 8).reinterpret(15).get(JAVA_BYTE, 8))
            assertEquals('n'.code.toByte(), encoded.get(ADDRESS, 24).reinterpret(12).get(JAVA_BYTE, 8))
            assertEquals(5.toByte(), encoded.get(ADDRESS, 40).reinterpret(3449).get(JAVA_BYTE, 0))
            assertEquals(6.toByte(), encoded.get(ADDRESS, 56).reinterpret(5725).get(JAVA_BYTE, 0))
            assertEquals(3449L, encoded.get(JAVA_LONG, 48)); assertEquals(5725L, encoded.get(JAVA_LONG, 64))
        }
    }
    @Test fun rootApprovalsOwnBytesAndRejectWrongGrammarBoundsAndStates() {
        for (bytes in listOf(byteArrayOf(), "QPAFPL02".toByteArray(), ByteArray(131073))) {
            assertFailsWith<IllegalArgumentException> { RootReplacementPlan(bytes) }
        }
        for (header in listOf("QPARPL01", "QPARPL02")) {
            val bytes = header.toByteArray(); val value = RootReplacementProposal(bytes); bytes.fill(0)
            val returned = value.bytes.encoded(); returned.fill(0)
            assertContentEquals(header.toByteArray(), value.bytes.encoded())
        }
        assertFailsWith<ContinuityBoundaryFailure> { RootReplacementProposal.decode("QPARPL03".toByteArray()) }
        for (value in listOf(0, 5, -1)) assertFailsWith<ContinuityBoundaryFailure> { RootReplacementState.decode(value) }
        assertEquals(RootReplacementState.entries, (1..4).map { RootReplacementState.decode(it) })
        val plan = RootReplacementPlan("QPAFPL01".toByteArray())
        assertFailsWith<IllegalArgumentException> { RootReplacementTransition(plan, plan, ByteArray(3448), byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> {
            RootReplacementAdoption(plan, RootReplacementProposal("QPARPL02".toByteArray()), ByteArray(3449), byteArrayOf(1))
        }
        val good = scope()
        assertFailsWith<IllegalArgumentException> { RootReplacementScope(good.checkpoint, ByteArray(32), good.publicKey.encoded()) }
        val key = good.publicKey.encoded(); val witness = good.witness.encoded()
        val copy = RootReplacementScope(good.checkpoint, witness, key); key.fill(0); witness.fill(0)
        assertEquals(good.publicKey, copy.publicKey); assertEquals(good.witness, copy.witness)
    }
    @Test fun pendingRegistryCannotGrantRootOrCleanupAuthority() {
        val point = "026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val trust = AccountAuthorityTrust(AccountAuthorityID(ByteArray(32) { 7 }), ByteArray(32) { 8 },
            scope().witness.encoded(), ByteArray(1952) + point)
        ContinuityAccountAuthority.prepareOpen("/unused", trust).use { owner ->
            assertEquals(6, assertFailsWith<ContinuityFailure> { owner.rootReplacementState() }.code)
            assertEquals(6, assertFailsWith<ContinuityFailure> { owner.retiredInventory() }.code)
            assertFailsWith<IllegalArgumentException> { owner.retainRootRetirement(byteArrayOf()) }
            assertEquals(6, assertFailsWith<ContinuityFailure> { owner.rootReplacementState() }.code)
            owner.cancel()
            assertEquals(302, assertFailsWith<ContinuityFailure> { owner.finishOpen() }.code)
        }
    }
}
