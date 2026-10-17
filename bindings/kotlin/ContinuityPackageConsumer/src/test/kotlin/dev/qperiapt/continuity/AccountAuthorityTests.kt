// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AccountAuthorityTests {
    // Public canonical inputs only; no fabricated account credential or witness signature.
    private fun trust(): AccountAuthorityTrust {
        val point = "026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        return AccountAuthorityTrust(AccountAuthorityID(ByteArray(32) { 1 }), ByteArray(32) { 2 },
            ByteArray(32) { 3 }, ByteArray(1952) + point)
    }
    @Test fun authorityLayoutsAndUnsignedCheckpointsMatchNative() {
        assertEquals(mapOf("options" to 120L, "public_key_offset" to 104L, "checkpoint" to 72L,
            "revision_offset" to 32L, "association" to 80L, "selection" to 88L,
            "selected_checkpoint_offset" to 16L), AccountAuthorityNative.layouts())
        val bytes = ByteBuffer.allocate(72).order(ByteOrder.nativeOrder())
            .put(ByteArray(32) { 4 }).putLong(-2L).put(ByteArray(32) { 5 }).array()
        val expected = AccountAuthorityCheckpoint(ApplicationAccountID(ByteArray(32) { 4 }),
            Counter64.parse("18446744073709551614"), AccountID(ByteArray(32) { 5 }))
        assertEquals(expected, AccountAuthorityNative.decode(bytes))
        for (revision in listOf(0L, -1L)) {
            ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()).putLong(32, revision)
            assertFailsWith<ContinuityBoundaryFailure> { AccountAuthorityNative.decode(bytes) }
        }
        assertFailsWith<ContinuityBoundaryFailure> { AccountAuthorityNative.decode(bytes.copyOf(71)) }
    }
    @Test fun authorityTrustCopiesCallerBytesAndRejectsEmptyScope() {
        val original = trust(); val family = original.family.encoded(); val key = original.publicKey.encoded()
        val selected = AccountAuthorityTrust(original.identity, family, original.witness.encoded(), key)
        family.fill(0); key.fill(0)
        assertEquals(original.family, selected.family)
        assertEquals(original.publicKey, selected.publicKey)
        val returned = selected.publicKey.encoded(); returned.fill(0)
        assertContentEquals(original.publicKey.encoded(), selected.publicKey.encoded())
        assertFailsWith<IllegalArgumentException> { AccountAuthorityTrust(original.identity, family, original.witness.encoded(), key) }
        assertFailsWith<IllegalArgumentException> {
            AccountAuthorityTrust(original.identity, original.family.encoded(), original.witness.encoded(), key.copyOf(1984))
        }
    }
    @Test fun pendingAuthoritySharesCapacityAndPreservesCancellation() {
        val owners = ArrayList<ContinuityAccountAuthority>()
        try {
            repeat(64) { owners.add(ContinuityAccountAuthority.prepareOpen("/unused", trust())) }
            assertEquals(4, assertFailsWith<ContinuityFailure> { ContinuityDevice.prepare("/unused").use { it.cancel() } }.code)
            for (owner in owners) {
                owner.cancel()
                assertEquals(302, assertFailsWith<ContinuityFailure> { owner.finishOpen() }.code)
            }
        } finally {
            var failure: Throwable? = null
            for (owner in owners) try { owner.close() } catch (next: Throwable) {
                if (failure == null) failure = next else failure.addSuppressed(next)
            }
            failure?.let { throw it }
        }
        for (owner in owners) assertEquals(2, assertFailsWith<ContinuityFailure> { owner.close() }.code)
        ContinuityDevice.prepare("/unused").use { it.cancel() }
    }
    @Test fun originalAuthorityStoreReopensAfterExplicitClose() {
        val directory = Files.createTempDirectory("qperiapt-authority-unit-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toRealPath()
        val path = directory.toString(); val input = trust()
        try {
            ContinuityAccountAuthority.provisionWrappingKey(path)
            ContinuityAccountAuthority.prepareCreate(path, input).use { it.finishOpen() }
            ContinuityAccountAuthority.prepareOpen(path, input).use { it.finishOpen() }
        } finally {
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.delete(it) } }
        }
    }
}
