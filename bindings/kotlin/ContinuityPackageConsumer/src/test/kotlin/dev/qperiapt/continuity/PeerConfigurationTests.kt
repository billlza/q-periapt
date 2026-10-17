// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import kotlin.test.*

class PeerConfigurationTests {
    private fun account(root: ByteArray) = AccountPin(AccountID(ByteArray(32) { 1 }), root,
        ByteArray(32) { 2 }, RosterCheckpoint(Counter64.of(1), ByteArray(32) { 3 }))
    @Test fun callerAndReturnedArraysCannotChangePeerTrust() {
        val root = ByteArray(1985) { 4 }; val device = ByteArray(16) { 5 }
        val bundle = byteArrayOf(6, 7); val certificate = byteArrayOf(8, 9); val directory = ByteArray(32) { 10 }
        val expected = PeerDeviceExpectation(account(root), device, Counter64.parse("18446744073709551615"))
        val input = PeerConfiguration(expected, expected, directory, bundle, certificate, "peer.test")
        root.fill(0); device.fill(0); bundle.fill(0); certificate.fill(0); directory.fill(0)
        assertContentEquals(ByteArray(1985) { 4 }, input.initiator.account.root.encoded())
        assertContentEquals(ByteArray(16) { 5 }, input.initiator.device.encoded())
        assertContentEquals(ByteArray(32) { 10 }, input.directory.encoded())
        assertContentEquals(byteArrayOf(6, 7), input.bundle.encoded())
        assertContentEquals(byteArrayOf(8, 9), input.tlsPeerCertificate.encoded())
        input.bundle.encoded().fill(0)
        assertContentEquals(byteArrayOf(6, 7), input.bundle.encoded())
        assertEquals("18446744073709551615", input.initiator.generation.toString())
    }
    @Test fun ffiLayoutsAndInputBoundsMatchNativeContract() {
        assertEquals(mapOf("device" to (144L to 8L), "configuration" to (384L to 8L)), ContinuityNative.peerConfigurationLayouts())
        val account = account(ByteArray(1985))
        assertFailsWith<IllegalArgumentException> { PeerDeviceExpectation(account, byteArrayOf(1), Counter64.of(1)) }
        assertFailsWith<IllegalArgumentException> { PeerDeviceExpectation(account, ByteArray(16) { 1 }, Counter64.ZERO) }
        val expected = PeerDeviceExpectation(account, ByteArray(16) { 1 }, Counter64.of(1))
        for (name in listOf("", "a\u0000b", "é".repeat(65))) {
            assertFailsWith<IllegalArgumentException> { PeerConfiguration(expected, expected, ByteArray(32) { 1 }, byteArrayOf(1), byteArrayOf(1), name) }
        }
        assertFails { PeerConfiguration(expected, expected, ByteArray(32) { 1 }, byteArrayOf(1), byteArrayOf(1), "\uD800") }
        assertFailsWith<IllegalArgumentException> { PeerConfiguration(expected, expected, ByteArray(32) { 1 }, ByteArray(65537), byteArrayOf(1), "peer.test") }
    }
}
