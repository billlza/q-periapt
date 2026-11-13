// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

class ConfigurationTests {
    @Test fun ffiStructuresMatchC() {
        assertEquals(mapOf("header" to (8L to 4L), "blob" to (16L to 8L), "trust" to (72L to 8L),
            "protocol" to (104L to 8L), "create" to (264L to 8L), "open" to (184L to 8L),
            "witness" to (152L to 8L)), ContinuityNative.configurationLayouts())
    }
    @Test fun originalTrustAndPolicyInputsAreCopiedAndBounded() {
        val root = ByteArray(1952) { 1 }; val scope = ByteArray(32) { 2 }
        val trust = SdkPolicyTrust.recoverable(scope, root, root)
        root.fill(0); scope.fill(0)
        assertTrue(trust.root.encoded().all { it == 1.toByte() }); assertTrue(trust.scope.encoded().all { it == 2.toByte() })
        assertFailsWith<IllegalArgumentException> { InitialSdkPolicy(trust, byteArrayOf(1), ByteArray(3309)) }
        val proof = ByteArray(3309) { 3 }
        val sdk = InitialSdkPolicy(trust, ByteArray(65536) { 1 }, ByteArray(3309), proof)
        proof.fill(0); assertTrue(sdk.enrollment.encoded().all { it == 3.toByte() })
        val fixed = SdkPolicyTrust.fixed(ByteArray(1952))
        assertFailsWith<IllegalArgumentException> { InitialSdkPolicy(fixed, byteArrayOf(1), ByteArray(3309), proof) }
        assertFailsWith<IllegalArgumentException> { InitialSdkPolicy(fixed, ByteArray(65537), ByteArray(3309)) }
        assertFailsWith<IllegalArgumentException> { SdkPolicyTrust.recoverable(ByteArray(32), ByteArray(1952), ByteArray(1952)) }
    }
    @Test fun tlsSnapshotsAreIsolatedClearedOnBothReturnsAndClosed() {
        val caller = ByteArray(32) { 7 }; val cert = ByteArray(32) { 9 }
        val tls = LocalTlsIdentity(cert, caller); caller.fill(2); cert.fill(3)
        val snapshot = tls.withKey { value -> assertTrue(value.all { it == 7.toByte() }); value }
        assertTrue(snapshot.all { it == 0.toByte() })
        assertTrue(tls.certificate.encoded().all { it == 9.toByte() })
        var failedSnapshot: ByteArray? = null
        assertFailsWith<IllegalArgumentException> { tls.withKey { failedSnapshot = it; throw IllegalArgumentException("test") } }
        assertTrue(checkNotNull(failedSnapshot).all { it == 0.toByte() })
        tls.close(); tls.close()
        assertFailsWith<IllegalStateException> { tls.withKey { error("closed input borrowed") } }
        assertTrue(caller.all { it == 2.toByte() })
    }
    @Test fun closeDoesNotCorruptAnAdmittedTlsSnapshot() {
        val tls = LocalTlsIdentity(byteArrayOf(1), ByteArray(32) { 7 })
        val entered = CountDownLatch(1); val continueCall = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val call = executor.submit<ByteArray> { tls.withKey { key ->
                entered.countDown(); check(continueCall.await(10, TimeUnit.SECONDS))
                assertTrue(key.all { it == 7.toByte() }); key
            } }
            check(entered.await(10, TimeUnit.SECONDS)); tls.close()
            assertFailsWith<IllegalStateException> { tls.withKey { error("new borrow after close") } }
            continueCall.countDown()
            assertTrue(call.get(10, TimeUnit.SECONDS).all { it == 0.toByte() })
        } finally { continueCall.countDown(); tls.close(); executor.shutdownNow(); check(executor.awaitTermination(10, TimeUnit.SECONDS)) }
    }
}
