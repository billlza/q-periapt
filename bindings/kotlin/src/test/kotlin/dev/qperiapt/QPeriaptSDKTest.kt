// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt

import java.io.File
import java.util.HexFormat
import java.util.concurrent.Callable
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QPeriaptSDKTest {
    private val json = File("../signed-policy-vectors.json").readText()
    private fun field(name: String, source: String = json): String = requireNotNull(
        Regex("\"$name\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").find(source),
    ).groupValues[1].replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\")
    private fun hex(name: String, source: String = json): ByteArray = HexFormat.of().parseHex(requireNotNull(
        Regex("\"$name\"\\s*:\\s*\"([0-9a-f]*)\"").find(source),
    ).groupValues[1])
    private fun runtime(keys: Int = 32, calls: Int = 4, previous: ByteArray = byteArrayOf()) =
        QPeriaptRuntime.fromSignedPolicy(
            field("policy_toml").encodeToByteArray(), hex("signature"), hex("verification_key"), previous, keys, calls,
        )
    private fun failure(code: Int, operation: () -> Unit) {
        assertEquals(code, assertFailsWith<QPeriaptSDKException>(block = operation).code)
    }
    private fun equalSecrets(left: QPeriaptSecret, right: QPeriaptSecret, equal: Boolean = true) {
        val a = left.exportForProtocol()
        val b = right.exportForProtocol()
        try { assertEquals(equal, a.contentEquals(b)) } finally { a.fill(0); b.fill(0) }
    }

    @Test
    fun expertTransferAndPolicyRevocationRecovery() = runtime().use { runtime ->
        assertTrue(runtime.isEnabled())
        runtime.generateKey().use { key ->
            val exported = QPeriaptExpert.exportExpanded(key)
            try {
                assertEquals(2440, exported.size)
                QPeriaptExpert.importExpanded(exported, runtime).use { imported ->
                    assertContentEquals(key.publicKey().encoded(), imported.publicKey().encoded())
                    runtime.encapsulate(imported.publicKey(), byteArrayOf(42)).use { enc ->
                        imported.decapsulate(enc.ciphertext, byteArrayOf(42)).use { dec ->
                            equalSecrets(enc.secret, dec)
                            val revoked = File("../sdk-policy-revocation-vectors.json").readText()
                            runtime.preparePolicyUpdate(field("policy_toml", revoked).encodeToByteArray(), hex("signature", revoked)).use { update ->
                                val states = update.states()
                                assertContentEquals(runtime.trustedState(), states.previous())
                                // Test-only in-memory persistence; no durable-store claim.
                                val stored = states.next()
                                update.activateAfterPersisting().use { disabled ->
                                    assertFalse(disabled.isEnabled())
                                    failure(-3) { disabled.generateKey() }
                                    failure(-9) { key.publicKey() }
                                    failure(-9) { dec.exportForProtocol() }
                                    failure(-9) { update.activateAfterPersisting() }
                                    update.close()
                                    assertFalse(disabled.isEnabled())
                                    QPeriaptRuntime.fromSignedPolicy(field("policy_toml", revoked).encodeToByteArray(),
                                        hex("signature", revoked), hex("verification_key", revoked), stored).use { recovered ->
                                        assertFalse(recovered.isEnabled())
                                        val allowed = File("../sdk-policy-update-vectors.json").readText()
                                        recovered.preparePolicyUpdate(field("policy_toml", allowed).encodeToByteArray(), hex("signature", allowed)).use { enable ->
                                            val nextState = enable.states().next()
                                            enable.activateAfterPersisting().use { next ->
                                                assertTrue(next.isEnabled())
                                                assertContentEquals(nextState, next.trustedState())
                                                next.generateKey().close()
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } finally { exported.fill(0) }
        }
    }

    @Test
    fun expertTransferRejectsInvalidFormatAndLength() = runtime().use { runtime ->
        runtime.generateKey().use { key ->
            val exported = QPeriaptExpert.exportExpanded(key)
            try {
                exported[0] = 0
                failure(-13) { QPeriaptExpert.importExpanded(exported, runtime) }
                failure(-2) { QPeriaptExpert.importExpanded(ByteArray(64), runtime) }
            } finally { exported.fill(0) }
        }
    }

    private fun derivedKeys(left: QPeriaptSecret, right: QPeriaptSecret, context: ByteArray) {
        val label = "app/v1/aes256".encodeToByteArray()
        var previous = ByteArray(32)
        try {
            for (purpose in QPeriaptKeyPurpose.entries) {
                left.deriveKey(purpose, label, context).use { a ->
                    right.deriveKey(purpose, label, context).use { b ->
                        val first = a.exportForProtocol()
                        val second = b.exportForProtocol()
                        try {
                            assertContentEquals(first, second)
                            assertFalse(first.contentEquals(previous))
                            previous.fill(0)
                            previous = first.clone()
                        } finally { first.fill(0); second.fill(0) }
                    }
                }
            }
            failure(-2) { left.deriveKey(QPeriaptKeyPurpose.EXPORTER, byteArrayOf(), context) }
            failure(-12) { left.deriveKey(QPeriaptKeyPurpose.EXPORTER, byteArrayOf(0), context) }
        } finally { previous.fill(0) }
    }

    @Test
    fun realNativePolicyRoundtripsAndImplicitRejection() = runtime().use { sender ->
        runtime().use { receiver ->
            receiver.generateKey().use { key ->
                val publicKey = key.publicKey()
                for (size in listOf(0, 32, 65536)) {
                    val context = ByteArray(size) { (it % 251).toByte() }
                    sender.encapsulate(publicKey, context).use { enc ->
                        key.decapsulate(enc.ciphertext, context).use {
                            equalSecrets(enc.secret, it)
                            derivedKeys(enc.secret, it, context)
                        }
                        val damaged = enc.ciphertext.encoded().also { it[0] = (it[0].toInt() xor 1).toByte() }
                        key.decapsulate(QPeriaptCiphertext(damaged), context).use { equalSecrets(enc.secret, it, false) }
                        if (size != 0) {
                            context[0] = (context[0].toInt() xor 1).toByte()
                            key.decapsulate(enc.ciphertext, context).use { equalSecrets(enc.secret, it, false) }
                        }
                    }
                }
            }
        }
    }

    @Test
    fun policyShapesTamperRollbackAndQuotaFailClosed() = runtime(keys = 1).use { runtime ->
        val state = runtime.trustedState()
        assertContentEquals(hex("policy_digest"), state.copyOfRange(4, 36))
        runtime(previous = state).close()
        failure(-2) { runtime(previous = ByteArray(4)) }
        val newer = state.clone().also { it[0] = 127 }
        failure(-3) { runtime(previous = newer) }
        failure(-3) {
            QPeriaptRuntime.fromSignedPolicy(
                field("policy_toml").encodeToByteArray(), hex("signature").also { it[0] = (it[0].toInt() xor 1).toByte() },
                hex("verification_key"),
            )
        }
        failure(-2) { QPeriaptPublicKey(ByteArray(1217)) }
        failure(-2) { QPeriaptCiphertext(ByteArray(1119)) }
        failure(-11) { runtime(keys = 0) }
        runtime.generateKey().use { key ->
            failure(-10) { runtime.generateKey() }
            failure(-2) { runtime.encapsulate(key.publicKey(), ByteArray(65537)) }
            val zeroShare = key.publicKey().encoded().also { it.fill(0, 1184) }
            failure(-6) { runtime.encapsulate(QPeriaptPublicKey(zeroShare), byteArrayOf()) }
        }
        runtime.generateKey().close() // disposal returned the key budget
    }

    @Test
    fun immutablePublicBytesAndRevokedOwners() {
        val runtime = runtime()
        val key = runtime.generateKey()
        val source = key.publicKey().encoded()
        val publicKey = QPeriaptPublicKey(source)
        source.fill(0)
        assertFalse(publicKey.encoded().contentEquals(source))
        publicKey.encoded().fill(0)
        runtime.encapsulate(publicKey, byteArrayOf()).use { enc ->
            val retained = key.decapsulate(enc.ciphertext, byteArrayOf())
            val derived = retained.deriveKey(QPeriaptKeyPurpose.EXPORTER, byteArrayOf(65), byteArrayOf())
            key.close()
            key.close()
            failure(-9) { key.publicKey() }
            equalSecrets(enc.secret, retained) // a secret has its own owner
            runtime.close()
            failure(-9) { retained.exportForProtocol() }
            failure(-9) { enc.secret.exportForProtocol() }
            failure(-9) { runtime.generateKey() }
            failure(-9) { derived.exportForProtocol() }
            derived.close()
            retained.close()
        }
        runtime.close()
    }

    @Test
    fun concurrentAsyncNativeCallsHaveIndependentSecretOwners() = runtime().use { runtime ->
        Executors.newFixedThreadPool(4).use { pool ->
            runtime.generateKeyAsync(pool).get(10, TimeUnit.SECONDS).use { key ->
                runtime.encapsulateAsync(pool, key.publicKey(), byteArrayOf(8, 9)).get(10, TimeUnit.SECONDS).use { enc ->
                    val work = (1..4).map {
                        Callable {
                            repeat(16) {
                                key.decapsulate(enc.ciphertext, byteArrayOf(8, 9)).use { secret ->
                                    equalSecrets(enc.secret, secret)
                                }
                            }
                        }
                    }
                    pool.invokeAll(work, 10, TimeUnit.SECONDS).forEach { it.get() }
                    key.decapsulateAsync(pool, enc.ciphertext, byteArrayOf(8, 9))
                        .get(10, TimeUnit.SECONDS).use { equalSecrets(enc.secret, it) }
                }
            }
        }
    }

    @Test
    fun cancellationDisposesUndeliveredNativeOwnerAndReturnsQuota() = runtime(keys = 1).use { runtime ->
        Executors.newSingleThreadExecutor().use { pool ->
            val produced = CountDownLatch(1)
            val release = CountDownLatch(1)
            val finished = CountDownLatch(1)
            // Deterministic cancellation after native generation, before publication.
            val future = submitOwned(pool, { finished.countDown() }) {
                val key = runtime.generateKey()
                produced.countDown()
                try {
                    check(release.await(10, TimeUnit.SECONDS))
                    key
                } catch (failure: Throwable) {
                    key.close()
                    throw failure
                }
            }
            try {
                assertTrue(produced.await(10, TimeUnit.SECONDS))
                assertTrue(future.cancel(true))
                assertFailsWith<CancellationException> { future.get() }
                failure(-10) { runtime.generateKey() } // cancellation did not dispose a running worker's result
            } finally {
                release.countDown()
            }
            assertTrue(finished.await(10, TimeUnit.SECONDS))
            runtime.generateKey().close()
        }
    }

    @Test
    fun queuedCancellationSkipsNativeWorkAndAsyncInputIsSnapshotted() = runtime(keys = 1).use { runtime ->
        val queued = AtomicReference<Runnable>()
        val executor = Executor { check(queued.compareAndSet(null, it)) }
        val cancelled = runtime.generateKeyAsync(executor)
        assertTrue(cancelled.cancel(false))
        requireNotNull(queued.getAndSet(null)).run()
        runtime.generateKey().use { key ->
            val context = byteArrayOf(1, 2, 3)
            val future = runtime.encapsulateAsync(executor, key.publicKey(), context)
            context.fill(9)
            requireNotNull(queued.getAndSet(null)).run()
            future.get(10, TimeUnit.SECONDS).use { enc ->
                key.decapsulate(enc.ciphertext, byteArrayOf(1, 2, 3)).use { equalSecrets(enc.secret, it) }
            }
        }
    }
}
