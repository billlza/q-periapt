package dev.qperiapt

import java.io.File
import java.lang.ref.Reference
import java.lang.ref.WeakReference
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.HexFormat
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QPeriaptPersistentRuntimeTest {
    private class Policy(name: String) {
        private val json = File("../$name").readText()
        private fun field(name: String): String = requireNotNull(
            Regex("\"$name\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").find(json),
        ).groupValues[1].replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\")
        val policy = field("policy_toml").encodeToByteArray()
        private fun hex(name: String): ByteArray = HexFormat.of().parseHex(requireNotNull(
            Regex("\"$name\"\\s*:\\s*\"([0-9a-f]*)\"").find(json),
        ).groupValues[1])
        val signature = hex("signature")
        val root = hex("verification_key")
        fun provision(path: Path) = QPeriaptPersistentRuntime.provision(path.toString(), policy, signature, root)
        fun open(path: Path) = QPeriaptPersistentRuntime.open(path.toString(), policy, signature, root)
    }

    private fun failure(code: Int, operation: () -> Unit) =
        assertEquals(code, assertFailsWith<QPeriaptSDKException>(block = operation).code)

    private fun withStore(operation: (Path) -> Unit) {
        val directory = Files.createTempDirectory("qperiapt-kotlin-persistence-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toRealPath()
        try {
            operation(directory.resolve("policy.redb"))
        } finally {
            assertTrue(directory.toFile().deleteRecursively())
        }
    }

    @Test
    fun originalStoreRevokesOldOwnersAndRecoversLatestPolicy() = withStore { path ->
        val initial = Policy("signed-policy-vectors.json")
        val revoked = Policy("sdk-policy-revocation-vectors.json")
        val enabled = Policy("sdk-policy-update-vectors.json")
        initial.provision(path).use { original ->
            assertTrue(original.runtime.isEnabled())
            failure(-20) { initial.open(path).close() }
            failure(-19) { initial.provision(path).close() }
            failure(-24) { original.runtime.preparePolicyUpdate(revoked.policy, revoked.signature).close() }
            original.runtime.generateKey().use { key ->
                val wrong = revoked.signature.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
                failure(-3) { original.update(revoked.policy, wrong).close() }
                assertTrue(original.runtime.isEnabled())
                key.publicKey()
                original.update(revoked.policy, revoked.signature).use { disabled ->
                    assertFalse(disabled.runtime.isEnabled())
                    failure(-9) { original.runtime.isEnabled() }
                    failure(-9) { key.publicKey() }
                    original.close()
                    assertFalse(disabled.runtime.isEnabled())
                    failure(-3) { disabled.runtime.generateKey() }
                    disabled.update(enabled.policy, enabled.signature).use { successor ->
                        assertTrue(successor.runtime.isEnabled())
                        disabled.close()
                        successor.runtime.generateKey().close()
                        val state = successor.runtime.trustedState()
                        successor.close()
                        enabled.open(path).use { reopened ->
                            assertContentEquals(state, reopened.runtime.trustedState())
                            reopened.runtime.generateKey().close()
                        }
                    }
                }
            }
        }
        failure(-3) { initial.open(path).close() }
        enabled.open(path).use { assertTrue(it.runtime.isEnabled()) }
    }

    @Test
    fun missingStoreIsNotProvisionedAndInvalidInputDoesNotWrite() = withStore { path ->
        val initial = Policy("signed-policy-vectors.json")
        failure(-19) { initial.open(path).close() }
        assertFalse(Files.exists(path))
        for (bad in listOf("", "x\u0000y", "\ud800", "a".repeat(4097), "界".repeat(1366))) {
            failure(-2) { QPeriaptPersistentRuntime.provision(bad, initial.policy, initial.signature, initial.root).close() }
        }
        failure(-11) {
            QPeriaptPersistentRuntime.provision(path.toString(), initial.policy, initial.signature, initial.root, 0).close()
        }
        failure(-2) {
            QPeriaptPersistentRuntime.provision(path.toString(), initial.policy, ByteArray(3308), initial.root).close()
        }
        assertFalse(Files.exists(path))
        initial.provision(path).use { assertTrue(it.runtime.isEnabled()) }
    }

    @Test
    fun explicitRuntimeCloseRevokesChildrenAndReleasesStorage() = withStore { path ->
        val initial = Policy("signed-policy-vectors.json")
        initial.provision(path).use { store ->
            store.runtime.generateKey().use { key ->
                store.runtime.close()
                failure(-9) { key.publicKey() }
                initial.open(path).use { replacement ->
                    store.close()
                    replacement.runtime.generateKey().close()
                }
            }
        }
    }

    private fun retainedKey(path: Path, policy: Policy): Pair<QPeriaptKey, WeakReference<SdkHandle>> {
        val store = policy.provision(path)
        return store.runtime.generateKey() to WeakReference(store.runtime.owned)
    }

    @Test
    fun retainedClosedChildAllowsAbandonedStoreToBeReopened() = withStore { path ->
        val initial = Policy("signed-policy-vectors.json")
        val (key, parent) = retainedKey(path, initial)
        try {
            repeat(8) {
                System.gc()
                Thread.sleep(25)
            }
            // A live child must keep its runtime and its persistent lease alive.
            assertTrue(parent.get() != null)
            key.publicKey()
            failure(-20) { initial.open(path).close() }
            key.close()
            var reopened = false
            var lastBusy: QPeriaptSDKException? = null
            for (attempt in 0 until 64) {
                System.gc()
                Thread.sleep(25)
                try {
                    initial.open(path).use { it.runtime.generateKey().close() }
                    reopened = true
                    break
                } catch (failure: QPeriaptSDKException) {
                    if (failure.code != -20) throw failure
                    lastBusy = failure
                }
            }
            assertTrue(reopened, "Closed child retained the abandoned store lease: $lastBusy")
            assertEquals(null, parent.get())
        } finally {
            // Retain the closed alias throughout the actual reopen attempts.
            Reference.reachabilityFence(key)
            key.close()
            parent.get()?.close()
        }
    }

    private fun retainedSecret(path: Path, policy: Policy, derive: Boolean): Pair<AutoCloseable, WeakReference<SdkHandle>> {
        val store = policy.provision(path)
        val parent = WeakReference(store.runtime.owned)
        val secret = store.runtime.generateKey().use { key ->
            store.runtime.encapsulate(key.publicKey(), byteArrayOf(7)).use { encapsulated ->
                key.decapsulate(encapsulated.ciphertext, byteArrayOf(7))
            }
        }
        return if (derive) {
            secret.use { it.deriveKey(QPeriaptKeyPurpose.EXPORTER, byteArrayOf(65), byteArrayOf(7)) } to parent
        } else secret to parent
    }

    private fun awaitReopened(path: Path, policy: Policy) {
        for (attempt in 0 until 64) {
            System.gc()
            Thread.sleep(25)
            try {
                policy.open(path).use { it.runtime.generateKey().close() }
                return
            } catch (failure: QPeriaptSDKException) {
                if (failure.code != -20 || attempt == 63) throw failure
            }
        }
    }

    @Test
    fun independentlyOwnedSecretsAndDerivedKeysRetainOnlyTheirLiveLease() {
        for (derive in listOf(false, true)) withStore { path ->
            val initial = Policy("signed-policy-vectors.json")
            val (child, parent) = retainedSecret(path, initial, derive)
            try {
                repeat(8) { System.gc(); Thread.sleep(25) }
                val exported = when (child) {
                    is QPeriaptSecret -> child.exportForProtocol()
                    is QPeriaptDerivedKey -> child.exportForProtocol()
                    else -> error("Unexpected test owner")
                }
                assertEquals(32, exported.size)
                exported.fill(0)
                failure(-20) { initial.open(path).close() }
                child.close()
                awaitReopened(path, initial)
                assertEquals(null, parent.get())
            } finally {
                Reference.reachabilityFence(child)
                child.close()
                parent.get()?.close()
            }
        }
    }

    @Test
    fun inFlightParentSnapshotSurvivesCloseAndTransfersToReturnedOwner() = withStore { path ->
        val initial = Policy("signed-policy-vectors.json")
        val (key, parent) = retainedKey(path, initial)
        val admitted = CountDownLatch(1)
        val proceed = CountDownLatch(1)
        try {
            Executors.newSingleThreadExecutor().use { worker ->
                val future = worker.submit<QPeriaptKey> {
                    // Stop at the shared JVM owner boundary, with real native owners.
                    // This checks lifetime transfer; it is not an injected Rust call.
                    key.owned.withParentHandle { _, snapshot ->
                        admitted.countDown()
                        check(proceed.await(10, TimeUnit.SECONDS))
                        QPeriaptRuntime.adopt(requireNotNull(snapshot)).generateKey()
                    }
                }
                try {
                    assertTrue(admitted.await(10, TimeUnit.SECONDS))
                    key.close()
                    repeat(8) { System.gc(); Thread.sleep(25) }
                    failure(-20) { initial.open(path).close() }
                    proceed.countDown()
                    future.get(10, TimeUnit.SECONDS).use { returned ->
                        repeat(8) { System.gc(); Thread.sleep(25) }
                        returned.publicKey()
                        failure(-20) { initial.open(path).close() }
                        returned.close()
                        awaitReopened(path, initial)
                        assertEquals(null, parent.get())
                        Reference.reachabilityFence(returned)
                    }
                } finally {
                    proceed.countDown()
                }
            }
        } finally {
            Reference.reachabilityFence(key)
            key.close()
            parent.get()?.close()
        }
    }
}
