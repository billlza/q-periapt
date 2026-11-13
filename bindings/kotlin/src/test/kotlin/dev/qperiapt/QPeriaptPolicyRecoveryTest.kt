// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.HexFormat
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class QPeriaptPolicyRecoveryTest {
    private class Fixture {
        private val fields = Regex("\"([a-z_]+)\"\\s*:\\s*\"([0-9a-f]*)\"")
            .findAll(File("../sdk-policy-recovery-vectors.json").readText())
            .associate { it.groupValues[1] to HexFormat.of().parseHex(it.groupValues[2]) }
        init { assertEquals(19, fields.size) }
        fun bytes(name: String): ByteArray = requireNotNull(fields[name]).clone()
        fun trust() = QPeriaptPolicyRecoveryTrust(bytes("scope"), bytes("initial_root"), bytes("recovery_root"))
        fun authorization() = QPeriaptPolicyRecoveryAuthorization(bytes("authorization"))
        fun provision(path: Path) = QPeriaptPersistentRuntime.provisionRecoverable(path.toString(), bytes("initial_policy"),
            bytes("initial_signature"), trust(), bytes("enrollment_signature"))
        fun openRecovering(path: Path) = QPeriaptPersistentRuntime.openRecovering(path.toString(), bytes("next_policy"),
            bytes("next_signature"), trust(), authorization())
        fun recover(owner: QPeriaptPersistentRuntime) = owner.recoverAuthority(authorization(), bytes("next_policy"), bytes("next_signature"))
    }

    private fun failure(code: Int, operation: () -> Unit) =
        assertEquals(code, assertFailsWith<QPeriaptSDKException>(block = operation).code)

    private fun withStore(operation: (Path) -> Unit) {
        val directory = Files.createTempDirectory("qperiapt-kotlin-recovery-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toRealPath()
        try { operation(directory.resolve("policy.redb")) }
        finally { assertTrue(directory.toFile().deleteRecursively()) }
    }

    @Test
    fun canonicalRecoveryStatementsAreImmutableAndKeepSignerRolesDistinct() {
        val f = Fixture()
        val scope = f.bytes("scope")
        val initial = f.bytes("initial_root")
        val recovery = f.bytes("recovery_root")
        val trust = QPeriaptPolicyRecoveryTrust(scope, initial, recovery)
        scope.fill(0); initial.fill(0); recovery.fill(0)
        assertContentEquals(f.bytes("scope"), trust.scope())
        assertContentEquals(f.bytes("initial_root"), trust.initialRoot())
        assertContentEquals(f.bytes("recovery_root"), trust.recoveryRoot())
        assertContentEquals(f.bytes("enrollment_message"), trust.enrollmentMessage())
        trust.enrollmentMessage().fill(0)
        assertContentEquals(f.bytes("enrollment_message"), trust.enrollmentMessage())
        val encoded = f.bytes("request")
        val request = QPeriaptPolicyRecoveryRequest(encoded)
        encoded.fill(0)
        assertContentEquals(f.bytes("request"), request.encoded())
        assertEquals(1uL, request.generation())
        assertContentEquals(f.bytes("operation"), request.operation())
        assertContentEquals(f.bytes("incoming_root"), request.incomingRoot())
        assertContentEquals(byteArrayOf(-1, -1, -1, -1), request.states().previous().copyOfRange(0, 4))
        assertContentEquals(byteArrayOf(0, 0, 0, 1), request.states().next().copyOfRange(0, 4))
        assertContentEquals(f.bytes("approval_message"), request.approvalMessage())
        assertContentEquals(f.bytes("possession_message"), request.possessionMessage())
        assertFalse(request.approvalMessage().contentEquals(request.possessionMessage()))
        val approval = f.bytes("approval_signature")
        val possession = f.bytes("possession_signature")
        val auth = QPeriaptPolicyRecoveryAuthorization(request, approval, possession)
        approval.fill(0); possession.fill(0); auth.encoded().fill(0)
        assertContentEquals(f.bytes("authorization"), auth.encoded())
        failure(-2) { QPeriaptPolicyRecoveryRequest(ByteArray(2167)) }
        failure(-3) { QPeriaptPolicyRecoveryRequest(f.bytes("request").also { it[0] = 0 }) }
        failure(-2) { QPeriaptPolicyRecoveryAuthorization(ByteArray(8787)) }
        failure(-3) { QPeriaptPolicyRecoveryTrust(ByteArray(32), trust.initialRoot(), trust.recoveryRoot()) }
        failure(-3) { QPeriaptPolicyRecoveryTrust(trust.scope(), trust.initialRoot(), trust.initialRoot()) }
    }

    @Test
    fun exhaustedVersionRecoversDisablesThenAdvancesWithoutReplayingOwnership() = withStore { path ->
        val f = Fixture()
        f.provision(path).use { original ->
            assertContentEquals(byteArrayOf(-1, -1, -1, -1), original.runtime.trustedState().copyOfRange(0, 4))
            original.runtime.generateKey().use { oldKey ->
                val oldPublic = oldKey.publicKey().encoded()
                val request = original.prepareAuthorityRecovery(f.bytes("operation"), f.bytes("next_policy"),
                    f.bytes("next_signature"), f.bytes("incoming_root"))
                assertContentEquals(f.bytes("request"), request.encoded())
                val swapped = QPeriaptPolicyRecoveryAuthorization(request, f.bytes("possession_signature"), f.bytes("approval_signature"))
                failure(-3) { original.recoverAuthority(swapped, f.bytes("next_policy"), f.bytes("next_signature")).discardReturnedOwner() }
                assertContentEquals(oldPublic, oldKey.publicKey().encoded())
                val applied = assertIs<QPeriaptPolicyRecoveryResult.Applied>(f.recover(original))
                applied.runtime.use { disabled ->
                    assertFalse(disabled.runtime.isEnabled())
                    failure(-9) { oldKey.publicKey() }
                    failure(-9) { original.runtime.isEnabled() }
                    original.close()
                    assertEquals(QPeriaptPolicyRecoveryResult.AlreadyApplied, f.recover(disabled))
                    disabled.update(f.bytes("current_policy"), f.bytes("current_signature")).use { current ->
                        current.runtime.generateKey().use { key ->
                            val public = key.publicKey().encoded()
                            assertEquals(QPeriaptPolicyRecoveryResult.AppliedThenAdvanced, f.recover(current))
                            assertContentEquals(public, key.publicKey().encoded())
                        }
                    }
                }
            }
        }
        failure(-3) { QPeriaptPersistentRuntime.openRecovering(path.toString(), f.bytes("current_policy"),
            f.bytes("current_signature"), f.trust(), f.authorization()).close() }
        f.openRecovering(path).use { reopened ->
            assertEquals(QPeriaptPolicyRecoveryDisposition.APPLIED_THEN_ADVANCED, reopened.disposition)
            assertContentEquals(byteArrayOf(0, 0, 0, 2), reopened.runtime.runtime.trustedState().copyOfRange(0, 4))
            assertTrue(reopened.runtime.runtime.isEnabled())
        }
        QPeriaptPersistentRuntime.openRecoverable(path.toString(), f.bytes("current_policy"),
            f.bytes("current_signature"), f.trust()).use { assertTrue(it.runtime.isEnabled()) }
        failure(-3) { QPeriaptPersistentRuntime.openRecoverable(path.toString(), f.bytes("next_policy"), f.bytes("next_signature"), f.trust()).close() }
    }

    @Test
    fun explicitLegacyEnrollmentPreservesOriginalFloorAndCannotResetRecoveredRoot() = withStore { path ->
        val f = Fixture()
        val legacy = QPeriaptPersistentRuntime.provision(path.toString(), f.bytes("initial_policy"), f.bytes("initial_signature"), f.bytes("initial_root"))
        val floor = legacy.runtime.trustedState()
        try {
            failure(-20) { QPeriaptPersistentRuntime.enrollRecovery(path.toString(), f.bytes("initial_policy"),
                f.bytes("initial_signature"), f.trust(), f.bytes("enrollment_signature")).close() }
            assertContentEquals(floor, legacy.runtime.trustedState())
        } finally { legacy.close() }
        failure(-25) { QPeriaptPersistentRuntime.openRecoverable(path.toString(), f.bytes("initial_policy"), f.bytes("initial_signature"), f.trust()).close() }
        repeat(2) {
            QPeriaptPersistentRuntime.enrollRecovery(path.toString(), f.bytes("initial_policy"), f.bytes("initial_signature"),
                f.trust(), f.bytes("enrollment_signature")).use { assertContentEquals(floor, it.runtime.trustedState()) }
        }
        failure(-25) { QPeriaptPersistentRuntime.open(path.toString(), f.bytes("initial_policy"), f.bytes("initial_signature"), f.bytes("initial_root")).close() }
        QPeriaptPersistentRuntime.openRecoverable(path.toString(), f.bytes("initial_policy"), f.bytes("initial_signature"), f.trust()).use { owner ->
            assertIs<QPeriaptPolicyRecoveryResult.Applied>(f.recover(owner)).runtime.close()
        }
        failure(-3) { QPeriaptPersistentRuntime.enrollRecovery(path.toString(), f.bytes("initial_policy"),
            f.bytes("initial_signature"), f.trust(), f.bytes("enrollment_signature")).close() }
        f.openRecovering(path).use { assertEquals(QPeriaptPolicyRecoveryDisposition.ALREADY_APPLIED, it.disposition) }
    }

    @Test
    fun publicAsyncCallsSnapshotBeforeDispatchAndQueuedCancellationDoesNotProvision() = withStore { path ->
        val f = Fixture()
        val queued = ArrayDeque<Runnable>()
        val executor = Executor { queued.addLast(it) }
        val cancelled = QPeriaptPersistentRuntime.provisionRecoverableAsync(executor, path.toString(), f.bytes("initial_policy"),
            f.bytes("initial_signature"), f.trust(), f.bytes("enrollment_signature"))
        assertTrue(cancelled.cancel(true)); queued.removeFirst().run()
        assertFalse(Files.exists(path))
        val policy = f.bytes("initial_policy"); val signature = f.bytes("initial_signature"); val proof = f.bytes("enrollment_signature")
        val pending = QPeriaptPersistentRuntime.provisionRecoverableAsync(executor, path.toString(), policy, signature, f.trust(), proof)
        policy.fill(0); signature.fill(0); proof.fill(0)
        assertFalse(Files.exists(path)); queued.removeFirst().run()
        pending.get(10, TimeUnit.SECONDS).use { original ->
            val operation = f.bytes("operation"); val next = f.bytes("next_policy"); val signed = f.bytes("next_signature"); val root = f.bytes("incoming_root")
            val prepared = original.prepareAuthorityRecoveryAsync(executor, operation, next, signed, root)
            operation.fill(0); next.fill(0); signed.fill(0); root.fill(0)
            queued.removeFirst().run()
            assertContentEquals(f.bytes("request"), prepared.get(10, TimeUnit.SECONDS).encoded())
            val nextPolicy = f.bytes("next_policy"); val nextSignature = f.bytes("next_signature")
            val apply = original.recoverAuthorityAsync(executor, f.authorization(), nextPolicy, nextSignature)
            nextPolicy.fill(0); nextSignature.fill(0); queued.removeFirst().run()
            assertIs<QPeriaptPolicyRecoveryResult.Applied>(apply.get(10, TimeUnit.SECONDS)).runtime.use { disabled ->
                assertFalse(disabled.runtime.isEnabled())
                val current = f.bytes("current_policy"); val currentSignature = f.bytes("current_signature")
                val update = disabled.updateAsync(executor, current, currentSignature)
                current.fill(0); currentSignature.fill(0); queued.removeFirst().run()
                update.get(10, TimeUnit.SECONDS).use { assertTrue(it.runtime.isEnabled()) }
            }
        }
        val reopened = QPeriaptPersistentRuntime.openRecoveringAsync(executor, path.toString(), f.bytes("next_policy"),
            f.bytes("next_signature"), f.trust(), f.authorization())
        queued.removeFirst().run()
        reopened.get(10, TimeUnit.SECONDS).use { assertEquals(QPeriaptPolicyRecoveryDisposition.APPLIED_THEN_ADVANCED, it.disposition) }
    }

    /** Hold the shared result handoff after a real public native operation, never mock the native call. */
    private fun <T> cancelAfterNative(discard: (T) -> Unit, operation: () -> T) {
        val reached = CountDownLatch(1); val release = CountDownLatch(1); val finished = CountDownLatch(1)
        val worker = Executors.newSingleThreadExecutor()
        val executor = Executor { task -> worker.execute { try { task.run() } finally { finished.countDown() } } }
        try {
            val future = submitSdkOperation(executor, discardResult = discard) {
                val result = operation()
                reached.countDown()
                if (!release.await(10, TimeUnit.SECONDS)) { discard(result); error("test handoff deadline") }
                result
            }
            assertTrue(reached.await(10, TimeUnit.SECONDS))
            assertTrue(future.cancel(true)); release.countDown()
            assertTrue(finished.await(10, TimeUnit.SECONDS))
            assertFailsWith<CancellationException> { future.get() }
        } finally {
            release.countDown(); worker.shutdown()
            assertTrue(worker.awaitTermination(10, TimeUnit.SECONDS))
        }
    }

    @Test
    fun cancellationAfterCommitDisposesNewOwnerButKeepsReplayedOwner() = withStore { path ->
        val f = Fixture()
        f.provision(path).use { original ->
            cancelAfterNative({ it.discardReturnedOwner() }) { f.recover(original) }
            failure(-9) { original.runtime.isEnabled() }
        }
        f.openRecovering(path).use { reopened ->
            assertEquals(QPeriaptPolicyRecoveryDisposition.ALREADY_APPLIED, reopened.disposition)
            cancelAfterNative({ it.discardReturnedOwner() }) { f.recover(reopened.runtime) }
            assertFalse(reopened.runtime.runtime.isEnabled())
            reopened.runtime.update(f.bytes("current_policy"), f.bytes("current_signature")).use { current ->
                current.runtime.generateKey().use { key ->
                    val public = key.publicKey().encoded()
                    cancelAfterNative({ it.discardReturnedOwner() }) { f.recover(current) }
                    assertContentEquals(public, key.publicKey().encoded())
                }
            }
        }
    }

    @Test
    fun cancelledEnrollmentRetainsDurableOriginalConfiguration() = withStore { path ->
        val f = Fixture()
        val floor = QPeriaptPersistentRuntime.provision(path.toString(), f.bytes("initial_policy"),
            f.bytes("initial_signature"), f.bytes("initial_root")).use { it.runtime.trustedState() }
        cancelAfterNative({ it.close() }) {
            QPeriaptPersistentRuntime.enrollRecovery(path.toString(), f.bytes("initial_policy"),
                f.bytes("initial_signature"), f.trust(), f.bytes("enrollment_signature"))
        }
        failure(-25) { QPeriaptPersistentRuntime.open(path.toString(), f.bytes("initial_policy"),
            f.bytes("initial_signature"), f.bytes("initial_root")).close() }
        QPeriaptPersistentRuntime.openRecoverable(path.toString(), f.bytes("initial_policy"),
            f.bytes("initial_signature"), f.trust()).use { assertContentEquals(floor, it.runtime.trustedState()) }
    }
}
