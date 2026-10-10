// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.*
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

private fun input(name: String) = Files.readAllBytes(Path.of(System.getProperty("sdk.fixtures"), name))
private fun recovery(name: String) = input("recovery.$name")
private fun refusal(code: Int, operation: () -> Unit) {
    try { operation() } catch (failure: QPeriaptSDKException) {
        check(failure.code == code) { "Expected $code, got ${failure.code}" }
        return
    }
    error("Expected refusal $code")
}
private class Pending : Executor {
    private var task: Runnable? = null
    override fun execute(command: Runnable) { check(task == null); task = command }
    fun run() { val command = checkNotNull(task); task = null; command.run() }
}
private fun <T> privateStore(operation: (String) -> T): T {
    val root = Files.createTempDirectory("qperiapt-installed-policy-",
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toRealPath()
    try { return operation(root.resolve("policy.redb").toString()) }
    finally { check(root.toFile().deleteRecursively()) }
}

internal fun persistentPolicy() = privateStore { path ->
    val queue = Pending()
    val policy = input("enabled.policy")
    val signature = input("enabled.signature")
    val root = input("root")
    val pending = QPeriaptPersistentRuntime.provisionAsync(queue, path, policy, signature, root)
    policy.fill(0); signature.fill(0); root.fill(0)
    queue.run()
    pending.get(10, TimeUnit.SECONDS).use { original ->
        check(original.runtime.isEnabled())
        refusal(-24) { original.runtime.preparePolicyUpdate(input("disabled.policy"), input("disabled.signature")).close() }
        refusal(-20) { QPeriaptPersistentRuntime.open(path, input("enabled.policy"), input("enabled.signature"), input("root")).close() }
        original.runtime.generateKey().use { oldKey ->
            original.update(input("disabled.policy"), input("disabled.signature")).use { disabled ->
                check(!disabled.runtime.isEnabled())
                refusal(-9) { oldKey.publicKey() }
                refusal(-3) { disabled.runtime.generateKey() }
                disabled.update(input("reenabled.policy"), input("reenabled.signature")).use { enabled ->
                    original.close(); disabled.close()
                    enabled.runtime.generateKey().close()
                }
            }
        }
    }
    QPeriaptPersistentRuntime.open(path, input("reenabled.policy"), input("reenabled.signature"), input("root")).use {
        it.runtime.generateKey().close()
    }
    refusal(-3) { QPeriaptPersistentRuntime.open(path, input("enabled.policy"), input("enabled.signature"), input("root")).close() }
}

private fun trust() = QPeriaptPolicyRecoveryTrust(recovery("scope"), recovery("initial_root"), recovery("recovery_root"))

internal fun authorityRecovery() = privateStore { path ->
    val trust = trust()
    check(trust.enrollmentMessage().contentEquals(recovery("enrollment_message")))
    val authorization = QPeriaptPolicyRecoveryAuthorization(recovery("authorization"))
    val queue = Pending()
    QPeriaptPersistentRuntime.provisionRecoverable(path, recovery("initial_policy"), recovery("initial_signature"),
        trust, recovery("enrollment_signature")).use { initial ->
        check(initial.runtime.isEnabled())
        val request = initial.prepareAuthorityRecovery(recovery("operation"), recovery("next_policy"),
            recovery("next_signature"), recovery("incoming_root"))
        check(request.encoded().contentEquals(recovery("request")))
        check(request.generation() == 1uL)
        check(request.approvalMessage().contentEquals(recovery("approval_message")))
        check(request.possessionMessage().contentEquals(recovery("possession_message")))
        val swapped = QPeriaptPolicyRecoveryAuthorization(request, recovery("possession_signature"), recovery("approval_signature"))
        initial.runtime.generateKey().use { oldKey ->
            refusal(-3) { initial.recoverAuthority(swapped, recovery("next_policy"), recovery("next_signature")) }
            oldKey.publicKey()
            val policy = recovery("next_policy")
            val signature = recovery("next_signature")
            val pending = initial.recoverAuthorityAsync(queue, authorization, policy, signature)
            policy.fill(0); signature.fill(0)
            queue.run()
            val result = pending.get(10, TimeUnit.SECONDS)
            check(result is QPeriaptPolicyRecoveryResult.Applied)
            result.runtime.use { disabled ->
                check(!disabled.runtime.isEnabled())
                refusal(-9) { oldKey.publicKey() }
                check(disabled.recoverAuthority(authorization, recovery("next_policy"), recovery("next_signature"))
                    == QPeriaptPolicyRecoveryResult.AlreadyApplied)
                disabled.update(recovery("current_policy"), recovery("current_signature")).use { current ->
                    current.runtime.generateKey().use { live ->
                        check(current.recoverAuthority(authorization, recovery("next_policy"), recovery("next_signature"))
                            == QPeriaptPolicyRecoveryResult.AppliedThenAdvanced)
                        initial.close(); disabled.close()
                        live.publicKey()
                    }
                }
            }
        }
    }
    refusal(-3) { QPeriaptPersistentRuntime.openRecovering(path, recovery("current_policy"), recovery("current_signature"),
        trust, authorization).close() }
    QPeriaptPersistentRuntime.openRecovering(path, recovery("next_policy"), recovery("next_signature"),
        trust, authorization).use { reopened ->
        check(reopened.disposition == QPeriaptPolicyRecoveryDisposition.APPLIED_THEN_ADVANCED)
        check(reopened.runtime.runtime.isEnabled())
        reopened.runtime.runtime.generateKey().close()
    }
}

internal fun legacyRecoveryEnrollment() = privateStore { path ->
    val trust = trust()
    val original = QPeriaptPersistentRuntime.provision(path, recovery("initial_policy"), recovery("initial_signature"), recovery("initial_root"))
    val floor = original.runtime.trustedState()
    original.close()
    refusal(-25) { QPeriaptPersistentRuntime.openRecoverable(path, recovery("initial_policy"), recovery("initial_signature"), trust).close() }
    QPeriaptPersistentRuntime.enrollRecovery(path, recovery("initial_policy"), recovery("initial_signature"),
        trust, recovery("enrollment_signature")).use { enrolled ->
        check(enrolled.runtime.trustedState().contentEquals(floor))
        val result = enrolled.recoverAuthority(QPeriaptPolicyRecoveryAuthorization(recovery("authorization")),
            recovery("next_policy"), recovery("next_signature"))
        check(result is QPeriaptPolicyRecoveryResult.Applied)
        result.runtime.use { check(!it.runtime.isEnabled()) }
    }
    QPeriaptPersistentRuntime.openRecoverable(path, recovery("next_policy"), recovery("next_signature"), trust).use {
        check(!it.runtime.isEnabled())
    }
}
