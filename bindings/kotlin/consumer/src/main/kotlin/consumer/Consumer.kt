// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

private val fixtures = Path.of(System.getProperty("sdk.fixtures"))
private fun bytes(name: String) = Files.readAllBytes(fixtures.resolve(name))
private fun runtime(previous: ByteArray = byteArrayOf(), keys: Int = 32) =
    QPeriaptRuntime.fromSignedPolicy(bytes("enabled.policy"), bytes("enabled.signature"),
        bytes("root"), previous, keys, 4)

private inline fun <reified T : Throwable> fails(operation: () -> Unit): T {
    try { operation() } catch (failure: Throwable) {
        check(failure is T) { "Expected ${T::class.java.name}, got ${failure.javaClass.name}" }
        return failure
    }
    error("Expected ${T::class.java.name}")
}
private fun status(code: Int, operation: () -> Unit) {
    check(fails<QPeriaptSDKException>(operation).code == code)
}
private fun equalSecrets(a: QPeriaptSecret, b: QPeriaptSecret, equal: Boolean = true) {
    val x = a.exportForProtocol()
    val y = b.exportForProtocol()
    try { check(x.contentEquals(y) == equal) } finally { x.fill(0); y.fill(0) }
}
private fun roundtrip(sender: QPeriaptRuntime, key: QPeriaptKey, context: ByteArray) {
    sender.encapsulate(key.publicKey(), context).use { enc ->
        key.decapsulate(enc.ciphertext, context).use { dec ->
            equalSecrets(enc.secret, dec)
            val label = "installed/v1/aes256".encodeToByteArray()
            var previous = byteArrayOf()
            try {
                for (purpose in QPeriaptKeyPurpose.entries) {
                    enc.secret.deriveKey(purpose, label, context).use { left ->
                        dec.deriveKey(purpose, label, context).use { right ->
                            val a = left.exportForProtocol()
                            val b = right.exportForProtocol()
                            try {
                                check(a.size == 32 && a.contentEquals(b) && !a.contentEquals(previous))
                                previous.fill(0)
                                previous = a.clone()
                            } finally { a.fill(0); b.fill(0) }
                        }
                    }
                }
            } finally { previous.fill(0) }
        }
        val damaged = enc.ciphertext.encoded().also { it[0] = (it[0].toInt() xor 1).toByte() }
        key.decapsulate(QPeriaptCiphertext(damaged), context).use { equalSecrets(enc.secret, it, false) }
    }
}

private fun ownersAndPolicy() = runtime().use { sender ->
    runtime().use { receiver ->
        receiver.generateKey().use { key ->
            for (size in listOf(0, 32, 65536)) roundtrip(sender, key, ByteArray(size) { (it % 251).toByte() })
            val plaintext = QPeriaptExpert.exportExpanded(key)
            try {
                check(plaintext.size == 2440)
                QPeriaptExpert.importExpanded(plaintext, receiver).use { imported ->
                    check(key.publicKey().encoded().contentEquals(imported.publicKey().encoded()))
                    roundtrip(sender, imported, byteArrayOf(42))
                }
                plaintext[0] = 0
                status(-13) { QPeriaptExpert.importExpanded(plaintext, receiver) }
            } finally { plaintext.fill(0) }
            receiver.preparePolicyUpdate(bytes("disabled.policy"), bytes("disabled.signature")).use { update ->
                val states = update.states()
                check(states.previous().contentEquals(receiver.trustedState()))
                // In-memory fixture only. This does not claim durable host storage.
                val stored = states.next()
                update.activateAfterPersisting().use { disabled ->
                    check(!disabled.isEnabled())
                    status(-3) { disabled.generateKey() }
                    status(-9) { key.publicKey() }
                    status(-9) { receiver.trustedState() }
                    status(-9) { update.activateAfterPersisting() }
                    QPeriaptRuntime.fromSignedPolicy(bytes("disabled.policy"), bytes("disabled.signature"),
                        bytes("root"), stored, 32, 4).use { recovered ->
                        check(!recovered.isEnabled())
                        recovered.preparePolicyUpdate(bytes("reenabled.policy"), bytes("reenabled.signature")).use { enable ->
                            val nextState = enable.states().next()
                            enable.activateAfterPersisting().use { next ->
                                check(next.isEnabled() && next.trustedState().contentEquals(nextState))
                                next.generateKey().close()
                            }
                        }
                    }
                }
            }
        }
    }
}

private class Queued : Executor {
    private var task: Runnable? = null
    override fun execute(command: Runnable) { check(task == null); task = command }
    fun run() { val next = checkNotNull(task); task = null; next.run() }
}
private fun asynchronousBoundaries() = runtime(keys = 1).use { owner ->
    val queue = Queued()
    val cancelled = owner.generateKeyAsync(queue)
    check(cancelled.cancel(true))
    queue.run()
    fails<CancellationException> { cancelled.get(5, TimeUnit.SECONDS) }
    fails<RejectedExecutionException> { owner.generateKeyAsync(Executor { throw RejectedExecutionException("full") }) }
    owner.generateKey().use { key ->
        status(-10) { owner.generateKey() }
        val frozen = byteArrayOf(1, 2, 3)
        val callerInput = frozen.clone()
        val pending = owner.encapsulateAsync(queue, key.publicKey(), callerInput)
        callerInput.fill(9)
        queue.run()
        pending.get(5, TimeUnit.SECONDS).use { enc ->
            key.decapsulate(enc.ciphertext, frozen).use { equalSecrets(enc.secret, it) }
        }
        val pool = ThreadPoolExecutor(2, 2, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(4))
        val start = CountDownLatch(1)
        try {
            val futures = (0 until 2).map { worker -> pool.submit {
                check(start.await(5, TimeUnit.SECONDS))
                repeat(8) { roundtrip(owner, key, byteArrayOf(worker.toByte(), it.toByte())) }
            } }
            start.countDown()
            futures.forEach { it.get(30, TimeUnit.SECONDS) }
        } finally {
            start.countDown()
            pool.shutdown()
            check(pool.awaitTermination(30, TimeUnit.SECONDS))
        }
        owner.close()
        owner.close()
        status(-9) { key.publicKey() }
    }
}

fun main() {
    val actual = Path.of(QPeriaptRuntime::class.java.protectionDomain.codeSource.location.toURI()).toRealPath()
    check(Files.isSameFile(actual, Path.of(System.getProperty("sdk.expectedJar"))))
    check(QPeriaptRuntime::class.java.`package`.implementationVersion == "0.2.0")
    check(QPeriaptHybrid.runtimeAbiVersion() == 2)
    check(QPeriaptHybrid.runtimeVersion() == "0.2.0")
    ownersAndPolicy()
    println("INSTALLED_KOTLIN_OWNER_POLICY_KDF_PASS")
    asynchronousBoundaries()
    println("INSTALLED_KOTLIN_CANCELLATION_CONCURRENCY_PASS")
    val badSignature = bytes("enabled.signature").also { it[0] = (it[0].toInt() xor 1).toByte() }
    status(-3) { QPeriaptRuntime.fromSignedPolicy(bytes("enabled.policy"), badSignature, bytes("root")) }
    status(-3) { runtime(bytes("future-state")) }
    println("INSTALLED_KOTLIN_TAMPER_ROLLBACK_PASS")
}
