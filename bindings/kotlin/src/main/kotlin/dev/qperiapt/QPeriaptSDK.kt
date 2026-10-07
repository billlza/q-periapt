// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout.ADDRESS
import java.lang.foreign.ValueLayout.JAVA_BYTE
import java.lang.foreign.ValueLayout.JAVA_INT
import java.lang.foreign.ValueLayout.JAVA_LONG
import java.lang.ref.Cleaner
import java.lang.ref.Reference
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import java.util.concurrent.Future
import java.util.logging.Level
import java.util.logging.Logger

/** Native ABI 2 status, with no secret bytes included in messages. */
class QPeriaptSDKException(val operation: String, val code: Int) :
    RuntimeException("$operation rc=$code")

private fun checkStatus(operation: String, status: Int) {
    if (status != 0) throw QPeriaptSDKException(operation, status)
}

/** Immutable public bytes. No constructor or getter accepts a private key. */
class QPeriaptPublicKey(bytes: ByteArray) {
    private val value: ByteArray
    init {
        checkStatus("public key", if (bytes.size == 1216) 0 else -2)
        value = bytes.clone()
    }
    fun encoded(): ByteArray = value.clone()
}

/** Correct-length invalid PQ ciphertexts retain ML-KEM implicit rejection. */
class QPeriaptCiphertext(bytes: ByteArray) {
    private val value: ByteArray
    init {
        checkStatus("ciphertext", if (bytes.size == 1120) 0 else -2)
        value = bytes.clone()
    }
    fun encoded(): ByteArray = value.clone()
}

/**
 * Immutable verified configuration. Pin the root and atomically persist
 * [trustedState] before use. This API is not a persistent authorization service.
 *
 * All owners are thread-safe references to native objects. Use `use`/`close` for
 * deterministic disposal; the JVM Cleaner is only a nondeterministic backstop.
 */
class QPeriaptRuntime private constructor(@get:JvmSynthetic internal val owned: SdkHandle) : AutoCloseable {
    companion object {
        @JvmSynthetic
        internal fun adopt(owned: SdkHandle) = QPeriaptRuntime(owned)

        fun fromSignedPolicy(
            policy: ByteArray, signature: ByteArray, trustRoot: ByteArray,
            previousState: ByteArray = byteArrayOf(), maxLiveKeys: Int = 32, maxInFlight: Int = 4,
        ): QPeriaptRuntime = NativeSdk.runtime(
            policy, signature, trustRoot, previousState, maxLiveKeys, maxInFlight,
        ) { QPeriaptRuntime(it) }
    }

    fun trustedState(): ByteArray = owned.withHandle { NativeSdk.state(it) }
    /** A verified policy may disable the fixed suite while permitting future policy updates. */
    fun isEnabled(): Boolean = owned.withHandle { NativeSdk.enabled(it) }
    fun preparePolicyUpdate(policy: ByteArray, signature: ByteArray): QPeriaptPolicyUpdate =
        owned.withHandle { NativeSdk.prepareUpdate(it, owned, policy, signature) }

    fun generateKey(): QPeriaptKey = owned.withHandle { handle ->
        NativeSdk.generate(handle, owned, QPeriaptKey::adopt)
    }

    fun encapsulate(peer: QPeriaptPublicKey, applicationContext: ByteArray): QPeriaptSDKEncapsulation =
        owned.withHandle { handle ->
            NativeSdk.encapsulate(handle, owned, peer.encoded(), applicationContext)
        }

    /** Revoke this runtime and every child. In-flight native leases finish safely. */
    override fun close() = owned.close()

    /** Caller supplies the executor and its queue/concurrency bound. */
    fun generateKeyAsync(executor: Executor): Future<QPeriaptKey> =
        submitOwned(executor) { generateKey() }

    fun encapsulateAsync(
        executor: Executor, peer: QPeriaptPublicKey, applicationContext: ByteArray,
    ): Future<QPeriaptSDKEncapsulation> {
        NativeSdk.checkContext(applicationContext)
        // Freeze mutable caller input before scheduling, never on a later worker.
        val context = applicationContext.clone()
        return submitOwned(executor, { context.fill(0) }) { encapsulate(peer, context) }
    }
}

/** One native key owner. Copying the JVM reference aliases, never copies, its key. */
class QPeriaptKey private constructor(@get:JvmSynthetic internal val owned: SdkHandle) : AutoCloseable {
    companion object {
        @JvmSynthetic
        internal fun adopt(owned: SdkHandle) = QPeriaptKey(owned)
    }
    fun publicKey(): QPeriaptPublicKey = owned.withHandle { QPeriaptPublicKey(NativeSdk.publicKey(it)) }
    fun decapsulate(ciphertext: QPeriaptCiphertext, applicationContext: ByteArray): QPeriaptSecret =
        owned.withHandle { NativeSdk.decapsulate(it, owned.parent, ciphertext.encoded(), applicationContext) }
    override fun close() = owned.close()

    fun decapsulateAsync(
        executor: Executor, ciphertext: QPeriaptCiphertext, applicationContext: ByteArray,
    ): Future<QPeriaptSecret> {
        NativeSdk.checkContext(applicationContext)
        val context = applicationContext.clone()
        return submitOwned(executor, { context.fill(0) }) { decapsulate(ciphertext, context) }
    }
}

/** Explicit plaintext transfer. The caller protects and erases every exported/input array. */
object QPeriaptExpert {
    fun importExpanded(bytes: ByteArray, runtime: QPeriaptRuntime): QPeriaptKey =
        runtime.owned.withHandle { NativeSdk.importExpanded(it, runtime.owned, bytes) }
    fun exportExpanded(key: QPeriaptKey): ByteArray = key.owned.withHandle { NativeSdk.exportExpanded(it) }
}

/** Public states for a root-scoped, atomic host compare-and-persist operation. */
class QPeriaptPolicyStates private constructor(bytes: ByteArray) {
    companion object {
        @JvmSynthetic
        internal fun decode(bytes: ByteArray) = QPeriaptPolicyStates(bytes)
    }
    private val before = bytes.copyOfRange(0, 36)
    private val after = bytes.copyOfRange(36, 72)
    fun previous(): ByteArray = before.clone()
    fun next(): ByteArray = after.clone()
}

/** A prepared policy with no key operations. Close cancels; it cannot undo host persistence. */
class QPeriaptPolicyUpdate private constructor(private val owned: SdkHandle) : AutoCloseable {
    companion object {
        @JvmSynthetic
        internal fun adopt(owned: SdkHandle) = QPeriaptPolicyUpdate(owned)
    }
    fun states(): QPeriaptPolicyStates = owned.withHandle { NativeSdk.updateStates(it) }
    /**
     * Call only after atomic persistence. Revokes old owners and returns an independent,
     * possibly disabled runtime. On failure after persistence, stop old-runtime use and
     * recover from the signed policy and persisted state; the SDK cannot inspect storage.
     */
    fun activateAfterPersisting(): QPeriaptRuntime = owned.withHandle { NativeSdk.activateUpdate(it) }
    override fun close() = owned.close()
}

/** Ciphertext and a reference to one secret owner; close disposes that secret. */
class QPeriaptSDKEncapsulation private constructor(
    val ciphertext: QPeriaptCiphertext, val secret: QPeriaptSecret,
) : AutoCloseable {
    companion object {
        @JvmSynthetic
        internal fun create(ciphertext: QPeriaptCiphertext, secret: QPeriaptSecret) =
            QPeriaptSDKEncapsulation(ciphertext, secret)
    }
    override fun close() = secret.close()
}

/** Global initiator/responder directions, shared by both protocol peers. */
enum class QPeriaptKeyPurpose(internal val code: Int) {
    INITIATOR_TRAFFIC(1), RESPONDER_TRAFFIC(2),
    INITIATOR_CONFIRMATION(3), RESPONDER_CONFIRMATION(4), EXPORTER(5),
}

/** No automatic secret getter; derivation retains a distinct native key owner. */
class QPeriaptSecret private constructor(private val owned: SdkHandle) : AutoCloseable {
    companion object {
        @JvmSynthetic
        internal fun adopt(owned: SdkHandle) = QPeriaptSecret(owned)
    }
    fun deriveKey(purpose: QPeriaptKeyPurpose, protocolLabel: ByteArray, context: ByteArray): QPeriaptDerivedKey =
        owned.withHandle { NativeSdk.derive(it, owned.parent, purpose.code, protocolLabel, context) }
    /** Caller must erase the returned array. Closing this owner cannot revoke that copy. */
    fun exportForProtocol(): ByteArray = owned.withHandle { NativeSdk.export(it) }
    override fun close() = owned.close()
}

/** A derived cipher/MAC key. Closing its runtime revokes export. */
class QPeriaptDerivedKey private constructor(private val owned: SdkHandle) : AutoCloseable {
    companion object {
        @JvmSynthetic
        internal fun adopt(owned: SdkHandle) = QPeriaptDerivedKey(owned)
    }
    fun exportForProtocol(): ByteArray = owned.withHandle { NativeSdk.exportDerived(it) }
    override fun close() = owned.close()
}

private val ownerLogger: Logger = Logger.getLogger("dev.qperiapt.sdk")

/**
 * Cancellation never interrupts a native call or disposes its inputs early.
 * Completion/cancellation races use complete's atomic result: the losing worker
 * closes its undelivered result. A cancelled Future can be done before native
 * work finishes. Explicit runtime close revokes its children independently.
 */
internal fun <T : AutoCloseable> submitOwned(
    executor: Executor, cleanupInput: () -> Unit = {}, operation: () -> T,
): Future<T> {
    val completion = CompletableFuture<T>()
    try {
        executor.execute {
            try {
                if (!completion.isCancelled) {
                    val result = operation()
                    if (!completion.complete(result)) result.close()
                }
            } catch (failure: Throwable) {
                if (!completion.completeExceptionally(failure)) {
                    // A cancelled consumer cannot receive a cleanup/provider
                    // failure; make it observable instead of silently dropping it.
                    ownerLogger.log(Level.SEVERE, "Cancelled SDK worker failed", failure)
                }
            } finally {
                cleanupInput()
            }
        }
    } catch (failure: Throwable) {
        cleanupInput()
        throw failure
    }
    return completion
}

/** Cleaner state contains only an ID, never a reference to the registered owner. */
internal class SdkHandle private constructor(private val value: Long, @get:JvmSynthetic val parent: SdkHandle?) : AutoCloseable {
    private class Release(private val value: Long) : Runnable {
        override fun run() {
            try {
                NativeSdk.close(value)
            } catch (failure: Throwable) {
                // Cleaner discards exceptions itself; report them explicitly.
                ownerLogger.log(Level.SEVERE, "SDK Cleaner disposal failed", failure)
            }
        }
    }
    private val cleanable = cleaner.register(this, Release(value))

    @JvmSynthetic
    fun <T> withHandle(operation: (Long) -> T): T = try {
        operation(value)
    } finally {
        Reference.reachabilityFence(this)
    }

    override fun close() {
        withHandle { NativeSdk.close(it) }
        cleanable.clean() // unregister; the second native close is idempotent
    }

    companion object {
        private val cleaner = Cleaner.create()

        @JvmSynthetic
        fun <T> adopt(value: Long, parent: SdkHandle?, wrap: (SdkHandle) -> T): T = try {
            wrap(SdkHandle(value, parent))
        } catch (failure: Throwable) {
            try {
                NativeSdk.close(value)
            } catch (disposal: Throwable) {
                failure.addSuppressed(disposal)
            }
            throw failure
        }
    }
}

/** All FFM marshalling lives here; cryptography and synchronization remain in Rust. */
private object NativeSdk {
    // The existing host JVM package supports 64-bit JVM targets. Do not silently
    // bind JAVA_LONG to uintptr_t on a different data model.
    init {
        check(ADDRESS.byteSize() == 8L) { "Q-Periapt JVM binding requires a 64-bit JVM" }
        check(QPeriaptHybrid.runtimeAbiVersion() == 2) { "Q-Periapt ABI mismatch" }
    }
    private val span = MemoryLayout.structLayout(ADDRESS.withName("data"), JAVA_LONG.withName("len"))
    private val options = MemoryLayout.structLayout(
        JAVA_INT.withName("struct_size"), JAVA_INT.withName("extension_version"),
        span.withName("policy"), span.withName("signature"), span.withName("trust_root"),
        span.withName("previous_state"), JAVA_INT.withName("max_live_keys"), JAVA_INT.withName("max_in_flight"),
    )
    private fun offset(name: String) = options.byteOffset(MemoryLayout.PathElement.groupElement(name))
    private fun function(name: String, vararg args: MemoryLayout) =
        QPeriaptNative.handle("q_periapt_sdk_$name", FunctionDescriptor.of(JAVA_INT, *args))
    private val extension = function("extension_version")
    private val runtime = function("runtime_new", ADDRESS, ADDRESS)
    private val state = function("runtime_state", JAVA_LONG, span)
    private val enabled = function("runtime_enabled", JAVA_LONG, ADDRESS)
    private val prepareUpdate = function("runtime_prepare_update", JAVA_LONG, span, span, ADDRESS)
    private val updateStates = function("policy_update_states", JAVA_LONG, span)
    private val activateUpdate = function("policy_update_activate", JAVA_LONG, ADDRESS)
    private val importExpanded = function("expert_key_import", JAVA_LONG, span, ADDRESS)
    private val exportExpanded = function("expert_key_export", JAVA_LONG, span)
    private val generate = function("key_generate", JAVA_LONG, ADDRESS)
    private val publicKey = function("key_public", JAVA_LONG, span)
    private val encapsulate = function("encapsulate", JAVA_LONG, span, span, span, ADDRESS)
    private val decapsulate = function("decapsulate", JAVA_LONG, span, span, ADDRESS)
    private val export = function("secret_export", JAVA_LONG, span)
    private val derive = function("secret_derive", JAVA_LONG, JAVA_INT, span, span, ADDRESS)
    private val exportDerived = function("derived_key_export", JAVA_LONG, span)
    private val close = function("close", JAVA_LONG)
    init {
        check((extension.invokeExact() as Int) == 1) { "Q-Periapt SDK extension mismatch" }
        check(options.byteSize() == 80L && offset("max_live_keys") == 72L) { "SDK native layout mismatch" }
    }

    private fun Arena.bytes(bytes: ByteArray): MemorySegment = allocate(bytes.size.toLong().coerceAtLeast(1)).also {
        MemorySegment.copy(bytes, 0, it, JAVA_BYTE, 0, bytes.size)
    }
    private fun Arena.span(data: MemorySegment, length: Long = data.byteSize()): MemorySegment =
        allocate(span).also { it.set(ADDRESS, 0, data); it.set(JAVA_LONG, 8, length) }
    private fun MemorySegment.bytes(): ByteArray = toArray(JAVA_BYTE)

    fun checkContext(context: ByteArray) = checkStatus("application context", if (context.size <= 65536) 0 else -2)

    fun <T> runtime(
        policy: ByteArray, signature: ByteArray, root: ByteArray, previous: ByteArray,
        keys: Int, calls: Int, wrap: (SdkHandle) -> T,
    ): T {
        checkStatus("verify policy", if (policy.size in 1..65536 && signature.size == 3309 && root.size == 1952 &&
            (previous.isEmpty() || previous.size == 36)) 0 else -2)
        checkStatus("runtime limits", if (keys in 1..1024 && calls in 1..64) 0 else -11)
        return Arena.ofConfined().use { arena ->
            val config = arena.allocate(options)
            config.set(JAVA_INT, offset("struct_size"), Math.toIntExact(options.byteSize()))
            config.set(JAVA_INT, offset("extension_version"), 1)
            for ((name, bytes) in listOf("policy" to policy, "signature" to signature, "trust_root" to root, "previous_state" to previous)) {
                config.set(ADDRESS, offset(name), arena.bytes(bytes))
                config.set(JAVA_LONG, offset(name) + 8, bytes.size.toLong())
            }
            config.set(JAVA_INT, offset("max_live_keys"), keys)
            config.set(JAVA_INT, offset("max_in_flight"), calls)
            val output = arena.allocate(JAVA_LONG)
            checkStatus("verify policy", runtime.invokeExact(config, output) as Int)
            SdkHandle.adopt(output.get(JAVA_LONG, 0), null, wrap)
        }
    }

    fun state(handle: Long): ByteArray = Arena.ofConfined().use { arena ->
        val output = arena.allocate(36)
        checkStatus("trusted state", state.invokeExact(handle, arena.span(output)) as Int)
        output.bytes()
    }
    fun enabled(handle: Long): Boolean = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_INT)
        checkStatus("runtime enabled", enabled.invokeExact(handle, output) as Int)
        output.get(JAVA_INT, 0) == 1
    }
    fun prepareUpdate(handle: Long, parent: SdkHandle, policy: ByteArray, signature: ByteArray): QPeriaptPolicyUpdate {
        checkStatus("prepare policy update", if (policy.size in 1..65536 && signature.size == 3309) 0 else -2)
        return Arena.ofConfined().use { arena ->
            val output = arena.allocate(JAVA_LONG)
            val wrap: (SdkHandle) -> QPeriaptPolicyUpdate = QPeriaptPolicyUpdate::adopt
            checkStatus("prepare policy update", prepareUpdate.invokeExact(handle,
                arena.span(arena.bytes(policy)), arena.span(arena.bytes(signature)), output) as Int)
            SdkHandle.adopt(output.get(JAVA_LONG, 0), parent, wrap)
        }
    }
    fun updateStates(handle: Long): QPeriaptPolicyStates = Arena.ofConfined().use { arena ->
        val output = arena.allocate(72)
        checkStatus("policy states", updateStates.invokeExact(handle, arena.span(output)) as Int)
        QPeriaptPolicyStates.decode(output.bytes())
    }
    fun activateUpdate(handle: Long): QPeriaptRuntime = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_LONG)
        val wrap: (SdkHandle) -> QPeriaptRuntime = QPeriaptRuntime::adopt
        checkStatus("activate policy update", activateUpdate.invokeExact(handle, output) as Int)
        SdkHandle.adopt(output.get(JAVA_LONG, 0), null, wrap)
    }
    fun importExpanded(handle: Long, parent: SdkHandle, bytes: ByteArray): QPeriaptKey {
        checkStatus("expert key import", if (bytes.size == 2440) 0 else -2)
        return Arena.ofConfined().use { arena ->
            val input = arena.bytes(bytes)
            try {
                val output = arena.allocate(JAVA_LONG)
                val wrap: (SdkHandle) -> QPeriaptKey = QPeriaptKey::adopt
                checkStatus("expert key import", importExpanded.invokeExact(handle, arena.span(input), output) as Int)
                SdkHandle.adopt(output.get(JAVA_LONG, 0), parent, wrap)
            } finally {
                input.fill(0)
            }
        }
    }
    fun exportExpanded(handle: Long): ByteArray = Arena.ofConfined().use { arena ->
        val output = arena.allocate(2440)
        try {
            checkStatus("expert key export", exportExpanded.invokeExact(handle, arena.span(output)) as Int)
            output.bytes()
        } finally {
            output.fill(0)
        }
    }
    fun <T> generate(handle: Long, parent: SdkHandle, wrap: (SdkHandle) -> T): T = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_LONG)
        checkStatus("generate key", generate.invokeExact(handle, output) as Int)
        SdkHandle.adopt(output.get(JAVA_LONG, 0), parent, wrap)
    }
    fun publicKey(handle: Long): ByteArray = Arena.ofConfined().use { arena ->
        val output = arena.allocate(1216)
        checkStatus("public key", publicKey.invokeExact(handle, arena.span(output)) as Int)
        output.bytes()
    }
    fun encapsulate(handle: Long, parent: SdkHandle, peer: ByteArray, context: ByteArray): QPeriaptSDKEncapsulation {
        checkContext(context)
        return Arena.ofConfined().use { arena ->
            val input = arena.bytes(context)
            try {
                val ciphertext = arena.allocate(1120)
                val secret = arena.allocate(JAVA_LONG)
                // Allocate the capturing factory before acquiring a native
                // handle, so JVM allocation failure cannot strand that handle.
                val wrap: (SdkHandle) -> QPeriaptSDKEncapsulation = {
                    QPeriaptSDKEncapsulation.create(QPeriaptCiphertext(ciphertext.bytes()), QPeriaptSecret.adopt(it))
                }
                checkStatus("encapsulate", encapsulate.invokeExact(
                    handle, arena.span(arena.bytes(peer)), arena.span(input, context.size.toLong()),
                    arena.span(ciphertext), secret,
                ) as Int)
                SdkHandle.adopt(secret.get(JAVA_LONG, 0), parent, wrap)
            } finally {
                input.fill(0)
            }
        }
    }
    fun decapsulate(handle: Long, parent: SdkHandle?, ciphertext: ByteArray, context: ByteArray): QPeriaptSecret {
        checkContext(context)
        return Arena.ofConfined().use { arena ->
            val input = arena.bytes(context)
            try {
                val secret = arena.allocate(JAVA_LONG)
                val wrap: (SdkHandle) -> QPeriaptSecret = QPeriaptSecret::adopt
                checkStatus("decapsulate", decapsulate.invokeExact(
                    handle, arena.span(arena.bytes(ciphertext)), arena.span(input, context.size.toLong()), secret,
                ) as Int)
                SdkHandle.adopt(secret.get(JAVA_LONG, 0), parent, wrap)
            } finally {
                input.fill(0)
            }
        }
    }
    fun export(handle: Long): ByteArray = Arena.ofConfined().use { arena ->
        val output = arena.allocate(32)
        try {
            checkStatus("export protocol secret", export.invokeExact(handle, arena.span(output)) as Int)
            output.bytes()
        } finally {
            output.fill(0)
        }
    }
    fun derive(handle: Long, parent: SdkHandle?, purpose: Int, label: ByteArray, context: ByteArray): QPeriaptDerivedKey {
        checkStatus("protocol label", if (label.size in 1..255) 0 else -2)
        checkContext(context)
        return Arena.ofConfined().use { arena ->
            val labelInput = arena.bytes(label)
            val input = arena.bytes(context)
            try {
                val output = arena.allocate(JAVA_LONG)
                val wrap: (SdkHandle) -> QPeriaptDerivedKey = QPeriaptDerivedKey::adopt
                checkStatus("derive purpose key", derive.invokeExact(handle, purpose,
                    arena.span(labelInput, label.size.toLong()), arena.span(input, context.size.toLong()), output) as Int)
                SdkHandle.adopt(output.get(JAVA_LONG, 0), parent, wrap)
            } finally {
                input.fill(0)
                labelInput.fill(0)
            }
        }
    }
    fun exportDerived(handle: Long): ByteArray = Arena.ofConfined().use { arena ->
        val output = arena.allocate(32)
        try {
            checkStatus("export derived key", exportDerived.invokeExact(handle, arena.span(output)) as Int)
            output.bytes()
        } finally {
            output.fill(0)
        }
    }
    fun close(handle: Long) {
        val status = close.invokeExact(handle) as Int
        if (status != -9) checkStatus("close", status)
    }
}
