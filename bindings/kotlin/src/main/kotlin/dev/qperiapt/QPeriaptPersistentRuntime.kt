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
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.concurrent.Executor
import java.util.concurrent.Future

private fun storageStatus(operation: String, status: Int) {
    if (status != 0) throw QPeriaptSDKException(operation, status)
}

private fun fixedCopy(bytes: ByteArray, length: Int, label: String): ByteArray {
    storageStatus(label, if (bytes.size == length) 0 else -2)
    return bytes.clone()
}

/** Original independent trust, retained outside incoming policies and the store. */
class QPeriaptPolicyRecoveryTrust(scope: ByteArray, initialRoot: ByteArray, recoveryRoot: ByteArray) {
    private val domain = fixedCopy(scope, 32, "recovery scope")
    private val initial = fixedCopy(initialRoot, 1952, "initial policy root")
    private val recovery = fixedCopy(recoveryRoot, 1952, "recovery policy root")
    private val message = NativePersistence.enrollmentMessage(domain, initial, recovery)
    fun scope(): ByteArray = domain.clone()
    fun initialRoot(): ByteArray = initial.clone()
    fun recoveryRoot(): ByteArray = recovery.clone()
    /** Public bytes for the independent recovery authority to inspect and sign. */
    fun enrollmentMessage(): ByteArray = message.clone()
}

/** Canonical public statement. Parsing verifies grammar, not recovery authority. */
class QPeriaptPolicyRecoveryRequest(encoded: ByteArray) {
    private val bytes = fixedCopy(encoded, 2168, "recovery request")
    private val messages = NativePersistence.signingMessages(bytes)
    fun encoded(): ByteArray = bytes.clone()
    fun approvalMessage(): ByteArray = messages.first.clone()
    fun possessionMessage(): ByteArray = messages.second.clone()
    fun trustBinding(): ByteArray = bytes.copyOfRange(8, 40)
    fun generation(): ULong = bytes.copyOfRange(40, 48).fold(0uL) { value, byte -> (value shl 8) or byte.toUByte().toULong() }
    fun operation(): ByteArray = bytes.copyOfRange(48, 80)
    fun previousRootDigest(): ByteArray = bytes.copyOfRange(80, 112)
    fun historyBinding(): ByteArray = bytes.copyOfRange(148, 180)
    fun incomingRoot(): ByteArray = bytes.copyOfRange(180, 2132)
    fun states(): QPeriaptPolicyStates = QPeriaptPolicyStates.decode(bytes.copyOfRange(112, 148) + bytes.copyOfRange(2132, 2168))
}

/** Retain this original request and both signatures across unknown outcomes. */
class QPeriaptPolicyRecoveryAuthorization {
    val request: QPeriaptPolicyRecoveryRequest
    private val bytes: ByteArray

    constructor(request: QPeriaptPolicyRecoveryRequest, approvalSignature: ByteArray, possessionSignature: ByteArray) {
        val approval = fixedCopy(approvalSignature, 3309, "recovery approval signature")
        val possession = fixedCopy(possessionSignature, 3309, "incoming root possession signature")
        this.request = request
        bytes = request.encoded() + approval + possession
    }

    constructor(encoded: ByteArray) {
        bytes = fixedCopy(encoded, 8786, "recovery authorization")
        request = QPeriaptPolicyRecoveryRequest(bytes.copyOfRange(0, 2168))
    }

    fun encoded(): ByteArray = bytes.clone()
}

enum class QPeriaptPolicyRecoveryDisposition { APPLIED, ALREADY_APPLIED, APPLIED_THEN_ADVANCED }

/** A replay returns no new owner; it preserves the current runtime and children. */
sealed class QPeriaptPolicyRecoveryResult {
    class Applied private constructor(val runtime: QPeriaptPersistentRuntime) : QPeriaptPolicyRecoveryResult() {
        companion object {
            @JvmSynthetic
            internal fun adopt(runtime: QPeriaptPersistentRuntime) = Applied(runtime)
        }
    }
    data object AlreadyApplied : QPeriaptPolicyRecoveryResult()
    data object AppliedThenAdvanced : QPeriaptPolicyRecoveryResult()

    @JvmSynthetic
    internal fun discardReturnedOwner() {
        if (this is Applied) runtime.close()
    }
}

/** Every successful reopen owns a new runtime, regardless of historical disposition. */
class QPeriaptPolicyRecoveryReopen private constructor(
    val runtime: QPeriaptPersistentRuntime, val disposition: QPeriaptPolicyRecoveryDisposition,
) : AutoCloseable {
    override fun close() = runtime.close()
    companion object {
        @JvmSynthetic
        internal fun adopt(runtime: QPeriaptPersistentRuntime, disposition: QPeriaptPolicyRecoveryDisposition) =
            QPeriaptPolicyRecoveryReopen(runtime, disposition)
    }
}

/**
 * Durable policy epoch on reviewed macOS/Linux hosts. Other native targets refuse.
 * Synchronous methods, including close, may block on filesystem synchronization.
 * Child owners retain the lease; explicit close revokes the epoch and its children.
 * A cancelled Future can finish before its native worker. Cancellation is never
 * proof that an admitted write did not commit: reopen the original requested state.
 */
class QPeriaptPersistentRuntime private constructor(val runtime: QPeriaptRuntime) : AutoCloseable {
    companion object {
        @JvmSynthetic
        internal fun adopt(owned: SdkHandle) = QPeriaptPersistentRuntime(QPeriaptRuntime.adopt(owned))

        /** Explicit fixed-authority first creation; never overwrites an existing file. */
        fun provision(path: String, policy: ByteArray, signature: ByteArray, trustRoot: ByteArray,
            maxLiveKeys: Int = 32, maxInFlight: Int = 4): QPeriaptPersistentRuntime =
            NativePersistence.fixed(true, StoreInput.fixed(path, policy, signature, trustRoot, maxLiveKeys, maxInFlight))

        /** Existing fixed-authority store only; missing/corrupt state is not first use. */
        fun open(path: String, policy: ByteArray, signature: ByteArray, trustRoot: ByteArray,
            maxLiveKeys: Int = 32, maxInFlight: Int = 4): QPeriaptPersistentRuntime =
            NativePersistence.fixed(false, StoreInput.fixed(path, policy, signature, trustRoot, maxLiveKeys, maxInFlight))

        fun provisionAsync(executor: Executor, path: String, policy: ByteArray, signature: ByteArray, trustRoot: ByteArray,
            maxLiveKeys: Int = 32, maxInFlight: Int = 4): Future<QPeriaptPersistentRuntime> {
            val input = StoreInput.fixed(path, policy, signature, trustRoot, maxLiveKeys, maxInFlight)
            return submitOwned(executor) { NativePersistence.fixed(true, input) }
        }

        fun openAsync(executor: Executor, path: String, policy: ByteArray, signature: ByteArray, trustRoot: ByteArray,
            maxLiveKeys: Int = 32, maxInFlight: Int = 4): Future<QPeriaptPersistentRuntime> {
            val input = StoreInput.fixed(path, policy, signature, trustRoot, maxLiveKeys, maxInFlight)
            return submitOwned(executor) { NativePersistence.fixed(false, input) }
        }

        fun provisionRecoverable(path: String, policy: ByteArray, signature: ByteArray, trust: QPeriaptPolicyRecoveryTrust,
            enrollmentSignature: ByteArray, maxLiveKeys: Int = 32, maxInFlight: Int = 4): QPeriaptPersistentRuntime =
            NativePersistence.recoverable(RecoveryOpen.PROVISION,
                StoreInput.recovery(path, policy, signature, trust, enrollmentSignature, maxLiveKeys, maxInFlight)).first

        fun openRecoverable(path: String, policy: ByteArray, signature: ByteArray, trust: QPeriaptPolicyRecoveryTrust,
            maxLiveKeys: Int = 32, maxInFlight: Int = 4): QPeriaptPersistentRuntime =
            NativePersistence.recoverable(RecoveryOpen.CONFIGURED,
                StoreInput.recovery(path, policy, signature, trust, null, maxLiveKeys, maxInFlight)).first

        /** Explicitly enroll an existing v1 store with its exact original policy and approval. */
        fun enrollRecovery(path: String, policy: ByteArray, signature: ByteArray, trust: QPeriaptPolicyRecoveryTrust,
            enrollmentSignature: ByteArray, maxLiveKeys: Int = 32, maxInFlight: Int = 4): QPeriaptPersistentRuntime =
            NativePersistence.recoverable(RecoveryOpen.ENROLL,
                StoreInput.recovery(path, policy, signature, trust, enrollmentSignature, maxLiveKeys, maxInFlight)).first

        /**
         * Reconcile the SAME original authorization and its exact requested signed policy.
         * Even after later updates, pass that original policy here. The returned runtime
         * uses the persisted current policy; use openRecoverable for ordinary current-policy admission.
         */
        fun openRecovering(path: String, policy: ByteArray, signature: ByteArray, trust: QPeriaptPolicyRecoveryTrust,
            authorization: QPeriaptPolicyRecoveryAuthorization, maxLiveKeys: Int = 32, maxInFlight: Int = 4): QPeriaptPolicyRecoveryReopen =
            NativePersistence.reopen(StoreInput.recovery(path, policy, signature, trust, null, maxLiveKeys, maxInFlight), authorization.encoded())

        fun provisionRecoverableAsync(executor: Executor, path: String, policy: ByteArray, signature: ByteArray,
            trust: QPeriaptPolicyRecoveryTrust, enrollmentSignature: ByteArray,
            maxLiveKeys: Int = 32, maxInFlight: Int = 4): Future<QPeriaptPersistentRuntime> {
            val input = StoreInput.recovery(path, policy, signature, trust, enrollmentSignature, maxLiveKeys, maxInFlight)
            return submitOwned(executor) { NativePersistence.recoverable(RecoveryOpen.PROVISION, input).first }
        }

        fun openRecoverableAsync(executor: Executor, path: String, policy: ByteArray, signature: ByteArray,
            trust: QPeriaptPolicyRecoveryTrust, maxLiveKeys: Int = 32, maxInFlight: Int = 4): Future<QPeriaptPersistentRuntime> {
            val input = StoreInput.recovery(path, policy, signature, trust, null, maxLiveKeys, maxInFlight)
            return submitOwned(executor) { NativePersistence.recoverable(RecoveryOpen.CONFIGURED, input).first }
        }

        fun enrollRecoveryAsync(executor: Executor, path: String, policy: ByteArray, signature: ByteArray,
            trust: QPeriaptPolicyRecoveryTrust, enrollmentSignature: ByteArray,
            maxLiveKeys: Int = 32, maxInFlight: Int = 4): Future<QPeriaptPersistentRuntime> {
            val input = StoreInput.recovery(path, policy, signature, trust, enrollmentSignature, maxLiveKeys, maxInFlight)
            return submitOwned(executor) { NativePersistence.recoverable(RecoveryOpen.ENROLL, input).first }
        }

        /** Async [openRecovering], with the original authorization's requested policy and signature. */
        fun openRecoveringAsync(executor: Executor, path: String, policy: ByteArray, signature: ByteArray,
            trust: QPeriaptPolicyRecoveryTrust, authorization: QPeriaptPolicyRecoveryAuthorization,
            maxLiveKeys: Int = 32, maxInFlight: Int = 4): Future<QPeriaptPolicyRecoveryReopen> {
            val input = StoreInput.recovery(path, policy, signature, trust, null, maxLiveKeys, maxInFlight)
            val original = authorization.encoded()
            return submitOwned(executor) { NativePersistence.reopen(input, original) }
        }
    }

    /** Success persists first, then revokes this epoch and returns its sole successor. */
    fun update(policy: ByteArray, signature: ByteArray): QPeriaptPersistentRuntime {
        val input = PolicyInput(policy, signature)
        return runtime.owned.withHandle { NativePersistence.update(it, input) }
    }

    fun updateAsync(executor: Executor, policy: ByteArray, signature: ByteArray): Future<QPeriaptPersistentRuntime> {
        val input = PolicyInput(policy, signature)
        return submitOwned(executor) { runtime.owned.withHandle { NativePersistence.update(it, input) } }
    }

    /** Public statement preparation does not persist or authorize a transition. */
    fun prepareAuthorityRecovery(operation: ByteArray, policy: ByteArray, signature: ByteArray,
        incomingRoot: ByteArray): QPeriaptPolicyRecoveryRequest {
        val input = RecoveryInput(operation, policy, signature, incomingRoot)
        return runtime.owned.withHandle { NativePersistence.prepare(it, input) }
    }

    fun prepareAuthorityRecoveryAsync(executor: Executor, operation: ByteArray, policy: ByteArray,
        signature: ByteArray, incomingRoot: ByteArray): Future<QPeriaptPolicyRecoveryRequest> {
        val input = RecoveryInput(operation, policy, signature, incomingRoot)
        return submitSdkOperation(executor, discardResult = { /* Public statement; no owner or mutation. */ }) {
            runtime.owned.withHandle { NativePersistence.prepare(it, input) }
        }
    }

    fun recoverAuthority(authorization: QPeriaptPolicyRecoveryAuthorization, policy: ByteArray,
        signature: ByteArray): QPeriaptPolicyRecoveryResult {
        val input = PolicyInput(policy, signature)
        val original = authorization.encoded()
        return runtime.owned.withHandle { NativePersistence.recover(it, original, input) }
    }

    fun recoverAuthorityAsync(executor: Executor, authorization: QPeriaptPolicyRecoveryAuthorization,
        policy: ByteArray, signature: ByteArray): Future<QPeriaptPolicyRecoveryResult> {
        val input = PolicyInput(policy, signature)
        val original = authorization.encoded()
        return submitSdkOperation(executor, discardResult = { it.discardReturnedOwner() }) {
            runtime.owned.withHandle { NativePersistence.recover(it, original, input) }
        }
    }

    override fun close() = runtime.close()
}

private class PolicyInput(policy: ByteArray, signature: ByteArray) {
    val policy: ByteArray
    val signature: ByteArray
    init {
        storageStatus("signed policy", if (policy.size in 1..65536 && signature.size == 3309) 0 else -2)
        this.policy = policy.clone()
        this.signature = signature.clone()
    }
}

private class RecoveryInput(operation: ByteArray, policy: ByteArray, signature: ByteArray, root: ByteArray) {
    val operation = fixedCopy(operation, 32, "recovery operation")
    val policy = PolicyInput(policy, signature)
    val root = fixedCopy(root, 1952, "incoming policy root")
}

private enum class RecoveryOpen { PROVISION, ENROLL, CONFIGURED, RECOVERING }

private class StoreInput private constructor(val fields: Map<String, ByteArray>, val keys: Int, val calls: Int) {
    companion object {
        private fun common(path: String, policy: ByteArray, signature: ByteArray, keys: Int, calls: Int): MutableMap<String, ByteArray> {
            storageStatus("runtime limits", if (keys in 1..1024 && calls in 1..64) 0 else -11)
            storageStatus("store path", if (path.length in 1..4096 && '\u0000' !in path) 0 else -2)
            val buffer = try {
                Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(path))
            } catch (_: CharacterCodingException) {
                throw QPeriaptSDKException("store path", -2)
            }
            storageStatus("store path", if (buffer.remaining() in 1..4096) 0 else -2)
            val encoded = ByteArray(buffer.remaining()).also { buffer.get(it) }
            val input = PolicyInput(policy, signature)
            return linkedMapOf("path" to encoded, "policy" to input.policy, "signature" to input.signature)
        }

        fun fixed(path: String, policy: ByteArray, signature: ByteArray, root: ByteArray, keys: Int, calls: Int): StoreInput {
            val fields = common(path, policy, signature, keys, calls)
            fields["trust_root"] = fixedCopy(root, 1952, "policy root")
            return StoreInput(fields, keys, calls)
        }

        fun recovery(path: String, policy: ByteArray, signature: ByteArray, trust: QPeriaptPolicyRecoveryTrust,
            enrollment: ByteArray?, keys: Int, calls: Int): StoreInput {
            val fields = common(path, policy, signature, keys, calls)
            fields["scope"] = trust.scope()
            fields["initial_root"] = trust.initialRoot()
            fields["recovery_root"] = trust.recoveryRoot()
            fields["enrollment_signature"] = enrollment?.let { fixedCopy(it, 3309, "recovery enrollment signature") } ?: byteArrayOf()
            return StoreInput(fields, keys, calls)
        }
    }
}

/** FFM representation only; persistence, verification and transition ownership stay in Rust. */
private object NativePersistence {
    private val span = MemoryLayout.structLayout(ADDRESS, JAVA_LONG)
    private val fixedLayout = layout("path", "policy", "signature", "trust_root")
    private val recoveryLayout = layout("path", "policy", "signature", "scope", "initial_root", "recovery_root", "enrollment_signature")
    private fun layout(vararg inputs: String): MemoryLayout = MemoryLayout.structLayout(
        JAVA_INT.withName("struct_size"), JAVA_INT.withName("extension_version"),
        *inputs.map { span.withName(it) }.toTypedArray(),
        JAVA_INT.withName("max_live_keys"), JAVA_INT.withName("max_in_flight"),
    )
    private fun offset(layout: MemoryLayout, name: String) = layout.byteOffset(MemoryLayout.PathElement.groupElement(name))
    private fun function(name: String, vararg arguments: MemoryLayout) =
        QPeriaptNative.handle("q_periapt_sdk_$name", FunctionDescriptor.of(JAVA_INT, *arguments))
    private val extension = function("extension_version")
    private val provisionStore = function("runtime_provision_store", ADDRESS, ADDRESS)
    private val openStore = function("runtime_open_store", ADDRESS, ADDRESS)
    private val updateStore = function("runtime_update_store", JAVA_LONG, span, span, ADDRESS)
    private val provisionRecovery = function("runtime_provision_recoverable_store", ADDRESS, ADDRESS)
    private val enrollRecovery = function("runtime_enroll_recovery_store", ADDRESS, ADDRESS)
    private val openRecovery = function("runtime_open_recoverable_store", ADDRESS, ADDRESS)
    private val openRecovering = function("runtime_open_recovering_store", ADDRESS, span, ADDRESS, ADDRESS)
    private val enrollmentMessage = function("policy_recovery_enrollment_message", span, span, span, span)
    private val signingMessages = function("policy_recovery_signing_messages", span, span, span)
    private val prepareRecovery = function("runtime_prepare_recovery", JAVA_LONG, span, span, span, span, span)
    private val recoverAuthority = function("runtime_recover_authority", JAVA_LONG, span, span, span, ADDRESS, ADDRESS)
    init {
        check(ADDRESS.byteSize() == 8L && QPeriaptHybrid.runtimeAbiVersion() == 2) { "SDK persistent ABI mismatch" }
        check((extension.invokeExact() as Int) == 1) { "SDK persistent extension mismatch" }
        check(fixedLayout.byteSize() == 80L && recoveryLayout.byteSize() == 128L &&
            offset(fixedLayout, "max_live_keys") == 72L && offset(recoveryLayout, "max_live_keys") == 120L) {
            "SDK persistent native layout mismatch"
        }
    }

    private fun Arena.input(bytes: ByteArray): MemorySegment {
        val data = if (bytes.isEmpty()) MemorySegment.NULL else allocate(bytes.size.toLong()).also {
            MemorySegment.copy(bytes, 0, it, JAVA_BYTE, 0, bytes.size)
        }
        return allocate(span).also { it.set(ADDRESS, 0, data); it.set(JAVA_LONG, 8, bytes.size.toLong()) }
    }
    private fun Arena.output(data: MemorySegment): MemorySegment = allocate(span).also {
        it.set(ADDRESS, 0, data); it.set(JAVA_LONG, 8, data.byteSize())
    }
    private fun Arena.options(layout: MemoryLayout, input: StoreInput): MemorySegment = allocate(layout).also { config ->
        config.set(JAVA_INT, offset(layout, "struct_size"), Math.toIntExact(layout.byteSize()))
        config.set(JAVA_INT, offset(layout, "extension_version"), 1)
        for ((name, bytes) in input.fields) MemorySegment.copy(this.input(bytes), 0, config, offset(layout, name), span.byteSize())
        config.set(JAVA_INT, offset(layout, "max_live_keys"), input.keys)
        config.set(JAVA_INT, offset(layout, "max_in_flight"), input.calls)
    }
    private fun <T> owner(handle: Long, wrap: (QPeriaptPersistentRuntime) -> T): T {
        storageStatus("persistent runtime ownership", if (handle != 0L) 0 else -5)
        return SdkHandle.adopt(handle, null) { wrap(QPeriaptPersistentRuntime.adopt(it)) }
    }
    private fun owner(handle: Long): QPeriaptPersistentRuntime = owner(handle) { it }

    fun fixed(creating: Boolean, input: StoreInput): QPeriaptPersistentRuntime = Arena.ofConfined().use { arena ->
        val options = arena.options(fixedLayout, input)
        val output = arena.allocate(JAVA_LONG)
        val call = if (creating) provisionStore else openStore
        storageStatus(if (creating) "provision policy store" else "open configured policy store", call.invokeExact(options, output) as Int)
        owner(output.get(JAVA_LONG, 0))
    }

    fun update(handle: Long, input: PolicyInput): QPeriaptPersistentRuntime = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_LONG)
        storageStatus("persist policy update", updateStore.invokeExact(handle, arena.input(input.policy), arena.input(input.signature), output) as Int)
        owner(output.get(JAVA_LONG, 0))
    }

    fun enrollmentMessage(scope: ByteArray, initial: ByteArray, recovery: ByteArray): ByteArray = Arena.ofConfined().use { arena ->
        val output = arena.allocate(3968)
        storageStatus("recovery trust configuration", enrollmentMessage.invokeExact(
            arena.input(scope), arena.input(initial), arena.input(recovery), arena.output(output)) as Int)
        output.toArray(JAVA_BYTE)
    }

    fun signingMessages(request: ByteArray): Pair<ByteArray, ByteArray> = Arena.ofConfined().use { arena ->
        val approval = arena.allocate(2203)
        val possession = arena.allocate(2204)
        storageStatus("recovery request grammar", signingMessages.invokeExact(arena.input(request), arena.output(approval), arena.output(possession)) as Int)
        approval.toArray(JAVA_BYTE) to possession.toArray(JAVA_BYTE)
    }

    fun recoverable(mode: RecoveryOpen, input: StoreInput, authorization: ByteArray = byteArrayOf()): Pair<QPeriaptPersistentRuntime, Int> =
        Arena.ofConfined().use { arena ->
            val options = arena.options(recoveryLayout, input)
            val output = arena.allocate(JAVA_LONG)
            val disposition = arena.allocate(JAVA_INT)
            val status = when (mode) {
                RecoveryOpen.PROVISION -> provisionRecovery.invokeExact(options, output) as Int
                RecoveryOpen.ENROLL -> enrollRecovery.invokeExact(options, output) as Int
                RecoveryOpen.CONFIGURED -> openRecovery.invokeExact(options, output) as Int
                RecoveryOpen.RECOVERING -> openRecovering.invokeExact(options, arena.input(authorization), output, disposition) as Int
            }
            storageStatus("open recoverable policy store", status)
            owner(output.get(JAVA_LONG, 0)) { it to disposition.get(JAVA_INT, 0) }
        }

    fun reopen(input: StoreInput, authorization: ByteArray): QPeriaptPolicyRecoveryReopen {
        val (runtime, raw) = recoverable(RecoveryOpen.RECOVERING, input, authorization)
        val disposition = when (raw) {
            1 -> QPeriaptPolicyRecoveryDisposition.APPLIED
            2 -> QPeriaptPolicyRecoveryDisposition.ALREADY_APPLIED
            3 -> QPeriaptPolicyRecoveryDisposition.APPLIED_THEN_ADVANCED
            else -> {
                val failure = QPeriaptSDKException("recovery reopen disposition", -5)
                try { runtime.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
                throw failure
            }
        }
        return try {
            QPeriaptPolicyRecoveryReopen.adopt(runtime, disposition)
        } catch (failure: Throwable) {
            try { runtime.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            throw failure
        }
    }

    fun prepare(handle: Long, input: RecoveryInput): QPeriaptPolicyRecoveryRequest = Arena.ofConfined().use { arena ->
        val output = arena.allocate(2168)
        storageStatus("prepare authority recovery", prepareRecovery.invokeExact(handle, arena.input(input.operation),
            arena.input(input.policy.policy), arena.input(input.policy.signature), arena.input(input.root), arena.output(output)) as Int)
        QPeriaptPolicyRecoveryRequest(output.toArray(JAVA_BYTE))
    }

    fun recover(previous: Long, authorization: ByteArray, input: PolicyInput): QPeriaptPolicyRecoveryResult = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_LONG)
        val disposition = arena.allocate(JAVA_INT)
        storageStatus("recover policy authority", recoverAuthority.invokeExact(previous, arena.input(authorization),
            arena.input(input.policy), arena.input(input.signature), output, disposition) as Int)
        val handle = output.get(JAVA_LONG, 0)
        val raw = disposition.get(JAVA_INT, 0)
        when {
            raw == 1 && handle != 0L && handle != previous -> owner(handle) { QPeriaptPolicyRecoveryResult.Applied.adopt(it) }
            raw == 2 && handle == 0L -> QPeriaptPolicyRecoveryResult.AlreadyApplied
            raw == 3 && handle == 0L -> QPeriaptPolicyRecoveryResult.AppliedThenAdvanced
            else -> {
                val failure = QPeriaptSDKException("recovery ownership disposition", -5)
                if (handle != 0L && handle != previous) {
                    try { owner(handle).close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
                }
                throw failure
            }
        }
    }
}
