package dev.qperiapt

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout.ADDRESS
import java.lang.foreign.ValueLayout.JAVA_BYTE
import java.lang.foreign.ValueLayout.JAVA_INT
import java.lang.foreign.ValueLayout.JAVA_LONG
import java.nio.file.Files
import java.nio.file.Path

/**
 * Kotlin product face of the PQ/T hybrid suite over the ABI-major C library, via the Foreign
 * Function & Memory API (Project Panama, JDK 22+). It reuses the Rust core but obtains
 * randomness inside the native ABI, so tests assert semantic parity rather than deterministic
 * byte replay — see bindings/README.md.
 *
 * Returned secret arrays are caller-owned. Invoke [EncapsulationResult.wipeSecret]
 * or `fill(0)` on every secret/key array after use; JVM and OS copies remain outside
 * this binding's control.
 */
object QPeriaptHybrid {
    const val ABI_VERSION = 2
    const val PROFILE_CONTEXT_BOUND: Byte = 2
    const val SECRET_LEN = 32
    const val MLKEM_PK_LEN = 1184
    const val MLKEM_SK_LEN = 2400
    const val MLKEM_CT_LEN = 1088
    const val X25519_LEN = 32
    const val POLICY_DECISION_LEN = 40
    const val TRUSTED_POLICY_STATE_LEN = 36
    const val MAX_SIGNED_POLICY_BYTES = 64 * 1024
    const val MAX_APPLICATION_CONTEXT_BYTES = 64 * 1024
    const val SUITE_MLKEM768_X25519: Byte = 1
    const val KEY_FORMAT_EXPANDED: Byte = 1

    class QPeriaptException(val operation: String, val code: Int) :
        RuntimeException("$operation rc=$code")

    data class EncapsulationResult(
        val ctPq: ByteArray,
        val ctTrad: ByteArray,
        /** Caller-owned secret material. Wipe this array when the session no longer needs it. */
        val secret: ByteArray,
    ) {
        /** Best-effort zeroization of this result's current secret array. */
        fun wipeSecret() {
            secret.fill(0)
        }
    }

    data class KeyPairResult(
        val skPq: ByteArray,
        val pkPq: ByteArray,
        val skTrad: ByteArray,
        val pkTrad: ByteArray,
    ) {
        fun wipeSecrets() {
            skPq.fill(0)
            skTrad.fill(0)
        }
    }

    /** Atomic suite/profile/version decision produced by a verified signed policy. */
    class PolicyDecision internal constructor(encoded: ByteArray) {
        val suiteCode: Byte
        val profile: Byte
        val keyFormat: Byte
        val policyVersion: Long
        private val digest: ByteArray
        private val canonical: ByteArray = encoded.clone()

        init {
            require(encoded.size == POLICY_DECISION_LEN) { "invalid policy decision length" }
            require(encoded[0] == 1.toByte()) { "unknown policy decision version" }
            require(encoded[1] == SUITE_MLKEM768_X25519) { "unsupported policy suite" }
            require(encoded[2] == PROFILE_CONTEXT_BOUND) { "unsupported policy profile" }
            require(encoded[3] == KEY_FORMAT_EXPANDED) { "unsupported policy key format" }
            suiteCode = encoded[1]
            profile = encoded[2]
            keyFormat = encoded[3]
            policyVersion = encoded.copyOfRange(4, 8).fold(0L) { value, byte ->
                (value shl 8) or (byte.toLong() and 0xff)
            }
            require(policyVersion != 0L) { "zero policy version" }
            digest = encoded.copyOfRange(8, POLICY_DECISION_LEN)
        }

        fun policyDigest(): ByteArray = digest.clone()

        internal fun encoded(): ByteArray = canonical.clone()

        /** Persist atomically and pass to the next decision load. */
        fun trustedState(): ByteArray = byteArrayOf(
            (policyVersion ushr 24).toByte(),
            (policyVersion ushr 16).toByte(),
            (policyVersion ushr 8).toByte(),
            policyVersion.toByte(),
        ) + digest
    }

    private val linker = Linker.nativeLinker()
    // Product code must bind a specific native library path, then verify ABI/suite metadata below.
    private val lookup: SymbolLookup = run {
        val explicit = System.getProperty("qperiapt.lib")
            ?: error("qperiapt.lib must be set to an absolute q-periapt native library path")
        val path = Path.of(explicit)
        require(path.isAbsolute) { "qperiapt.lib must be an absolute path: $explicit" }
        require(Files.isRegularFile(path)) { "qperiapt.lib does not name a regular file: $explicit" }
        SymbolLookup.libraryLookup(path, Arena.global())
    }

    private fun handle(name: String, desc: FunctionDescriptor) =
        linker.downcallHandle(lookup.find(name).orElseThrow { RuntimeException("missing symbol $name") }, desc)

    private val abiVersionFn = handle("q_periapt_abi_version", FunctionDescriptor.of(JAVA_INT))
    private val versionFn = handle("q_periapt_version", FunctionDescriptor.of(ADDRESS))
    private val fixedSuiteIdFn = handle("q_periapt_fixed_suite_id", FunctionDescriptor.of(ADDRESS))
    private val fixedSuiteIdLenFn = handle("q_periapt_fixed_suite_id_len", FunctionDescriptor.of(JAVA_LONG))
    private val statusNameFn = handle("q_periapt_status_name", FunctionDescriptor.of(ADDRESS, JAVA_INT))

    private val decisionPolicyDesc = FunctionDescriptor.of(
        JAVA_INT,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG
    )
    private val decisionPolicy =
        handle("q_periapt_decision_from_signed_policy", decisionPolicyDesc)

    // (ptr,long) buffer pairs are modeled as ADDRESS + JAVA_LONG.
    private val generateKeypairDesc = FunctionDescriptor.of(
        JAVA_INT,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG
    )
    private val generateKeypair = handle("q_periapt_generate_keypair", generateKeypairDesc)

    private val encapDesc = FunctionDescriptor.of(
        JAVA_INT,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        ADDRESS, JAVA_LONG
    )
    private val encap = handle("q_periapt_encapsulate", encapDesc)

    private val decapDesc = FunctionDescriptor.of(
        JAVA_INT,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG
    )
    private val decap = handle("q_periapt_decapsulate", decapDesc)

    private fun Arena.seg(bytes: ByteArray): MemorySegment =
        allocate(bytes.size.toLong().coerceAtLeast(1)).also {
            MemorySegment.copy(bytes, 0, it, JAVA_BYTE, 0, bytes.size)
        }

    /**
     * Owns native segments that contain secret material from the moment they are
     * allocated. The owner wipes every registered segment before the surrounding
     * arena releases it, including allocation/copy/native-call failure paths.
     */
    private class SecretSegments(private val arena: Arena) : AutoCloseable {
        private val segments = ArrayList<MemorySegment>()

        fun copy(bytes: ByteArray): MemorySegment =
            allocate(bytes.size.toLong().coerceAtLeast(1)).also {
                MemorySegment.copy(bytes, 0, it, JAVA_BYTE, 0, bytes.size)
            }

        fun allocate(byteSize: Long): MemorySegment =
            arena.allocate(byteSize.coerceAtLeast(1)).also { segments.add(it) }

        override fun close() {
            var failure: Throwable? = null
            for (segment in segments.asReversed()) {
                try {
                    segment.fill(0)
                } catch (error: Throwable) {
                    val first = failure
                    if (first == null) {
                        failure = error
                    } else {
                        first.addSuppressed(error)
                    }
                }
            }
            failure?.let { throw it }
        }
    }

    private fun MemorySegment.toBytes(n: Int): ByteArray =
        ByteArray(n).also { MemorySegment.copy(this, JAVA_BYTE, 0, it, 0, n) }

    // A confined Arena frees its native memory on close but does NOT zero it; explicitly
    // wipe any segment that held secret material (keys, shared secrets, combiner inputs)
    // before that happens, so freed pages cannot leak a secret to a later allocation.
    private fun MemorySegment.wipe() {
        fill(0)
    }

    private fun checkOk(operation: String, rc: Int) {
        if (rc != 0) throw QPeriaptException(operation, rc)
    }

    private fun cString(pointer: MemorySegment, maxBytes: Long): String {
        require(pointer != MemorySegment.NULL) { "native string pointer was NULL" }
        return pointer.reinterpret(maxBytes).getString(0)
    }

    fun runtimeAbiVersion(): Int = abiVersionFn.invokeExact() as Int

    fun runtimeVersion(): String = cString(versionFn.invokeExact() as MemorySegment, 64)

    fun fixedSuiteId(): ByteArray = cString(fixedSuiteIdFn.invokeExact() as MemorySegment, 64).encodeToByteArray()

    fun fixedSuiteIdLen(): Long = fixedSuiteIdLenFn.invokeExact() as Long

    fun statusName(code: Int): String = cString(statusNameFn.invokeExact(code) as MemorySegment, 64)

    private fun validateRuntimeMetadata() {
        check(runtimeAbiVersion() == ABI_VERSION) {
            "q-periapt ABI mismatch: header=$ABI_VERSION runtime=${runtimeAbiVersion()}"
        }
        check(fixedSuiteId().contentEquals("ML-KEM-768+X25519".encodeToByteArray())) {
            "q-periapt fixed suite mismatch: ${fixedSuiteId().decodeToString()}"
        }
        check(fixedSuiteIdLen() == "ML-KEM-768+X25519".length.toLong()) {
            "q-periapt fixed suite length mismatch: ${fixedSuiteIdLen()}"
        }
    }

    init {
        validateRuntimeMetadata()
    }

    fun decisionFromSignedPolicy(
        toml: ByteArray,
        signature: ByteArray,
        verificationKey: ByteArray,
        lastTrustedState: ByteArray = byteArrayOf(),
    ): PolicyDecision = Arena.ofConfined().use { a ->
        require(toml.size <= MAX_SIGNED_POLICY_BYTES) {
            "toml exceeds $MAX_SIGNED_POLICY_BYTES bytes: ${toml.size}"
        }
        require(lastTrustedState.isEmpty() || lastTrustedState.size == TRUSTED_POLICY_STATE_LEN) {
            "lastTrustedState must be empty or $TRUSTED_POLICY_STATE_LEN bytes"
        }
        val tomlSeg = a.seg(toml)
        val sigSeg = a.seg(signature)
        val vkSeg = a.seg(verificationKey)
        val stateSeg = a.seg(lastTrustedState)
        val out = a.allocate(POLICY_DECISION_LEN.toLong())
        try {
            val rc = decisionPolicy.invokeExact(
                tomlSeg, toml.size.toLong(), sigSeg, signature.size.toLong(),
                vkSeg, verificationKey.size.toLong(),
                stateSeg, lastTrustedState.size.toLong(),
                out, POLICY_DECISION_LEN.toLong()
            ) as Int
            checkOk("q_periapt_decision_from_signed_policy", rc)
            PolicyDecision(out.toBytes(POLICY_DECISION_LEN))
        } finally {
            stateSeg.wipe(); out.wipe()
        }
    }

    fun generateKeypair(decision: PolicyDecision): KeyPairResult = Arena.ofConfined().use { a ->
        SecretSegments(a).use { secrets ->
            val skPq = secrets.allocate(MLKEM_SK_LEN.toLong())
            val pkPq = a.allocate(MLKEM_PK_LEN.toLong())
            val skTrad = secrets.allocate(X25519_LEN.toLong())
            val pkTrad = a.allocate(X25519_LEN.toLong())
            val decisionBytes = decision.encoded()
            val rc = generateKeypair.invokeExact(
                a.seg(decisionBytes), decisionBytes.size.toLong(),
                skPq, MLKEM_SK_LEN.toLong(), pkPq, MLKEM_PK_LEN.toLong(),
                skTrad, X25519_LEN.toLong(), pkTrad, X25519_LEN.toLong()
            ) as Int
            checkOk("q_periapt_generate_keypair", rc)
            KeyPairResult(
                skPq = skPq.toBytes(MLKEM_SK_LEN),
                pkPq = pkPq.toBytes(MLKEM_PK_LEN),
                skTrad = skTrad.toBytes(X25519_LEN),
                pkTrad = pkTrad.toBytes(X25519_LEN),
            )
        }
    }

    /** Encapsulate while committing the exact signed-policy digest and application context. */
    fun encapsulate(
        decision: PolicyDecision,
        pkPq: ByteArray,
        pkTrad: ByteArray,
        applicationContext: ByteArray,
    ): EncapsulationResult = Arena.ofConfined().use { a ->
        require(applicationContext.size <= MAX_APPLICATION_CONTEXT_BYTES) {
            "applicationContext exceeds $MAX_APPLICATION_CONTEXT_BYTES bytes: ${applicationContext.size}"
        }
        SecretSegments(a).use { secrets ->
            val decisionBytes = decision.encoded()
            val decisionSeg = a.seg(decisionBytes)
            val outCtPq = a.allocate(MLKEM_CT_LEN.toLong())
            val outCtTrad = a.allocate(X25519_LEN.toLong())
            val outSecret = secrets.allocate(SECRET_LEN.toLong())
            val rc = encap.invokeExact(
                decisionSeg, decisionBytes.size.toLong(),
                a.seg(pkPq), pkPq.size.toLong(), a.seg(pkTrad), pkTrad.size.toLong(),
                a.seg(applicationContext), applicationContext.size.toLong(),
                outCtPq, MLKEM_CT_LEN.toLong(), outCtTrad, X25519_LEN.toLong(),
                outSecret, SECRET_LEN.toLong()
            ) as Int
            checkOk("q_periapt_encapsulate", rc)
            EncapsulationResult(
                ctPq = outCtPq.toBytes(MLKEM_CT_LEN),
                ctTrad = outCtTrad.toBytes(X25519_LEN),
                secret = outSecret.toBytes(SECRET_LEN),
            )
        }
    }

    /** Decapsulate under the same policy decision and application context. */
    fun decapsulate(
        decision: PolicyDecision,
        skPq: ByteArray,
        ctPq: ByteArray,
        pkPq: ByteArray,
        skTrad: ByteArray,
        ctTrad: ByteArray,
        pkTrad: ByteArray,
        applicationContext: ByteArray,
    ): ByteArray = Arena.ofConfined().use { a ->
        require(applicationContext.size <= MAX_APPLICATION_CONTEXT_BYTES) {
            "applicationContext exceeds $MAX_APPLICATION_CONTEXT_BYTES bytes: ${applicationContext.size}"
        }
        SecretSegments(a).use { secrets ->
            val decisionBytes = decision.encoded()
            val decisionSeg = a.seg(decisionBytes)
            val skPqSeg = secrets.copy(skPq)
            val skTradSeg = secrets.copy(skTrad)
            val out = secrets.allocate(SECRET_LEN.toLong())
            val rc = decap.invokeExact(
                decisionSeg, decisionBytes.size.toLong(),
                skPqSeg, skPq.size.toLong(), a.seg(ctPq), ctPq.size.toLong(),
                a.seg(pkPq), pkPq.size.toLong(), skTradSeg, skTrad.size.toLong(),
                a.seg(ctTrad), ctTrad.size.toLong(), a.seg(pkTrad), pkTrad.size.toLong(),
                a.seg(applicationContext), applicationContext.size.toLong(),
                out, SECRET_LEN.toLong()
            ) as Int
            checkOk("q_periapt_decapsulate", rc)
            out.toBytes(SECRET_LEN)
        }
    }

}
