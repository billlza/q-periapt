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
 * Kotlin face of the PQ/T hybrid suite over the `q-periapt-ffi` C ABI, via the Foreign
 * Function & Memory API (Project Panama, JDK 22+). One Rust core, byte-identical
 * across platforms — see bindings/README.md.
 */
object QPeriaptHybrid {
    const val ABI_VERSION = 1
    const val PROFILE_COMPAT_XWING: Byte = 1
    const val PROFILE_CONTEXT_BOUND: Byte = 2
    const val SECRET_LEN = 32
    const val MLKEM_PK_LEN = 1184
    const val MLKEM_SK_LEN = 2400
    const val MLKEM_XWING_SEED_LEN = 32
    const val MLKEM_CT_LEN = 1088
    const val X25519_LEN = 32
    private const val UINT32_MAX = 0xffff_ffffL

    class QPeriaptException(val operation: String, val code: Int) :
        RuntimeException("$operation rc=$code")

    data class EncapsulationResult(
        val ctPq: ByteArray,
        val ctTrad: ByteArray,
        /** Caller-owned secret material. Wipe this array when the session no longer needs it. */
        val secret: ByteArray,
    )

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

    // (ptr,long) buffer pairs are modeled as ADDRESS + JAVA_LONG.
    private val keypairDesc = FunctionDescriptor.of(
        JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG
    )
    private val mlkemKeypair = handle("q_periapt_mlkem768_keypair", keypairDesc)
    private val mlkemXWingKeypair = handle("q_periapt_mlkem768_xwing_keypair", keypairDesc)
    private val x25519Keypair = handle("q_periapt_x25519_keypair", keypairDesc)

    private val profilePolicyDesc = FunctionDescriptor.of(
        JAVA_INT,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        JAVA_INT, ADDRESS, JAVA_LONG
    )
    private val profilePolicy = handle("q_periapt_profile_from_signed_policy", profilePolicyDesc)

    private val encapDesc = FunctionDescriptor.of(
        JAVA_INT,
        JAVA_BYTE, ADDRESS, JAVA_LONG, JAVA_INT,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG
    )
    private val encap = handle("q_periapt_hybrid_encapsulate", encapDesc)

    private val decapDesc = FunctionDescriptor.of(
        JAVA_INT,
        JAVA_BYTE, ADDRESS, JAVA_LONG, JAVA_INT,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG,
        ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG
    )
    private val decap = handle("q_periapt_hybrid_decapsulate", decapDesc)

    private val combineDesc = FunctionDescriptor.of(
        JAVA_INT, JAVA_BYTE, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG
    )
    private val combineFn = handle("q_periapt_combine", combineDesc)

    private fun Arena.seg(bytes: ByteArray): MemorySegment =
        allocate(bytes.size.toLong().coerceAtLeast(1)).also {
            MemorySegment.copy(bytes, 0, it, JAVA_BYTE, 0, bytes.size)
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

    private fun checkedUInt32(label: String, value: Long): Int {
        require(value in 0..UINT32_MAX) { "$label must be in uint32 range: $value" }
        return value.toInt()
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

    fun profileFromSignedPolicy(
        toml: ByteArray,
        signature: ByteArray,
        verificationKey: ByteArray,
        lastTrustedVersion: Long,
    ): Byte = Arena.ofConfined().use { a ->
        val tomlSeg = a.seg(toml)
        val sigSeg = a.seg(signature)
        val vkSeg = a.seg(verificationKey)
        val out = a.allocate(1)
        val lastTrusted = checkedUInt32("lastTrustedVersion", lastTrustedVersion)
        try {
            val rc = profilePolicy.invokeExact(
                tomlSeg, toml.size.toLong(), sigSeg, signature.size.toLong(),
                vkSeg, verificationKey.size.toLong(), lastTrusted, out, 1L
            ) as Int
            checkOk("q_periapt_profile_from_signed_policy", rc)
            out.get(JAVA_BYTE, 0L)
        } finally {
            out.wipe()
        }
    }

    fun mlkem768Keypair(seed: ByteArray): Pair<ByteArray, ByteArray> = Arena.ofConfined().use { a ->
        val seedSeg = a.seg(seed)
        val sk = a.allocate(MLKEM_SK_LEN.toLong())
        val pk = a.allocate(MLKEM_PK_LEN.toLong())
        try {
            val rc = mlkemKeypair.invokeExact(
                seedSeg, seed.size.toLong(), sk, MLKEM_SK_LEN.toLong(), pk, MLKEM_PK_LEN.toLong()
            ) as Int
            checkOk("q_periapt_mlkem768_keypair", rc)
            sk.toBytes(MLKEM_SK_LEN) to pk.toBytes(MLKEM_PK_LEN)
        } finally {
            seedSeg.wipe(); sk.wipe() // seed + secret key are sensitive; pk is public
        }
    }

    fun mlkem768XWingKeypair(seed: ByteArray): Pair<ByteArray, ByteArray> = Arena.ofConfined().use { a ->
        val seedSeg = a.seg(seed)
        val skSeed = a.allocate(MLKEM_XWING_SEED_LEN.toLong())
        val pk = a.allocate(MLKEM_PK_LEN.toLong())
        try {
            val rc = mlkemXWingKeypair.invokeExact(
                seedSeg, seed.size.toLong(),
                skSeed, MLKEM_XWING_SEED_LEN.toLong(),
                pk, MLKEM_PK_LEN.toLong()
            ) as Int
            checkOk("q_periapt_mlkem768_xwing_keypair", rc)
            skSeed.toBytes(MLKEM_XWING_SEED_LEN) to pk.toBytes(MLKEM_PK_LEN)
        } finally {
            seedSeg.wipe(); skSeed.wipe()
        }
    }

    fun x25519Keypair(secret: ByteArray): Pair<ByteArray, ByteArray> = Arena.ofConfined().use { a ->
        val secretSeg = a.seg(secret)
        val sk = a.allocate(X25519_LEN.toLong())
        val pk = a.allocate(X25519_LEN.toLong())
        try {
            val rc = x25519Keypair.invokeExact(
                secretSeg, secret.size.toLong(), sk, X25519_LEN.toLong(), pk, X25519_LEN.toLong()
            ) as Int
            checkOk("q_periapt_x25519_keypair", rc)
            sk.toBytes(X25519_LEN) to pk.toBytes(X25519_LEN)
        } finally {
            secretSeg.wipe(); sk.wipe()
        }
    }

    @Suppress("LongParameterList")
    fun decapsulate(
        profile: Byte, suiteId: ByteArray, policyVersion: Long,
        skPq: ByteArray, ctPq: ByteArray, pkPq: ByteArray,
        skTrad: ByteArray, ctTrad: ByteArray, pkTrad: ByteArray, context: ByteArray
    ): ByteArray = Arena.ofConfined().use { a ->
        val skPqSeg = a.seg(skPq)
        val skTradSeg = a.seg(skTrad)
        val out = a.allocate(SECRET_LEN.toLong())
        val checkedPolicyVersion = checkedUInt32("policyVersion", policyVersion)
        try {
            val rc = decap.invokeExact(
                profile, a.seg(suiteId), suiteId.size.toLong(), checkedPolicyVersion,
                skPqSeg, skPq.size.toLong(), a.seg(ctPq), ctPq.size.toLong(),
                a.seg(pkPq), pkPq.size.toLong(), skTradSeg, skTrad.size.toLong(),
                a.seg(ctTrad), ctTrad.size.toLong(), a.seg(pkTrad), pkTrad.size.toLong(),
                a.seg(context), context.size.toLong(), out, SECRET_LEN.toLong()
            ) as Int
            checkOk("q_periapt_hybrid_decapsulate", rc)
            out.toBytes(SECRET_LEN)
        } finally {
            skPqSeg.wipe(); skTradSeg.wipe(); out.wipe() // both secret keys + the session secret
        }
    }

    @Suppress("LongParameterList")
    fun encapsulate(
        profile: Byte, suiteId: ByteArray, policyVersion: Long,
        pkPq: ByteArray, pkTrad: ByteArray, context: ByteArray,
        randPq: ByteArray, randTrad: ByteArray
    ): EncapsulationResult = Arena.ofConfined().use { a ->
        val randPqSeg = a.seg(randPq)
        val randTradSeg = a.seg(randTrad)
        val outCtPq = a.allocate(MLKEM_CT_LEN.toLong())
        val outCtTrad = a.allocate(X25519_LEN.toLong())
        val outSecret = a.allocate(SECRET_LEN.toLong())
        val checkedPolicyVersion = checkedUInt32("policyVersion", policyVersion)
        try {
            val rc = encap.invokeExact(
                profile, a.seg(suiteId), suiteId.size.toLong(), checkedPolicyVersion,
                a.seg(pkPq), pkPq.size.toLong(), a.seg(pkTrad), pkTrad.size.toLong(),
                a.seg(context), context.size.toLong(), randPqSeg, randPq.size.toLong(),
                randTradSeg, randTrad.size.toLong(),
                outCtPq, MLKEM_CT_LEN.toLong(), outCtTrad, X25519_LEN.toLong(),
                outSecret, SECRET_LEN.toLong()
            ) as Int
            checkOk("q_periapt_hybrid_encapsulate", rc)
            EncapsulationResult(
                ctPq = outCtPq.toBytes(MLKEM_CT_LEN),
                ctTrad = outCtTrad.toBytes(X25519_LEN),
                secret = outSecret.toBytes(SECRET_LEN),
            )
        } finally {
            randPqSeg.wipe(); randTradSeg.wipe(); outSecret.wipe()
        }
    }

    /** Derive a combined secret directly from the serialized combiner inputs (the
     * cross-platform reference-vector entry point): `input` is the nine 8-byte
     * big-endian length-prefixed fields consumed by `q_periapt_combine`. */
    fun combine(profile: Byte, input: ByteArray): ByteArray = Arena.ofConfined().use { a ->
        val inputSeg = a.seg(input)
        val out = a.allocate(SECRET_LEN.toLong())
        try {
            val rc = combineFn.invokeExact(
                profile, inputSeg, input.size.toLong(), out, SECRET_LEN.toLong()
            ) as Int
            checkOk("q_periapt_combine", rc)
            out.toBytes(SECRET_LEN)
        } finally {
            inputSeg.wipe(); out.wipe() // input carries the component shared secrets
        }
    }
}
