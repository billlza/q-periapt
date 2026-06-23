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

/**
 * Kotlin face of the PQ/T hybrid suite over the `q-periapt-ffi` C ABI, via the Foreign
 * Function & Memory API (Project Panama, JDK 22+). One Rust core, byte-identical
 * across platforms — see bindings/README.md.
 *
 * Scaffold: not built in CI here yet (needs JDK 22+ and the linked native lib).
 */
object QPeriaptHybrid {
    const val PROFILE_COMPAT_XWING: Byte = 1
    const val PROFILE_CONTEXT_BOUND: Byte = 2
    const val SECRET_LEN = 32
    const val MLKEM_PK_LEN = 1184
    const val MLKEM_SK_LEN = 2400
    const val MLKEM_CT_LEN = 1088
    const val X25519_LEN = 32

    private val linker = Linker.nativeLinker()
    // Prefer an explicit absolute path (`-Dqperiapt.lib=...`); else resolve by name via
    // the OS loader. The absolute path is the robust choice on macOS, where the
    // dynamic loader does not consult java.library.path.
    private val lookup: SymbolLookup = run {
        val explicit = System.getProperty("qperiapt.lib")
        if (explicit != null) {
            SymbolLookup.libraryLookup(java.nio.file.Path.of(explicit), Arena.global())
        } else {
            SymbolLookup.libraryLookup(System.mapLibraryName("q_periapt_ffi"), Arena.global())
        }
    }

    private fun handle(name: String, desc: FunctionDescriptor) =
        linker.downcallHandle(lookup.find(name).orElseThrow { RuntimeException("missing symbol $name") }, desc)

    // (ptr,long) buffer pairs are modeled as ADDRESS + JAVA_LONG.
    private val keypairDesc = FunctionDescriptor.of(
        JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG
    )
    private val mlkemKeypair = handle("q_periapt_mlkem768_keypair", keypairDesc)
    private val x25519Keypair = handle("q_periapt_x25519_keypair", keypairDesc)

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

    fun mlkem768Keypair(seed: ByteArray): Pair<ByteArray, ByteArray> = Arena.ofConfined().use { a ->
        val sk = a.allocate(MLKEM_SK_LEN.toLong())
        val pk = a.allocate(MLKEM_PK_LEN.toLong())
        val rc = mlkemKeypair.invokeExact(
            a.seg(seed), seed.size.toLong(), sk, MLKEM_SK_LEN.toLong(), pk, MLKEM_PK_LEN.toLong()
        ) as Int
        require(rc == 0) { "q_periapt_mlkem768_keypair rc=$rc" }
        sk.toBytes(MLKEM_SK_LEN) to pk.toBytes(MLKEM_PK_LEN)
    }

    fun x25519Keypair(secret: ByteArray): Pair<ByteArray, ByteArray> = Arena.ofConfined().use { a ->
        val sk = a.allocate(X25519_LEN.toLong())
        val pk = a.allocate(X25519_LEN.toLong())
        val rc = x25519Keypair.invokeExact(
            a.seg(secret), secret.size.toLong(), sk, X25519_LEN.toLong(), pk, X25519_LEN.toLong()
        ) as Int
        require(rc == 0) { "q_periapt_x25519_keypair rc=$rc" }
        sk.toBytes(X25519_LEN) to pk.toBytes(X25519_LEN)
    }

    @Suppress("LongParameterList")
    fun decapsulate(
        profile: Byte, suiteId: ByteArray, policyVersion: Int,
        skPq: ByteArray, ctPq: ByteArray, pkPq: ByteArray,
        skTrad: ByteArray, ctTrad: ByteArray, pkTrad: ByteArray, context: ByteArray
    ): ByteArray = Arena.ofConfined().use { a ->
        val out = a.allocate(SECRET_LEN.toLong())
        val rc = decap.invokeExact(
            profile, a.seg(suiteId), suiteId.size.toLong(), policyVersion,
            a.seg(skPq), skPq.size.toLong(), a.seg(ctPq), ctPq.size.toLong(),
            a.seg(pkPq), pkPq.size.toLong(), a.seg(skTrad), skTrad.size.toLong(),
            a.seg(ctTrad), ctTrad.size.toLong(), a.seg(pkTrad), pkTrad.size.toLong(),
            a.seg(context), context.size.toLong(), out, SECRET_LEN.toLong()
        ) as Int
        require(rc == 0) { "q_periapt_hybrid_decapsulate rc=$rc" }
        out.toBytes(SECRET_LEN)
    }

    /** Derive a combined secret directly from the serialized combiner inputs (the
     * cross-platform reference-vector entry point): `input` is the nine 8-byte
     * big-endian length-prefixed fields consumed by `q_periapt_combine`. */
    fun combine(profile: Byte, input: ByteArray): ByteArray = Arena.ofConfined().use { a ->
        val out = a.allocate(SECRET_LEN.toLong())
        val rc = combineFn.invokeExact(
            profile, a.seg(input), input.size.toLong(), out, SECRET_LEN.toLong()
        ) as Int
        require(rc == 0) { "q_periapt_combine rc=$rc" }
        out.toBytes(SECRET_LEN)
    }
}
