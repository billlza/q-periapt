package dev.qperiapt

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Cross-platform consistency: decapsulate the shared Rust-generated vector and
 * assert the secret matches byte-for-byte (bindings/shared-test-vectors.json).
 */
class QPeriaptHybridTest {
    private fun hex(s: String) = ByteArray(s.length / 2) {
        ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte()
    }

    // Minimal field extraction (the vector is a flat object of "key":"hex").
    private fun field(json: String, key: String): String =
        Regex("\"$key\"\\s*:\\s*\"([0-9a-f]*)\"").find(json)!!.groupValues[1]

    private fun intField(json: String, key: String): Long =
        Regex("\"$key\"\\s*:\\s*(\\d+)").find(json)!!.groupValues[1].toLong()

    private fun stringField(json: String, key: String): String =
        Regex("\"$key\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").find(json)!!.groupValues[1]
            .replace("\\n", "\n")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")

    @Test
    fun encapsulationWipesNativeRandomnessCopies() {
        val source = File("src/main/kotlin/dev/qperiapt/QPeriaptHybrid.kt").readText()
        assertTrue(source.contains("val randPqSeg = a.seg(randPq)"))
        assertTrue(source.contains("val randTradSeg = a.seg(randTrad)"))
        assertTrue(source.contains("randPqSeg.wipe(); randTradSeg.wipe(); outSecret.wipe()"))
        assertFalse(source.contains("a.seg(randPq), randPq.size.toLong()"))
        assertFalse(source.contains("a.seg(randTrad), randTrad.size.toLong()"))
    }

    @Test
    fun runtimeMetadataMatchesCompiledBinding() {
        assertEquals(QPeriaptHybrid.ABI_VERSION, QPeriaptHybrid.runtimeAbiVersion())
        assertEquals("0.0.1", QPeriaptHybrid.runtimeVersion())
        assertContentEquals("ML-KEM-768+X25519".encodeToByteArray(), QPeriaptHybrid.fixedSuiteId())
        assertEquals("ML-KEM-768+X25519".length.toLong(), QPeriaptHybrid.fixedSuiteIdLen())
        assertEquals("ERR_POLICY", QPeriaptHybrid.statusName(-3))
        assertEquals("UNKNOWN_STATUS", QPeriaptHybrid.statusName(12345))
    }

    @Test
    fun sharedVectorDecapsulates() {
        val json = File("../shared-test-vectors.json").readText()
        val secret = QPeriaptHybrid.decapsulate(
            profile = QPeriaptHybrid.PROFILE_CONTEXT_BOUND,
            suiteId = hex(field(json, "suite_id")),
            policyVersion = intField(json, "policy_version"),
            skPq = hex(field(json, "sk_pq")),
            ctPq = hex(field(json, "ct_pq")),
            pkPq = hex(field(json, "pk_pq")),
            skTrad = hex(field(json, "sk_trad")),
            ctTrad = hex(field(json, "ct_trad")),
            pkTrad = hex(field(json, "pk_trad")),
            context = hex(field(json, "context")),
        )
        assertContentEquals(hex(field(json, "secret")), secret,
            "Kotlin decapsulation must match the Rust core byte-for-byte")
    }

    @Test
    fun sharedVectorEncapsulates() {
        val json = File("../shared-test-vectors.json").readText()
        val enc = QPeriaptHybrid.encapsulate(
            profile = QPeriaptHybrid.PROFILE_CONTEXT_BOUND,
            suiteId = hex(field(json, "suite_id")),
            policyVersion = intField(json, "policy_version"),
            pkPq = hex(field(json, "pk_pq")),
            pkTrad = hex(field(json, "pk_trad")),
            context = hex(field(json, "context")),
            randPq = hex(field(json, "rand_pq")),
            randTrad = hex(field(json, "rand_trad")),
        )
        assertContentEquals(hex(field(json, "ct_pq")), enc.ctPq,
            "Kotlin ML-KEM ciphertext must match the Rust vector")
        assertContentEquals(hex(field(json, "ct_trad")), enc.ctTrad,
            "Kotlin X25519 ciphertext must match the Rust vector")
        assertContentEquals(hex(field(json, "secret")), enc.secret,
            "Kotlin encapsulated secret must match the Rust vector")
    }

    @Test
    fun contextBoundRejectsEmptyContext() {
        val json = File("../shared-test-vectors.json").readText()
        val err = assertFailsWith<QPeriaptHybrid.QPeriaptException> {
            QPeriaptHybrid.encapsulate(
                profile = QPeriaptHybrid.PROFILE_CONTEXT_BOUND,
                suiteId = hex(field(json, "suite_id")),
                policyVersion = intField(json, "policy_version"),
                pkPq = hex(field(json, "pk_pq")),
                pkTrad = hex(field(json, "pk_trad")),
                context = byteArrayOf(),
                randPq = hex(field(json, "rand_pq")),
                randTrad = hex(field(json, "rand_trad")),
            )
        }
        assertEquals(-2, err.code, "empty ContextBound context must be a length error")
    }

    @Test
    fun compatXWingSeedKeypairRoundtrip() {
        val (skPq, pkPq) = QPeriaptHybrid.mlkem768XWingKeypair(
            ByteArray(QPeriaptHybrid.MLKEM_XWING_SEED_LEN) { 7 }
        )
        val (skTrad, pkTrad) = QPeriaptHybrid.x25519Keypair(ByteArray(QPeriaptHybrid.X25519_LEN) { 9 })
        val enc = QPeriaptHybrid.encapsulate(
            profile = QPeriaptHybrid.PROFILE_COMPAT_XWING,
            suiteId = "ML-KEM-768+X25519".encodeToByteArray(),
            policyVersion = 1,
            pkPq = pkPq,
            pkTrad = pkTrad,
            context = byteArrayOf(),
            randPq = ByteArray(32) { 3 },
            randTrad = ByteArray(32) { 5 },
        )
        val dec = QPeriaptHybrid.decapsulate(
            profile = QPeriaptHybrid.PROFILE_COMPAT_XWING,
            suiteId = "ML-KEM-768+X25519".encodeToByteArray(),
            policyVersion = 1,
            skPq = skPq,
            ctPq = enc.ctPq,
            pkPq = pkPq,
            skTrad = skTrad,
            ctTrad = enc.ctTrad,
            pkTrad = pkTrad,
            context = byteArrayOf(),
        )
        assertContentEquals(enc.secret, dec,
            "Kotlin CompatXWing seed-dk roundtrip must match")
    }

    /** Cross-platform combiner reference vectors: feed each `input` blob to the C ABI
     * `combine` and assert the 32-byte key (bindings/contextbound-vectors.txt). */
    @Test
    fun combineReferenceVectors() {
        val text = File("../contextbound-vectors.txt").readText()
        var n = 0
        for (line in text.lines()) {
            val p = line.trim().split(" ")
            if (p.size != 3) continue
            val got = QPeriaptHybrid.combine(p[0].toByte(), hex(p[1]))
            assertContentEquals(hex(p[2]), got,
                "Kotlin combine must match the Rust core byte-for-byte")
            n++
        }
        assertEquals(6, n, "expected 6 reference vectors")
    }

    @Test
    fun signedPolicyVectorSelectsProfileAndRejectsRollbackAndTamper() {
        val json = File("../signed-policy-vectors.json").readText()
        val policyToml = stringField(json, "policy_toml").encodeToByteArray()
        val signature = hex(field(json, "signature"))
        val verificationKey = hex(field(json, "verification_key"))
        val expectedCode = intField(json, "selected_profile_code").toByte()

        val profile = QPeriaptHybrid.profileFromSignedPolicy(
            toml = policyToml,
            signature = signature,
            verificationKey = verificationKey,
            lastTrustedVersion = intField(json, "last_trusted_version_accept"),
        )
        assertEquals(expectedCode, profile)

        val rollback = assertFailsWith<QPeriaptHybrid.QPeriaptException> {
            QPeriaptHybrid.profileFromSignedPolicy(
                toml = policyToml,
                signature = signature,
                verificationKey = verificationKey,
                lastTrustedVersion = intField(json, "last_trusted_version_reject"),
            )
        }
        assertEquals(-3, rollback.code)

        val tampered = signature.copyOf()
        val tamperByte = intField(json, "tamper_signature_byte").toInt()
        tampered[tamperByte] = (tampered[tamperByte].toInt() xor 1).toByte()
        val tamper = assertFailsWith<QPeriaptHybrid.QPeriaptException> {
            QPeriaptHybrid.profileFromSignedPolicy(
                toml = policyToml,
                signature = tampered,
                verificationKey = verificationKey,
                lastTrustedVersion = 0,
            )
        }
        assertEquals(-3, tamper.code)
    }

    @Test
    fun uint32ScalarsRejectNegativeAndOverflowBeforeFfi() {
        val json = File("../shared-test-vectors.json").readText()
        assertFailsWith<IllegalArgumentException> {
            QPeriaptHybrid.encapsulate(
                profile = QPeriaptHybrid.PROFILE_CONTEXT_BOUND,
                suiteId = hex(field(json, "suite_id")),
                policyVersion = -1,
                pkPq = hex(field(json, "pk_pq")),
                pkTrad = hex(field(json, "pk_trad")),
                context = hex(field(json, "context")),
                randPq = hex(field(json, "rand_pq")),
                randTrad = hex(field(json, "rand_trad")),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            QPeriaptHybrid.profileFromSignedPolicy(
                toml = byteArrayOf(),
                signature = byteArrayOf(),
                verificationKey = byteArrayOf(),
                lastTrustedVersion = 0x1_0000_0000L,
            )
        }
    }
}
