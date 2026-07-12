package dev.qperiapt

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class QPeriaptHybridTest {
    private fun hex(s: String) = ByteArray(s.length / 2) {
        ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte()
    }

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
    fun sourceUsesScopedSecretSegmentOwner() {
        val source = File("src/main/kotlin/dev/qperiapt/QPeriaptHybrid.kt").readText()
        assertTrue(source.contains("private class SecretSegments"))
        assertTrue(source.contains("SecretSegments(a).use { secrets ->"))
        assertTrue(source.contains("val skPq = secrets.allocate"))
        assertTrue(source.contains("val skTrad = secrets.allocate"))
        assertTrue(source.contains("val outSecret = secrets.allocate"))
        assertFalse(source.contains("q_periapt_hybrid_encapsulate"))
        assertFalse(source.contains("q_periapt_combine"))
    }

    @Test
    fun runtimeMetadataMatchesCompiledBinding() {
        assertEquals(QPeriaptHybrid.ABI_VERSION, QPeriaptHybrid.runtimeAbiVersion())
        assertEquals("0.1.0-alpha.1", QPeriaptHybrid.runtimeVersion())
        assertContentEquals("ML-KEM-768+X25519".encodeToByteArray(), QPeriaptHybrid.fixedSuiteId())
        assertEquals("ML-KEM-768+X25519".length.toLong(), QPeriaptHybrid.fixedSuiteIdLen())
        assertEquals(65_536, QPeriaptHybrid.MAX_SIGNED_POLICY_BYTES)
        assertEquals(65_536, QPeriaptHybrid.MAX_APPLICATION_CONTEXT_BYTES)
        assertEquals("ERR_POLICY", QPeriaptHybrid.statusName(-3))
        assertEquals("ERR_ENTROPY", QPeriaptHybrid.statusName(-8))
    }

    @Test
    fun signedPolicySizeCapIsCheckedBeforeFfiMarshalling() {
        assertFailsWith<QPeriaptHybrid.QPeriaptException> {
            QPeriaptHybrid.decisionFromSignedPolicy(
                ByteArray(QPeriaptHybrid.MAX_SIGNED_POLICY_BYTES),
                byteArrayOf(),
                byteArrayOf(),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            QPeriaptHybrid.decisionFromSignedPolicy(
                ByteArray(QPeriaptHybrid.MAX_SIGNED_POLICY_BYTES + 1),
                byteArrayOf(),
                byteArrayOf(),
            )
        }
    }

    @Test
    fun signedPolicyControlsRandomProductPathAndRejectsLegacyRollbackAndTamper() {
        val json = File("../signed-policy-vectors.json").readText()
        val policy = stringField(json, "policy_toml").encodeToByteArray()
        val signature = hex(field(json, "signature"))
        val verificationKey = hex(field(json, "verification_key"))
        val decision = QPeriaptHybrid.decisionFromSignedPolicy(policy, signature, verificationKey)

        assertEquals(intField(json, "policy_version"), decision.policyVersion)
        assertEquals(QPeriaptHybrid.PROFILE_CONTEXT_BOUND, decision.profile)
        assertEquals(QPeriaptHybrid.KEY_FORMAT_EXPANDED, decision.keyFormat)
        assertContentEquals(hex(field(json, "policy_digest")), decision.policyDigest())
        assertEquals(QPeriaptHybrid.TRUSTED_POLICY_STATE_LEN, decision.trustedState().size)

        val reapplied = QPeriaptHybrid.decisionFromSignedPolicy(
            policy, signature, verificationKey, decision.trustedState()
        )
        assertContentEquals(decision.policyDigest(), reapplied.policyDigest())

        assertFailsWith<IllegalArgumentException> {
            QPeriaptHybrid.decisionFromSignedPolicy(
                policy,
                signature,
                verificationKey,
                byteArrayOf(0, 0, 0, decision.policyVersion.toByte()),
            )
        }

        val keys = QPeriaptHybrid.generateKeypair(decision)
        val context = "kotlin-policy-context".encodeToByteArray()
        val maximum = QPeriaptHybrid.encapsulate(
            decision,
            keys.pkPq,
            keys.pkTrad,
            ByteArray(QPeriaptHybrid.MAX_APPLICATION_CONTEXT_BYTES) { 1 },
        )
        maximum.wipeSecret()
        assertContentEquals(ByteArray(QPeriaptHybrid.SECRET_LEN), maximum.secret)
        assertFailsWith<IllegalArgumentException> {
            QPeriaptHybrid.encapsulate(
                decision,
                keys.pkPq,
                keys.pkTrad,
                ByteArray(QPeriaptHybrid.MAX_APPLICATION_CONTEXT_BYTES + 1),
            )
        }

        val enc = QPeriaptHybrid.encapsulate(decision, keys.pkPq, keys.pkTrad, context)
        val dec = QPeriaptHybrid.decapsulate(
            decision,
            keys.skPq,
            enc.ctPq,
            keys.pkPq,
            keys.skTrad,
            enc.ctTrad,
            keys.pkTrad,
            context,
        )
        assertContentEquals(enc.secret, dec)
        val wrongContext = QPeriaptHybrid.decapsulate(
            decision,
            keys.skPq,
            enc.ctPq,
            keys.pkPq,
            keys.skTrad,
            enc.ctTrad,
            keys.pkTrad,
            "wrong-context".encodeToByteArray(),
        )
        assertNotEquals(enc.secret.toList(), wrongContext.toList())

        val newerState = decision.trustedState()
        newerState[3] = 3
        val rollback = assertFailsWith<QPeriaptHybrid.QPeriaptException> {
            QPeriaptHybrid.decisionFromSignedPolicy(policy, signature, verificationKey, newerState)
        }
        assertEquals(-3, rollback.code)

        val tampered = signature.clone()
        tampered[intField(json, "tamper_signature_byte").toInt()] =
            (tampered[intField(json, "tamper_signature_byte").toInt()].toInt() xor 1).toByte()
        val badSignature = assertFailsWith<QPeriaptHybrid.QPeriaptException> {
            QPeriaptHybrid.decisionFromSignedPolicy(policy, tampered, verificationKey)
        }
        assertEquals(-3, badSignature.code)

        keys.wipeSecrets()
        assertContentEquals(ByteArray(QPeriaptHybrid.MLKEM_SK_LEN), keys.skPq)
        assertContentEquals(ByteArray(QPeriaptHybrid.X25519_LEN), keys.skTrad)
    }
}
