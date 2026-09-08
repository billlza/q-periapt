package dev.qperiapt

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
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
    fun resultDescriptionsRedactSecretsAndPreserveDataClassOperations() {
        // These are fixed public sample bytes, not key material from a native call.
        val encapsulation = QPeriaptHybrid.EncapsulationResult(
            byteArrayOf(1, 2), byteArrayOf(3, 4), byteArrayOf(71, 72)
        )
        assertEquals(
            "EncapsulationResult(ctPq=[1, 2], ctTrad=[3, 4], secret=<redacted>)",
            encapsulation.toString(),
        )
        val encapsulationCopy = encapsulation.copy()
        assertEquals(encapsulation, encapsulationCopy)
        val (ctPq, ctTrad, secret) = encapsulationCopy
        assertSame(encapsulation.ctPq, ctPq)
        assertSame(encapsulation.ctTrad, ctTrad)
        assertSame(encapsulation.secret, secret)
        assertContentEquals(byteArrayOf(71, 72), secret)

        val keys = QPeriaptHybrid.KeyPairResult(
            byteArrayOf(81, 82), byteArrayOf(5, 6), byteArrayOf(91, 92), byteArrayOf(7, 8)
        )
        assertEquals(
            "KeyPairResult(skPq=<redacted>, pkPq=[5, 6], skTrad=<redacted>, pkTrad=[7, 8])",
            keys.toString(),
        )
        val keysCopy = keys.copy()
        assertEquals(keys, keysCopy)
        val (skPq, pkPq, skTrad, pkTrad) = keysCopy
        assertSame(keys.skPq, skPq)
        assertSame(keys.pkPq, pkPq)
        assertSame(keys.skTrad, skTrad)
        assertSame(keys.pkTrad, pkTrad)
        assertContentEquals(byteArrayOf(81, 82), skPq)
        assertContentEquals(byteArrayOf(91, 92), skTrad)
    }

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
        assertEquals("0.1.5", QPeriaptHybrid.runtimeVersion())
        assertContentEquals("ML-KEM-768+X25519".encodeToByteArray(), QPeriaptHybrid.fixedSuiteId())
        assertEquals("ML-KEM-768+X25519".length.toLong(), QPeriaptHybrid.fixedSuiteIdLen())
        assertEquals(65_536, QPeriaptHybrid.MAX_SIGNED_POLICY_BYTES)
        assertEquals(65_536, QPeriaptHybrid.MAX_APPLICATION_CONTEXT_BYTES)
        assertEquals("ERR_POLICY", QPeriaptHybrid.statusName(-3))
        assertEquals("ERR_ENTROPY", QPeriaptHybrid.statusName(-8))
    }

    @Test
    fun signedPolicySizeCapIsCheckedBeforeFfiMarshalling() {
        val fixture = File("../signed-policy-vectors.json").readText()
        val signature = hex(field(fixture, "signature"))
        val verificationKey = hex(field(fixture, "verification_key"))
        assertFailsWith<QPeriaptHybrid.QPeriaptException> {
            QPeriaptHybrid.decisionFromSignedPolicy(
                ByteArray(QPeriaptHybrid.MAX_SIGNED_POLICY_BYTES),
                signature,
                verificationKey,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            QPeriaptHybrid.decisionFromSignedPolicy(
                ByteArray(QPeriaptHybrid.MAX_SIGNED_POLICY_BYTES + 1),
                signature,
                verificationKey,
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
    private fun assertNativeError(operation: String, code: Int, action: () -> Unit) {
        val failure = assertFailsWith<QPeriaptHybrid.QPeriaptException>(block = action)
        assertEquals(operation, failure.operation)
        assertEquals(code, failure.code)
    }

    @Test
    fun fixedKemLengthsKeepNativeErrorMappingAndContextPriority() {
        val fixture = File("../signed-policy-vectors.json").readText()
        val decision = QPeriaptHybrid.decisionFromSignedPolicy(
            stringField(fixture, "policy_toml").encodeToByteArray(),
            hex(field(fixture, "signature")),
            hex(field(fixture, "verification_key")),
        )
        val keys = QPeriaptHybrid.generateKeypair(decision)
        val context = byteArrayOf(1)
        val encapsulated = QPeriaptHybrid.encapsulate(decision, keys.pkPq, keys.pkTrad, context)
        try {
            val publicKeys = arrayOf(keys.pkPq, keys.pkTrad)
            for (index in publicKeys.indices) {
                for (length in listOf(0, publicKeys[index].size - 1, publicKeys[index].size + 1, 8192)) {
                    val inputs = publicKeys.copyOf()
                    inputs[index] = ByteArray(length)
                    assertNativeError("q_periapt_encapsulate", -2) {
                        QPeriaptHybrid.encapsulate(decision, inputs[0], inputs[1], context)
                    }
                }
            }
            val decapsulationInputs = arrayOf(
                keys.skPq, encapsulated.ctPq, keys.pkPq,
                keys.skTrad, encapsulated.ctTrad, keys.pkTrad,
            )
            for (index in decapsulationInputs.indices) {
                for (length in listOf(0, decapsulationInputs[index].size - 1, decapsulationInputs[index].size + 1, 8192)) {
                    val inputs = decapsulationInputs.copyOf()
                    inputs[index] = ByteArray(length)
                    assertNativeError("q_periapt_decapsulate", -2) {
                        QPeriaptHybrid.decapsulate(
                            decision, inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5], context,
                        )
                    }
                }
            }
            val exact = QPeriaptHybrid.decapsulate(
                decision, keys.skPq, encapsulated.ctPq, keys.pkPq,
                keys.skTrad, encapsulated.ctTrad, keys.pkTrad, context,
            )
            try {
                assertContentEquals(encapsulated.secret, exact)
            } finally {
                exact.fill(0)
            }
            val oversizedContext = ByteArray(QPeriaptHybrid.MAX_APPLICATION_CONTEXT_BYTES + 1)
            assertFailsWith<IllegalArgumentException> {
                QPeriaptHybrid.encapsulate(decision, byteArrayOf(), keys.pkTrad, oversizedContext)
            }
            assertFailsWith<IllegalArgumentException> {
                QPeriaptHybrid.decapsulate(
                    decision, byteArrayOf(), encapsulated.ctPq, keys.pkPq,
                    keys.skTrad, encapsulated.ctTrad, keys.pkTrad, oversizedContext,
                )
            }
            // A Java caller's null input still precedes both context and shape failures.
            val method = QPeriaptHybrid.javaClass.getMethod(
                "encapsulate", QPeriaptHybrid.PolicyDecision::class.java,
                ByteArray::class.java, ByteArray::class.java, ByteArray::class.java,
            )
            val nullFailure = assertFailsWith<java.lang.reflect.InvocationTargetException> {
                method.invoke(QPeriaptHybrid, decision, byteArrayOf(), null, oversizedContext)
            }
            assertTrue(nullFailure.cause is NullPointerException)
        } finally {
            encapsulated.wipeSecret()
            keys.wipeSecrets()
        }
        assertTrue(keys.skPq.all { it == 0.toByte() })
        assertTrue(keys.skTrad.all { it == 0.toByte() })
        assertTrue(encapsulated.secret.all { it == 0.toByte() })
    }

    @Test
    fun fixedPolicyLengthsKeepPolicyErrorsAndStatePriority() {
        val fixture = File("../signed-policy-vectors.json").readText()
        val policy = stringField(fixture, "policy_toml").encodeToByteArray()
        val signature = hex(field(fixture, "signature"))
        val key = hex(field(fixture, "verification_key"))
        assertEquals(QPeriaptHybrid.POLICY_SIGNATURE_LEN, signature.size)
        assertEquals(QPeriaptHybrid.POLICY_VERIFICATION_KEY_LEN, key.size)
        val decision = QPeriaptHybrid.decisionFromSignedPolicy(policy, signature, key)
        val inputs = arrayOf(signature, key)
        for (index in inputs.indices) {
            for (length in listOf(0, inputs[index].size - 1, inputs[index].size + 1, 8192)) {
                val invalid = inputs.copyOf()
                invalid[index] = ByteArray(length)
                assertNativeError("q_periapt_decision_from_signed_policy", -3) {
                    QPeriaptHybrid.decisionFromSignedPolicy(policy, invalid[0], invalid[1])
                }
            }
        }
        assertContentEquals(
            decision.policyDigest(),
            QPeriaptHybrid.decisionFromSignedPolicy(policy, signature, key, decision.trustedState()).policyDigest(),
        )
        for (length in listOf(1, QPeriaptHybrid.TRUSTED_POLICY_STATE_LEN - 1, QPeriaptHybrid.TRUSTED_POLICY_STATE_LEN + 1)) {
            assertFailsWith<IllegalArgumentException> {
                QPeriaptHybrid.decisionFromSignedPolicy(policy, byteArrayOf(), key, ByteArray(length))
            }
        }
        assertFailsWith<IllegalArgumentException> {
            QPeriaptHybrid.decisionFromSignedPolicy(
                ByteArray(QPeriaptHybrid.MAX_SIGNED_POLICY_BYTES + 1), byteArrayOf(), key,
            )
        }
    }

}
