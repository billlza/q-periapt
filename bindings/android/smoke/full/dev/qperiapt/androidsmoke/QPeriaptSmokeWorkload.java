package dev.qperiapt.androidsmoke;

import android.content.res.AssetManager;
import dev.qperiapt.android.QPeriaptAndroid;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.json.JSONObject;

/** The complete original device smoke workload, shared by SDK and AGP full consumers. */
final class QPeriaptSmokeWorkload {
    private final AssetManager assets;

    QPeriaptSmokeWorkload(AssetManager assets) {
        this.assets = assets;
    }

    void run(List<String> passed) throws Exception {
        runtimeMetadataMatches(passed);
        signedPolicyDecisionIsExactAndFailClosed(passed);
        osRandomPolicyRoundtripAndWipes(passed);
    }

    private void runtimeMetadataMatches(List<String> passed) {
        expect(QPeriaptAndroid.runtimeAbiVersion() == QPeriaptAndroid.ABI_VERSION, "ABI mismatch");
        expect("0.1.5".equals(QPeriaptAndroid.runtimeVersion()), "version mismatch");
        assertBytes("ML-KEM-768+X25519".getBytes(StandardCharsets.UTF_8), QPeriaptAndroid.fixedSuiteId(), "suite id");
        expect(QPeriaptAndroid.fixedSuiteIdLen() == "ML-KEM-768+X25519".length(), "suite len");
        expect(QPeriaptAndroid.MAX_SIGNED_POLICY_BYTES == 65536, "signed policy limit");
        expect(QPeriaptAndroid.MAX_APPLICATION_CONTEXT_BYTES == 65536, "application context limit");
        expect("ERR_POLICY".equals(QPeriaptAndroid.statusName(-3)), "status -3");
        expect("UNKNOWN_STATUS".equals(QPeriaptAndroid.statusName(12345)), "unknown status");
        passed.add("runtimeMetadataMatches");
    }

    private void signedPolicyDecisionIsExactAndFailClosed(List<String> passed) throws Exception {
        String json = asset("signed-policy-vectors.json");
        byte[] policyToml = stringField(json, "policy_toml").getBytes(StandardCharsets.UTF_8);
        byte[] signature = hex(field(json, "signature"));
        byte[] verificationKey = hex(field(json, "verification_key"));
        byte expected = (byte) intField(json, "selected_profile_code");
        QPeriaptAndroid.PolicyDecision decision = QPeriaptAndroid.decisionFromSignedPolicy(
                policyToml,
                signature,
                verificationKey
        );
        expect(decision.profile() == expected, "signed policy selected profile mismatch");
        expect(decision.suiteCode() == QPeriaptAndroid.SUITE_MLKEM768_X25519,
                "signed policy selected suite mismatch");
        expect(decision.policyVersion() == intField(json, "policy_version"),
                "signed policy selected version mismatch");
        assertBytes(hex(field(json, "policy_digest")), decision.policyDigest(),
                "exact signed policy digest");
        QPeriaptAndroid.PolicyDecision reapplied = QPeriaptAndroid.decisionFromSignedPolicy(
                policyToml,
                signature,
                verificationKey,
                decision.trustedState()
        );
        assertBytes(decision.policyDigest(), reapplied.policyDigest(), "reapplied policy digest");
        try {
            QPeriaptAndroid.decisionFromSignedPolicy(
                    policyToml, signature, verificationKey, new byte[] {0, 0, 0, 2});
            throw new AssertionError("legacy ABI1 version-only state was accepted");
        } catch (IllegalArgumentException expectedLegacyStateFailure) {
            // ABI1 has no exact policy digest and therefore cannot be migrated automatically.
        }
        try {
            QPeriaptAndroid.decisionFromSignedPolicy(
                    new byte[QPeriaptAndroid.MAX_SIGNED_POLICY_BYTES], signature, verificationKey);
            throw new AssertionError("maximum-size invalid policy unexpectedly verified");
        } catch (QPeriaptAndroid.QPeriaptException expectedPolicyFailure) {
            // The exact boundary reached native verification rather than the facade size guard.
        }
        try {
            QPeriaptAndroid.decisionFromSignedPolicy(
                    new byte[QPeriaptAndroid.MAX_SIGNED_POLICY_BYTES + 1], signature, verificationKey);
            throw new AssertionError("oversized policy reached native verification");
        } catch (IllegalArgumentException expectedSizeFailure) {
            // The Java facade rejects before JNI copies the policy.
        }
        byte[] newerState = decision.trustedState();
        newerState[0] = 0;
        newerState[1] = 0;
        newerState[2] = 0;
        newerState[3] = (byte) intField(json, "last_trusted_version_reject");
        try {
            QPeriaptAndroid.decisionFromSignedPolicy(
                    policyToml,
                    signature,
                    verificationKey,
                    newerState
            );
            throw new AssertionError("rollback policy was accepted");
        } catch (QPeriaptAndroid.QPeriaptException err) {
            expect(err.code() == -3, "rollback rc=" + err.code());
        }
        byte[] tampered = signature.clone();
        int tamperByte = (int) intField(json, "tamper_signature_byte");
        tampered[tamperByte] = (byte) (tampered[tamperByte] ^ 1);
        try {
            QPeriaptAndroid.decisionFromSignedPolicy(policyToml, tampered, verificationKey);
            throw new AssertionError("tampered policy signature was accepted");
        } catch (QPeriaptAndroid.QPeriaptException err) {
            expect(err.code() == -3, "tamper rc=" + err.code());
        }
        passed.add("signedPolicyDecisionIsExactAndFailClosed");
    }

    private void osRandomPolicyRoundtripAndWipes(List<String> passed) throws Exception {
        String json = asset("signed-policy-vectors.json");
        QPeriaptAndroid.PolicyDecision decision = QPeriaptAndroid.decisionFromSignedPolicy(
                stringField(json, "policy_toml").getBytes(StandardCharsets.UTF_8),
                hex(field(json, "signature")),
                hex(field(json, "verification_key")));
        byte[] applicationContext = "android-device-policy-context".getBytes(StandardCharsets.UTF_8);

        QPeriaptAndroid.KeyPairResult keys = QPeriaptAndroid.generateKeypair(decision);
        try (keys) {
            byte[] skPq = keys.skPq();
            byte[] skTrad = keys.skTrad();
            byte[] encapsulatedSecret = null;
            byte[] decapsulatedSecret = null;
            byte[] wrongContextSecret = null;
            try {
                try (QPeriaptAndroid.EncapsulationResult maximumContext =
                                QPeriaptAndroid.encapsulate(
                                        decision,
                                        keys.pkPq(),
                                        keys.pkTrad(),
                                        fill(QPeriaptAndroid.MAX_APPLICATION_CONTEXT_BYTES, 1))) {
                    byte[] maximumSecret = maximumContext.takeSecret();
                    QPeriaptAndroid.wipe(maximumSecret);
                    assertWiped(maximumSecret, "maximum application-context secret");
                }
                try {
                    QPeriaptAndroid.encapsulate(
                            decision,
                            keys.pkPq(),
                            keys.pkTrad(),
                            new byte[QPeriaptAndroid.MAX_APPLICATION_CONTEXT_BYTES + 1]);
                    throw new AssertionError("oversized application context reached JNI");
                } catch (IllegalArgumentException expectedSizeFailure) {
                    // The Java facade rejects before JNI copies the context.
                }
                try (QPeriaptAndroid.EncapsulationResult encapsulation =
                                QPeriaptAndroid.encapsulate(
                                        decision, keys.pkPq(), keys.pkTrad(), applicationContext)) {
                    encapsulatedSecret = encapsulation.takeSecret();
                    try {
                        encapsulation.secret();
                        throw new AssertionError("transferred encapsulation secret remained readable");
                    } catch (IllegalStateException expectedClosedResult) {
                        // takeSecret transfers the sole binding-owned secret and closes the result.
                    }
                    decapsulatedSecret = QPeriaptAndroid.decapsulate(
                            decision,
                            skPq,
                            encapsulation.ctPq(),
                            keys.pkPq(),
                            skTrad,
                            encapsulation.ctTrad(),
                            keys.pkTrad(),
                            applicationContext);
                    assertBytes(encapsulatedSecret, decapsulatedSecret,
                            "OS-random policy-bound roundtrip");
                    wrongContextSecret = QPeriaptAndroid.decapsulate(
                            decision,
                            skPq,
                            encapsulation.ctPq(),
                            keys.pkPq(),
                            skTrad,
                            encapsulation.ctTrad(),
                            keys.pkTrad(),
                            "wrong-context".getBytes(StandardCharsets.UTF_8));
                    expect(!bytesEqual(decapsulatedSecret, wrongContextSecret),
                            "application context was not committed");
                }
            } finally {
                QPeriaptAndroid.wipe(skPq);
                QPeriaptAndroid.wipe(skTrad);
                if (encapsulatedSecret != null) {
                    QPeriaptAndroid.wipe(encapsulatedSecret);
                }
                if (decapsulatedSecret != null) {
                    QPeriaptAndroid.wipe(decapsulatedSecret);
                }
                if (wrongContextSecret != null) {
                    QPeriaptAndroid.wipe(wrongContextSecret);
                }
            }
            assertWiped(skPq, "ML-KEM secret key");
            assertWiped(skTrad, "X25519 secret key");
            if (encapsulatedSecret != null) {
                assertWiped(encapsulatedSecret, "encapsulated secret");
            }
            if (decapsulatedSecret != null) {
                assertWiped(decapsulatedSecret, "decapsulated secret");
            }
            if (wrongContextSecret != null) {
                assertWiped(wrongContextSecret, "wrong-context secret");
            }
        }
        try {
            keys.skPq();
            throw new AssertionError("closed key-pair secrets remained readable");
        } catch (IllegalStateException expectedClosedKeys) {
            // close wipes the binding-owned key buffers and seals their accessors.
        }

        try {
            QPeriaptAndroid.decisionFromSignedPolicy(
                    new byte[0], new byte[0], new byte[0], new byte[1]);
            throw new AssertionError("malformed lastTrustedState was accepted");
        } catch (IllegalArgumentException expectedMalformedState) {
            // Malformed state never reaches native verification.
        }
        passed.add("osRandomPolicyRoundtripAndWipes");
    }

    private String asset(String name) throws Exception {
        InputStream in = assets.open(name);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            while (true) {
                int n = in.read(buf);
                if (n < 0) {
                    break;
                }
                out.write(buf, 0, n);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        } finally {
            in.close();
        }
    }

    private static byte[] hex(String text) {
        if ((text.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(text.charAt(i * 2), 16);
            int lo = Character.digit(text.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static String field(String json, String name) throws Exception {
        return new JSONObject(json).getString(name);
    }

    private static long intField(String json, String name) throws Exception {
        return new JSONObject(json).getLong(name);
    }

    private static String stringField(String json, String name) throws Exception {
        return new JSONObject(json).getString(name);
    }

    private static byte[] fill(int len, int value) {
        byte[] out = new byte[len];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) value;
        }
        return out;
    }

    private static void assertBytes(byte[] expected, byte[] got, String label) {
        if (expected.length != got.length) {
            throw new AssertionError(label + " length mismatch");
        }
        for (int i = 0; i < expected.length; i++) {
            if (expected[i] != got[i]) {
                throw new AssertionError(label + " mismatch at byte " + i);
            }
        }
    }

    private static void assertWiped(byte[] value, String label) {
        for (int i = 0; i < value.length; i++) {
            if (value[i] != 0) {
                throw new AssertionError(label + " was not wiped at byte " + i);
            }
        }
    }

    private static boolean bytesEqual(byte[] left, byte[] right) {
        if (left.length != right.length) {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < left.length; i++) {
            difference |= left[i] ^ right[i];
        }
        return difference == 0;
    }

    private static void expect(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }

}
