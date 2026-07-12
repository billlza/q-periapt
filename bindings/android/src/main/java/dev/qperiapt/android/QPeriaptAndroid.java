package dev.qperiapt.android;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * Android facade over the q-periapt-ffi C ABI.
 *
 * <p>This class loads only the native libraries packaged in the app/AAR for the
 * device ABI. It does not search external or writable paths. Result objects that
 * retain secret material must be closed; caller-owned byte arrays that contain
 * secrets must be passed to {@link #wipe(byte[])} after use. Native temporary
 * copies are wiped before the JNI call returns. JVM/OS copies remain outside the
 * binding's control.</p>
 */
public final class QPeriaptAndroid {
    public static final int ABI_VERSION = 2;
    public static final byte PROFILE_CONTEXT_BOUND = 2;
    public static final int SECRET_LEN = 32;
    public static final int MLKEM_PK_LEN = 1184;
    public static final int MLKEM_SK_LEN = 2400;
    public static final int MLKEM_CT_LEN = 1088;
    public static final int X25519_LEN = 32;
    public static final int POLICY_DECISION_LEN = 40;
    public static final int TRUSTED_POLICY_STATE_LEN = 36;
    public static final int MAX_SIGNED_POLICY_BYTES = 64 * 1024;
    public static final int MAX_APPLICATION_CONTEXT_BYTES = 64 * 1024;
    public static final byte SUITE_MLKEM768_X25519 = 1;
    public static final byte KEY_FORMAT_EXPANDED = 1;
    private static final String FIXED_SUITE_ID = "ML-KEM-768+X25519";

    static {
        System.loadLibrary("q_periapt_ffi_abi2");
        System.loadLibrary("qperiapt_jni_abi2");
        validateRuntimeMetadata();
    }

    private QPeriaptAndroid() {
    }

    public static final class QPeriaptException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final String operation;
        private final int code;
        private final String statusName;

        public QPeriaptException(String operation, int code, String statusName) {
            super(operation + " rc=" + code + " (" + statusName + ")");
            this.operation = operation;
            this.code = code;
            this.statusName = statusName;
        }

        public String operation() {
            return operation;
        }

        public int code() {
            return code;
        }

        public String statusName() {
            return statusName;
        }
    }

    public static final class KeyPairResult implements AutoCloseable {
        private byte[] skPq;
        private final byte[] pkPq;
        private byte[] skTrad;
        private final byte[] pkTrad;
        private boolean closed;

        private KeyPairResult(byte[] skPq, byte[] pkPq, byte[] skTrad, byte[] pkTrad) {
            this.skPq = skPq;
            this.pkPq = pkPq;
            this.skTrad = skTrad;
            this.pkTrad = pkTrad;
        }

        public synchronized byte[] skPq() {
            if (closed) {
                throw new IllegalStateException("KeyPairResult secrets are closed");
            }
            return skPq.clone();
        }

        public synchronized byte[] skTrad() {
            if (closed) {
                throw new IllegalStateException("KeyPairResult secrets are closed");
            }
            return skTrad.clone();
        }

        public byte[] pkPq() {
            return pkPq.clone();
        }

        public byte[] pkTrad() {
            return pkTrad.clone();
        }

        @Override
        public synchronized void close() {
            if (!closed) {
                wipe(skPq);
                wipe(skTrad);
                skPq = null;
                skTrad = null;
                closed = true;
            }
        }
    }

    public static final class EncapsulationResult implements AutoCloseable {
        private final byte[] ctPq;
        private final byte[] ctTrad;
        private byte[] secret;
        private boolean closed;

        private EncapsulationResult(byte[] ctPq, byte[] ctTrad, byte[] secret) {
            this.ctPq = ctPq;
            this.ctTrad = ctTrad;
            this.secret = secret;
        }

        public byte[] ctPq() {
            return ctPq.clone();
        }

        public byte[] ctTrad() {
            return ctTrad.clone();
        }

        public synchronized byte[] secret() {
            if (closed) {
                throw new IllegalStateException("EncapsulationResult secret is closed");
            }
            return secret.clone();
        }

        /**
         * Transfer the sole binding-owned session-secret array to the caller.
         * The result is closed atomically; the caller must pass the returned
         * array to {@link QPeriaptAndroid#wipe(byte[])} after use.
         */
        public synchronized byte[] takeSecret() {
            if (closed) {
                throw new IllegalStateException("EncapsulationResult secret is closed");
            }
            byte[] value = secret;
            secret = null;
            closed = true;
            return value;
        }

        @Override
        public synchronized void close() {
            if (!closed) {
                wipe(secret);
                secret = null;
                closed = true;
            }
        }
    }

    /** Best-effort zeroization of one caller-owned secret array. */
    public static void wipe(byte[] secret) {
        Arrays.fill(Objects.requireNonNull(secret, "secret"), (byte) 0);
    }

    /** Atomic suite/profile/version result of a verified signed policy. */
    public static final class PolicyDecision {
        private final byte suiteCode;
        private final byte profile;
        private final byte keyFormat;
        private final long policyVersion;
        private final byte[] policyDigest;
        private final byte[] encoded;

        private PolicyDecision(byte[] encoded) {
            if (encoded.length != POLICY_DECISION_LEN || encoded[0] != 1
                    || encoded[1] != SUITE_MLKEM768_X25519
                    || encoded[2] != PROFILE_CONTEXT_BOUND
                    || encoded[3] != KEY_FORMAT_EXPANDED) {
                throw new IllegalArgumentException("invalid native policy decision");
            }
            suiteCode = encoded[1];
            profile = encoded[2];
            keyFormat = encoded[3];
            policyVersion = ((long) Byte.toUnsignedInt(encoded[4]) << 24)
                    | ((long) Byte.toUnsignedInt(encoded[5]) << 16)
                    | ((long) Byte.toUnsignedInt(encoded[6]) << 8)
                    | Byte.toUnsignedInt(encoded[7]);
            if (policyVersion == 0) {
                throw new IllegalArgumentException("zero policy version");
            }
            policyDigest = Arrays.copyOfRange(encoded, 8, POLICY_DECISION_LEN);
            this.encoded = encoded.clone();
        }

        public byte suiteCode() {
            return suiteCode;
        }

        public byte profile() {
            return profile;
        }

        public byte keyFormat() {
            return keyFormat;
        }

        public long policyVersion() {
            return policyVersion;
        }

        public byte[] policyDigest() {
            return policyDigest.clone();
        }

        /** Persist atomically and pass to the next signed-policy decision load. */
        public byte[] trustedState() {
            byte[] state = new byte[TRUSTED_POLICY_STATE_LEN];
            state[0] = (byte) (policyVersion >>> 24);
            state[1] = (byte) (policyVersion >>> 16);
            state[2] = (byte) (policyVersion >>> 8);
            state[3] = (byte) policyVersion;
            System.arraycopy(policyDigest, 0, state, 4, policyDigest.length);
            return state;
        }

        private byte[] encoded() {
            return encoded.clone();
        }
    }

    public static int runtimeAbiVersion() {
        return runtimeAbiVersionNative();
    }

    public static String runtimeVersion() {
        return runtimeVersionNative();
    }

    public static byte[] fixedSuiteId() {
        return fixedSuiteIdNative().getBytes(StandardCharsets.UTF_8);
    }

    public static long fixedSuiteIdLen() {
        return fixedSuiteIdLenNative();
    }

    public static String statusName(int code) {
        return statusNameNative(code);
    }

    public static PolicyDecision decisionFromSignedPolicy(
            byte[] toml,
            byte[] signature,
            byte[] verificationKey,
            byte[] lastTrustedState
    ) {
        requireNonNull(toml, "toml");
        requireNonNull(signature, "signature");
        requireNonNull(verificationKey, "verificationKey");
        requireNonNull(lastTrustedState, "lastTrustedState");
        requireAtMost("toml", toml, MAX_SIGNED_POLICY_BYTES);
        if (lastTrustedState.length != 0
                && lastTrustedState.length != TRUSTED_POLICY_STATE_LEN) {
            throw new IllegalArgumentException(
                    "lastTrustedState must be empty or " + TRUSTED_POLICY_STATE_LEN + " bytes");
        }
        return new PolicyDecision(decisionFromSignedPolicyNative(
                toml,
                signature,
                verificationKey,
                lastTrustedState
        ));
    }

    public static PolicyDecision decisionFromSignedPolicy(
            byte[] toml,
            byte[] signature,
            byte[] verificationKey
    ) {
        return decisionFromSignedPolicy(toml, signature, verificationKey, new byte[0]);
    }

    public static KeyPairResult generateKeypair(PolicyDecision decision) {
        Objects.requireNonNull(decision, "decision must not be null");
        byte[] skPq = new byte[MLKEM_SK_LEN];
        byte[] pkPq = new byte[MLKEM_PK_LEN];
        byte[] skTrad = new byte[X25519_LEN];
        byte[] pkTrad = new byte[X25519_LEN];
        try {
            generateKeypairNative(decision.encoded(), skPq, pkPq, skTrad, pkTrad);
        } catch (RuntimeException | Error failure) {
            wipe(skPq);
            wipe(skTrad);
            throw failure;
        }
        return new KeyPairResult(skPq, pkPq, skTrad, pkTrad);
    }

    /** Encapsulate while committing the exact signed-policy digest and application context. */
    public static EncapsulationResult encapsulate(
            PolicyDecision decision,
            byte[] pkPq,
            byte[] pkTrad,
            byte[] applicationContext
    ) {
        Objects.requireNonNull(decision, "decision must not be null");
        requireNonNull(pkPq, "pkPq");
        requireNonNull(pkTrad, "pkTrad");
        requireNonNull(applicationContext, "applicationContext");
        requireAtMost("applicationContext", applicationContext, MAX_APPLICATION_CONTEXT_BYTES);
        byte[] ctPq = new byte[MLKEM_CT_LEN];
        byte[] ctTrad = new byte[X25519_LEN];
        byte[] secret = new byte[SECRET_LEN];
        try {
            encapsulateNative(
                    decision.encoded(), pkPq, pkTrad, applicationContext,
                    ctPq, ctTrad, secret);
        } catch (RuntimeException | Error failure) {
            wipe(secret);
            throw failure;
        }
        return new EncapsulationResult(ctPq, ctTrad, secret);
    }

    /** Decapsulate under the same decision and application context. */
    public static byte[] decapsulate(
            PolicyDecision decision,
            byte[] skPq,
            byte[] ctPq,
            byte[] pkPq,
            byte[] skTrad,
            byte[] ctTrad,
            byte[] pkTrad,
            byte[] applicationContext
    ) {
        Objects.requireNonNull(decision, "decision must not be null");
        requireNonNull(skPq, "skPq");
        requireNonNull(ctPq, "ctPq");
        requireNonNull(pkPq, "pkPq");
        requireNonNull(skTrad, "skTrad");
        requireNonNull(ctTrad, "ctTrad");
        requireNonNull(pkTrad, "pkTrad");
        requireNonNull(applicationContext, "applicationContext");
        requireAtMost("applicationContext", applicationContext, MAX_APPLICATION_CONTEXT_BYTES);
        byte[] secret = new byte[SECRET_LEN];
        try {
            decapsulateNative(
                    decision.encoded(), skPq, ctPq, pkPq, skTrad, ctTrad, pkTrad,
                    applicationContext, secret);
        } catch (RuntimeException | Error failure) {
            wipe(secret);
            throw failure;
        }
        return secret;
    }

    private static void validateRuntimeMetadata() {
        if (runtimeAbiVersion() != ABI_VERSION) {
            throw new IllegalStateException(
                    "q-periapt ABI mismatch: header=" + ABI_VERSION + " runtime=" + runtimeAbiVersion()
            );
        }
        String fixedSuite = fixedSuiteIdNative();
        if (!FIXED_SUITE_ID.equals(fixedSuite)) {
            throw new IllegalStateException("q-periapt fixed suite mismatch: " + fixedSuite);
        }
        if (fixedSuiteIdLen() != FIXED_SUITE_ID.length()) {
            throw new IllegalStateException(
                    "q-periapt fixed suite length mismatch: " + fixedSuiteIdLen()
            );
        }
    }

    private static void requireAtMost(String label, byte[] value, int maximum) {
        if (value.length > maximum) {
            throw new IllegalArgumentException(
                    label + " exceeds " + maximum + " bytes: " + value.length);
        }
    }

    private static void requireNonNull(byte[] value, String label) {
        Objects.requireNonNull(value, label + " must not be null");
    }

    private static native int runtimeAbiVersionNative();

    private static native String runtimeVersionNative();

    private static native String fixedSuiteIdNative();

    private static native long fixedSuiteIdLenNative();

    private static native String statusNameNative(int code);

    private static native byte[] decisionFromSignedPolicyNative(
            byte[] toml,
            byte[] signature,
            byte[] verificationKey,
            byte[] lastTrustedState
    );

    private static native void generateKeypairNative(
            byte[] decision,
            byte[] outSkPq,
            byte[] outPkPq,
            byte[] outSkTrad,
            byte[] outPkTrad
    );

    private static native void encapsulateNative(
            byte[] decision,
            byte[] pkPq,
            byte[] pkTrad,
            byte[] applicationContext,
            byte[] outCtPq,
            byte[] outCtTrad,
            byte[] outSecret
    );

    private static native void decapsulateNative(
            byte[] decision,
            byte[] skPq,
            byte[] ctPq,
            byte[] pkPq,
            byte[] skTrad,
            byte[] ctTrad,
            byte[] pkTrad,
            byte[] applicationContext,
            byte[] outSecret
    );
}
