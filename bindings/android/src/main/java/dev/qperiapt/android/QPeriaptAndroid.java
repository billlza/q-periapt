package dev.qperiapt.android;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Android facade over the q-periapt-ffi C ABI.
 *
 * <p>This class loads only the native libraries packaged in the app/AAR for the
 * device ABI. It does not search external or writable paths. Caller-owned byte
 * arrays that contain secrets remain the caller's responsibility to clear after
 * use; native temporary copies are wiped before the JNI call returns.</p>
 */
public final class QPeriaptAndroid {
    public static final int ABI_VERSION = 1;
    public static final byte PROFILE_COMPAT_XWING = 1;
    public static final byte PROFILE_CONTEXT_BOUND = 2;
    public static final int SECRET_LEN = 32;
    public static final int MLKEM_PK_LEN = 1184;
    public static final int MLKEM_SK_LEN = 2400;
    public static final int MLKEM_XWING_SEED_LEN = 32;
    public static final int MLKEM_CT_LEN = 1088;
    public static final int X25519_LEN = 32;

    private static final long UINT32_MAX = 0xffff_ffffL;
    private static final String FIXED_SUITE_ID = "ML-KEM-768+X25519";

    static {
        System.loadLibrary("q_periapt_ffi");
        System.loadLibrary("qperiapt_jni");
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

    public static final class KeyPairResult {
        private final byte[] secretKey;
        private final byte[] publicKey;

        private KeyPairResult(byte[] secretKey, byte[] publicKey) {
            this.secretKey = secretKey;
            this.publicKey = publicKey;
        }

        public byte[] secretKey() {
            return secretKey.clone();
        }

        public byte[] publicKey() {
            return publicKey.clone();
        }
    }

    public static final class EncapsulationResult {
        private final byte[] ctPq;
        private final byte[] ctTrad;
        private final byte[] secret;

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

        public byte[] secret() {
            return secret.clone();
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

    public static byte profileFromSignedPolicy(
            byte[] toml,
            byte[] signature,
            byte[] verificationKey,
            long lastTrustedVersion
    ) {
        requireNonNull(toml, "toml");
        requireNonNull(signature, "signature");
        requireNonNull(verificationKey, "verificationKey");
        return profileFromSignedPolicyNative(
                toml,
                signature,
                verificationKey,
                checkedUInt32("lastTrustedVersion", lastTrustedVersion)
        );
    }

    public static KeyPairResult mlkem768Keypair(byte[] seed) {
        requireNonNull(seed, "seed");
        byte[] secretKey = new byte[MLKEM_SK_LEN];
        byte[] publicKey = new byte[MLKEM_PK_LEN];
        mlkem768KeypairNative(seed, secretKey, publicKey);
        return new KeyPairResult(secretKey, publicKey);
    }

    public static KeyPairResult mlkem768XWingKeypair(byte[] seed) {
        requireNonNull(seed, "seed");
        byte[] secretKey = new byte[MLKEM_XWING_SEED_LEN];
        byte[] publicKey = new byte[MLKEM_PK_LEN];
        mlkem768XWingKeypairNative(seed, secretKey, publicKey);
        return new KeyPairResult(secretKey, publicKey);
    }

    public static KeyPairResult x25519Keypair(byte[] secret) {
        requireNonNull(secret, "secret");
        byte[] secretKey = new byte[X25519_LEN];
        byte[] publicKey = new byte[X25519_LEN];
        x25519KeypairNative(secret, secretKey, publicKey);
        return new KeyPairResult(secretKey, publicKey);
    }

    public static EncapsulationResult encapsulate(
            byte profile,
            byte[] suiteId,
            long policyVersion,
            byte[] pkPq,
            byte[] pkTrad,
            byte[] context,
            byte[] randPq,
            byte[] randTrad
    ) {
        requireNonNull(suiteId, "suiteId");
        requireNonNull(pkPq, "pkPq");
        requireNonNull(pkTrad, "pkTrad");
        requireNonNull(context, "context");
        requireNonNull(randPq, "randPq");
        requireNonNull(randTrad, "randTrad");
        byte[] ctPq = new byte[MLKEM_CT_LEN];
        byte[] ctTrad = new byte[X25519_LEN];
        byte[] secret = new byte[SECRET_LEN];
        encapsulateNative(
                profile,
                suiteId,
                checkedUInt32("policyVersion", policyVersion),
                pkPq,
                pkTrad,
                context,
                randPq,
                randTrad,
                ctPq,
                ctTrad,
                secret
        );
        return new EncapsulationResult(ctPq, ctTrad, secret);
    }

    public static byte[] decapsulate(
            byte profile,
            byte[] suiteId,
            long policyVersion,
            byte[] skPq,
            byte[] ctPq,
            byte[] pkPq,
            byte[] skTrad,
            byte[] ctTrad,
            byte[] pkTrad,
            byte[] context
    ) {
        requireNonNull(suiteId, "suiteId");
        requireNonNull(skPq, "skPq");
        requireNonNull(ctPq, "ctPq");
        requireNonNull(pkPq, "pkPq");
        requireNonNull(skTrad, "skTrad");
        requireNonNull(ctTrad, "ctTrad");
        requireNonNull(pkTrad, "pkTrad");
        requireNonNull(context, "context");
        byte[] secret = new byte[SECRET_LEN];
        decapsulateNative(
                profile,
                suiteId,
                checkedUInt32("policyVersion", policyVersion),
                skPq,
                ctPq,
                pkPq,
                skTrad,
                ctTrad,
                pkTrad,
                context,
                secret
        );
        return secret;
    }

    public static byte[] combine(byte profile, byte[] input) {
        requireNonNull(input, "input");
        byte[] secret = new byte[SECRET_LEN];
        combineNative(profile, input, secret);
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

    private static int checkedUInt32(String label, long value) {
        if (value < 0 || value > UINT32_MAX) {
            throw new IllegalArgumentException(label + " must be in uint32 range: " + value);
        }
        return (int) value;
    }

    private static void requireNonNull(byte[] value, String label) {
        Objects.requireNonNull(value, label + " must not be null");
    }

    private static native int runtimeAbiVersionNative();

    private static native String runtimeVersionNative();

    private static native String fixedSuiteIdNative();

    private static native long fixedSuiteIdLenNative();

    private static native String statusNameNative(int code);

    private static native byte profileFromSignedPolicyNative(
            byte[] toml,
            byte[] signature,
            byte[] verificationKey,
            int lastTrustedVersion
    );

    private static native void mlkem768KeypairNative(byte[] seed, byte[] outSecretKey, byte[] outPublicKey);

    private static native void mlkem768XWingKeypairNative(byte[] seed, byte[] outSecretKey, byte[] outPublicKey);

    private static native void x25519KeypairNative(byte[] secret, byte[] outSecretKey, byte[] outPublicKey);

    private static native void encapsulateNative(
            byte profile,
            byte[] suiteId,
            int policyVersion,
            byte[] pkPq,
            byte[] pkTrad,
            byte[] context,
            byte[] randPq,
            byte[] randTrad,
            byte[] outCtPq,
            byte[] outCtTrad,
            byte[] outSecret
    );

    private static native void decapsulateNative(
            byte profile,
            byte[] suiteId,
            int policyVersion,
            byte[] skPq,
            byte[] ctPq,
            byte[] pkPq,
            byte[] skTrad,
            byte[] ctTrad,
            byte[] pkTrad,
            byte[] context,
            byte[] outSecret
    );

    private static native void combineNative(byte profile, byte[] input, byte[] outSecret);
}
