// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.android;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Actual JNI/native consumer. Host execution is not an Android device claim. */
public final class QPeriaptSDKTest {
    private final byte[] policy;
    private final byte[] signature;
    private final byte[] root;
    private final byte[] digest;
    private QPeriaptSDKTest(String json) {
        policy = field(json, "policy_toml", "((?:[^\"\\\\]++|\\\\.)*)")
                .replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\")
                .getBytes(StandardCharsets.UTF_8);
        signature = hex(field(json, "signature", "([0-9a-f]*)"));
        root = hex(field(json, "verification_key", "([0-9a-f]*)"));
        digest = hex(field(json, "policy_digest", "([0-9a-f]*)"));
    }
    private static String field(String json, String name, String value) {
        Matcher match = Pattern.compile("\"" + name + "\"\\s*:\\s*\"" + value + "\"").matcher(json);
        if (!match.find()) throw new AssertionError("missing fixture field " + name);
        return match.group(1);
    }
    private static byte[] hex(String value) {
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte)Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }
    private QPeriaptSDK.Runtime runtime(int keys) {
        return QPeriaptSDK.Runtime.fromSignedPolicy(policy, signature, root, new byte[0], keys, 4);
    }
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    private static void denied(int expected, Runnable call) {
        try {
            call.run();
            throw new AssertionError("expected status " + expected);
        } catch (QPeriaptAndroid.QPeriaptException failure) {
            require(failure.code() == expected, "wrong failure: " + failure);
        }
    }
    private static void sameSecret(QPeriaptSDK.Secret left, QPeriaptSDK.Secret right, boolean same) {
        byte[] a = left.exportForProtocol(), b = right.exportForProtocol();
        try { require(Arrays.equals(a, b) == same, "combined secret relation"); }
        finally { QPeriaptAndroid.wipe(a); QPeriaptAndroid.wipe(b); }
    }

    private void roundtrips() {
        try (QPeriaptSDK.Runtime sender = runtime(1); QPeriaptSDK.Runtime receiver = runtime(1);
                QPeriaptSDK.Key key = receiver.generateKey()) {
            for (int size : new int[]{0, 32, 65536}) {
                byte[] context = new byte[size];
                Arrays.fill(context, (byte)42);
                try (QPeriaptSDK.Encapsulation enc = sender.encapsulate(key.publicKey(), context);
                        QPeriaptSDK.Secret dec = key.decapsulate(enc.ciphertext(), context)) {
                    sameSecret(enc.secret(), dec, true);
                    byte[] label = "app/v1/aes256".getBytes(StandardCharsets.US_ASCII);
                    byte[] previous = new byte[32];
                    try {
                        for (QPeriaptSDK.KeyPurpose purpose : QPeriaptSDK.KeyPurpose.values()) {
                            try (QPeriaptSDK.DerivedKey a = enc.secret().deriveKey(purpose, label, context);
                                    QPeriaptSDK.DerivedKey b = dec.deriveKey(purpose, label, context)) {
                                byte[] left = a.exportForProtocol(), right = b.exportForProtocol();
                                try {
                                    require(Arrays.equals(left, right), "derived peer agreement");
                                    require(!Arrays.equals(left, previous), "direction separation");
                                    QPeriaptAndroid.wipe(previous);
                                    previous = left.clone();
                                } finally { QPeriaptAndroid.wipe(left); QPeriaptAndroid.wipe(right); }
                            }
                        }
                    } finally { QPeriaptAndroid.wipe(previous); }
                    denied(-12, () -> enc.secret().deriveKey(QPeriaptSDK.KeyPurpose.EXPORTER, new byte[]{0}, context));
                    byte[] damaged = enc.ciphertext().encoded();
                    damaged[0] ^= 1;
                    try (QPeriaptSDK.Secret rejected = key.decapsulate(new QPeriaptSDK.Ciphertext(damaged), context)) {
                        sameSecret(enc.secret(), rejected, false);
                    }
                    if (size != 0) {
                        context[0] ^= 1;
                        try (QPeriaptSDK.Secret other = key.decapsulate(enc.ciphertext(), context)) {
                            sameSecret(enc.secret(), other, false);
                        }
                    }
                }
            }
        }
    }

    private void expertTransferAndPolicyUpdates(QPeriaptSDKTest revoked, QPeriaptSDKTest allowed) {
        try (QPeriaptSDK.Runtime runtime = runtime(2); QPeriaptSDK.Key key = runtime.generateKey()) {
            require(runtime.isEnabled(), "initial policy enabled");
            byte[] exported = QPeriaptSDK.Expert.exportExpanded(key);
            try {
                require(exported.length == 2440, "expanded length");
                try (QPeriaptSDK.Key imported = QPeriaptSDK.Expert.importExpanded(exported, runtime);
                        QPeriaptSDK.Encapsulation enc = runtime.encapsulate(imported.publicKey(), new byte[]{42});
                        QPeriaptSDK.Secret dec = imported.decapsulate(enc.ciphertext(), new byte[]{42})) {
                    require(Arrays.equals(key.publicKey().encoded(), imported.publicKey().encoded()), "imported pairing");
                    sameSecret(enc.secret(), dec, true);
                    try (QPeriaptSDK.PolicyUpdate update = runtime.preparePolicyUpdate(revoked.policy, revoked.signature)) {
                        QPeriaptSDK.PolicyStates states = update.states();
                        require(Arrays.equals(states.previous(), runtime.trustedState()), "expected previous state");
                        // In-memory host persistence only, not durable-store evidence.
                        byte[] persisted = states.next();
                        try (QPeriaptSDK.Runtime disabled = update.activateAfterPersisting()) {
                            require(!disabled.isEnabled(), "revocation installed");
                            denied(-3, disabled::generateKey);
                            denied(-9, key::publicKey);
                            denied(-9, dec::exportForProtocol);
                            denied(-9, update::activateAfterPersisting);
                            try (QPeriaptSDK.Runtime recovered = QPeriaptSDK.Runtime.fromSignedPolicy(
                                    revoked.policy, revoked.signature, revoked.root, persisted, 2, 4)) {
                                require(!recovered.isEnabled(), "revocation survives recovery");
                                try (QPeriaptSDK.PolicyUpdate enable = recovered.preparePolicyUpdate(allowed.policy, allowed.signature)) {
                                    byte[] nextState = enable.states().next();
                                    try (QPeriaptSDK.Runtime next = enable.activateAfterPersisting()) {
                                        require(next.isEnabled(), "policy reenabled");
                                        require(Arrays.equals(nextState, next.trustedState()), "activated exact state");
                                        next.generateKey().close();
                                    }
                                }
                            }
                        }
                    }
                }
            } finally { QPeriaptAndroid.wipe(exported); }
        }
        try (QPeriaptSDK.Runtime runtime = runtime(2); QPeriaptSDK.Key key = runtime.generateKey()) {
            byte[] exported = QPeriaptSDK.Expert.exportExpanded(key);
            try {
                exported[0] = 0;
                denied(-13, () -> QPeriaptSDK.Expert.importExpanded(exported, runtime));
                denied(-2, () -> QPeriaptSDK.Expert.importExpanded(new byte[64], runtime));
            } finally { QPeriaptAndroid.wipe(exported); }
        }
    }

    private void policiesAndQuota() {
        try (QPeriaptSDK.Runtime runtime = runtime(1)) {
            byte[] state = runtime.trustedState();
            require(Arrays.equals(digest, Arrays.copyOfRange(state, 4, 36)), "exact policy state");
            QPeriaptSDK.Runtime.fromSignedPolicy(policy, signature, root, state, 1, 1).close();
            state[0] = 127;
            denied(-3, () -> QPeriaptSDK.Runtime.fromSignedPolicy(policy, signature, root, state, 1, 1));
            byte[] tampered = signature.clone();
            tampered[0] ^= 1;
            denied(-3, () -> QPeriaptSDK.Runtime.fromSignedPolicy(policy, tampered, root));
            denied(-11, () -> runtime(0));
            denied(-2, () -> new QPeriaptSDK.PublicKey(new byte[1215]));
            try (QPeriaptSDK.Key key = runtime.generateKey()) {
                denied(-10, runtime::generateKey);
                denied(-2, () -> runtime.encapsulate(key.publicKey(), new byte[65537]));
                byte[] zeroShare = key.publicKey().encoded();
                Arrays.fill(zeroShare, 1184, zeroShare.length, (byte)0);
                denied(-6, () -> runtime.encapsulate(new QPeriaptSDK.PublicKey(zeroShare), new byte[0]));
            }
            runtime.generateKey().close();
        }
    }

    private void closeRevokesChildren() {
        QPeriaptSDK.Runtime runtime = runtime(1);
        QPeriaptSDK.Key key = runtime.generateKey();
        byte[] encoded = key.publicKey().encoded();
        QPeriaptSDK.PublicKey publicKey = new QPeriaptSDK.PublicKey(encoded);
        Arrays.fill(encoded, (byte)0);
        require(!Arrays.equals(publicKey.encoded(), encoded), "immutable public key");
        try (QPeriaptSDK.Encapsulation enc = runtime.encapsulate(publicKey, new byte[0]);
                QPeriaptSDK.Secret retained = key.decapsulate(enc.ciphertext(), new byte[0])) {
            QPeriaptSDK.DerivedKey derived = retained.deriveKey(QPeriaptSDK.KeyPurpose.EXPORTER, new byte[]{65}, new byte[0]);
            key.close();
            key.close();
            denied(-9, key::publicKey);
            sameSecret(enc.secret(), retained, true);
            runtime.close();
            denied(-9, retained::exportForProtocol);
            denied(-9, enc.secret()::exportForProtocol);
            denied(-9, runtime::trustedState);
            denied(-9, derived::exportForProtocol);
            derived.close();
        } finally { runtime.close(); key.close(); }
    }

    private void nativePreflight() {
        // Exercise the native boundary directly so Java facade checks cannot
        // conceal a missing JNI check. Values are intentionally unowned IDs.
        denied(-2, () -> QPeriaptAndroid.sdkRuntimeNewNative(policy, new byte[3308], root, new byte[0], 1, 1));
        denied(-2, () -> QPeriaptAndroid.sdkRuntimeNewNative(new byte[65537], signature, root, new byte[0], 1, 1));
        denied(-2, () -> QPeriaptAndroid.sdkRuntimeNewNative(policy, signature, root, new byte[4], 1, 1));
        denied(-2, () -> QPeriaptAndroid.sdkDecapsulateNative(0, new byte[1120], new byte[65537]));
        denied(-2, () -> QPeriaptAndroid.sdkEncapsulateNative(0, new byte[1215], new byte[0], new byte[1120]));
        denied(-9, () -> QPeriaptAndroid.sdkKeyPublicNative(0));
        denied(-2, () -> QPeriaptAndroid.sdkSecretDeriveNative(0, 1, new byte[0], new byte[0]));
        denied(-2, () -> QPeriaptAndroid.sdkSecretDeriveNative(0, 1, new byte[256], new byte[0]));
        denied(-2, () -> QPeriaptAndroid.sdkSecretDeriveNative(0, 1, new byte[]{65}, new byte[65537]));
        denied(-12, () -> QPeriaptAndroid.sdkSecretDeriveNative(0, 0, new byte[]{65}, new byte[0]));
        try {
            QPeriaptAndroid.sdkDecapsulateNative(0, null, new byte[0]);
            throw new AssertionError("native null must fail");
        } catch (NullPointerException expected) {
            require(expected.getMessage().contains("ciphertext"), "native null context");
        }
    }

    private void concurrent(ExecutorService pool) throws Exception {
        try (QPeriaptSDK.Runtime runtime = runtime(1);
                QPeriaptSDK.Key key = runtime.generateKeyAsync(pool).get(10, TimeUnit.SECONDS);
                QPeriaptSDK.Encapsulation enc = runtime.encapsulateAsync(pool, key.publicKey(), new byte[]{8, 9})
                        .get(10, TimeUnit.SECONDS)) {
            List<Callable<Void>> calls = new ArrayList<>();
            for (int i = 0; i < 4; i++) calls.add(() -> {
                for (int n = 0; n < 16; n++) {
                    try (QPeriaptSDK.Secret dec = key.decapsulate(enc.ciphertext(), new byte[]{8, 9})) {
                        sameSecret(enc.secret(), dec, true);
                    }
                }
                return null;
            });
            for (Future<Void> result : pool.invokeAll(calls, 10, TimeUnit.SECONDS)) result.get();
            try (QPeriaptSDK.Secret dec = key.decapsulateAsync(pool, enc.ciphertext(), new byte[]{8, 9})
                    .get(10, TimeUnit.SECONDS)) { sameSecret(enc.secret(), dec, true); }
        }
    }

    private void cancellation(ExecutorService pool) throws Exception {
        try (QPeriaptSDK.Runtime runtime = runtime(1)) {
            CountDownLatch produced = new CountDownLatch(1), release = new CountDownLatch(1), finished = new CountDownLatch(1);
            byte[] input = {1, 2, 3};
            QPeriaptSDK.OwnedTask<QPeriaptSDK.Key> task = new QPeriaptSDK.OwnedTask<>(() -> {
                QPeriaptSDK.Key key = runtime.generateKey();
                produced.countDown();
                try {
                    require(release.await(10, TimeUnit.SECONDS), "worker release timeout");
                    return key;
                } catch (Exception | Error failure) { key.close(); throw failure; }
            }, input);
            pool.execute(() -> { try { task.run(); } finally { finished.countDown(); } });
            try {
                require(produced.await(10, TimeUnit.SECONDS), "native key not produced");
                task.run(); // FutureTask permits a second run; it must not wipe the first worker's input.
                require(Arrays.equals(input, new byte[]{1, 2, 3}), "concurrent duplicate run erased live input");
                require(task.cancel(true), "cancel accepted");
                denied(-10, runtime::generateKey);
                try { task.get(); throw new AssertionError("cancelled result escaped"); }
                catch (CancellationException expected) { require(task.isCancelled(), "cancel state"); }
            } finally { release.countDown(); }
            require(finished.await(10, TimeUnit.SECONDS), "cancel cleanup timeout");
            require(Arrays.equals(input, new byte[3]), "worker input not cleared after completion");
            runtime.generateKey().close();
        }
    }

    private void queuedCancellationAndSnapshot() throws Exception {
        AtomicReference<Runnable> queue = new AtomicReference<>();
        Executor executor = task -> require(queue.compareAndSet(null, task), "test executor queue full");
        try (QPeriaptSDK.Runtime runtime = runtime(1)) {
            Future<QPeriaptSDK.Key> cancelled = runtime.generateKeyAsync(executor);
            require(cancelled.cancel(false), "queued cancellation");
            queue.getAndSet(null).run();
            try (QPeriaptSDK.Key key = runtime.generateKey()) {
                byte[] context = {1, 2, 3};
                Future<QPeriaptSDK.Encapsulation> result = runtime.encapsulateAsync(executor, key.publicKey(), context);
                Arrays.fill(context, (byte)9);
                queue.getAndSet(null).run();
                try (QPeriaptSDK.Encapsulation enc = result.get(10, TimeUnit.SECONDS);
                        QPeriaptSDK.Secret dec = key.decapsulate(enc.ciphertext(), new byte[]{1, 2, 3})) {
                    sameSecret(enc.secret(), dec, true);
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 1, "fixture path required");
        QPeriaptSDKTest test = new QPeriaptSDKTest(Files.readString(Path.of(args[0])));
        Path fixtures = Path.of(args[0]).getParent();
        QPeriaptSDKTest revoked = new QPeriaptSDKTest(Files.readString(fixtures.resolve("sdk-policy-revocation-vectors.json")));
        QPeriaptSDKTest allowed = new QPeriaptSDKTest(Files.readString(fixtures.resolve("sdk-policy-update-vectors.json")));
        require(QPeriaptAndroid.runtimeAbiVersion() == 2, "ABI major remains 2");
        test.roundtrips(); test.policiesAndQuota(); test.closeRevokesChildren(); test.nativePreflight();
        test.expertTransferAndPolicyUpdates(revoked, allowed);
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try { test.concurrent(pool); test.cancellation(pool); test.queuedCancellationAndSnapshot(); }
        finally {
            pool.shutdown();
            require(pool.awaitTermination(10, TimeUnit.SECONDS), "workers did not stop");
        }
        System.out.println("SDK_ANDROID_JNI_HOST_PASS cases=8");
    }
}
