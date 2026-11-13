// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.androidsmoke;

import android.content.res.AssetManager;
import dev.qperiapt.android.QPeriaptAndroid;
import dev.qperiapt.android.QPeriaptSDK;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/** Public API workload for a real, minified ART consumer; compilation alone is not a pass. */
final class QPeriaptSDKWorkload {
    private QPeriaptSDKWorkload() { }
    private static final class Policy {
        final byte[] policy;
        final byte[] signature;
        final byte[] root;
        Policy(AssetManager assets, String name) throws Exception {
            try (InputStream input = assets.open(name); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] block = new byte[4096];
                int count;
                while ((count = input.read(block)) != -1) {
                    if (output.size() + count > 65536) throw new IllegalArgumentException("fixture size");
                    output.write(block, 0, count);
                }
                JSONObject json = new JSONObject(new String(output.toByteArray(), StandardCharsets.UTF_8));
                policy = json.getString("policy_toml").getBytes(StandardCharsets.UTF_8);
                signature = hex(json.getString("signature"));
                root = hex(json.getString("verification_key"));
            }
        }
        QPeriaptSDK.Runtime open() { return QPeriaptSDK.Runtime.fromSignedPolicy(policy, signature, root); }
    }
    private static byte[] hex(String value) {
        require(value.matches("(?:[0-9a-f]{2})+"), "hex fixture");
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) result[i] = (byte) Integer.parseInt(value.substring(2 * i, 2 * i + 2), 16);
        return result;
    }
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    private static void denied(int code, Runnable operation) {
        try { operation.run(); } catch (QPeriaptAndroid.QPeriaptException failure) {
            require(failure.code() == code, "unexpected status");
            return;
        }
        throw new AssertionError("missing expected status");
    }
    private static void same(QPeriaptSDK.Secret a, QPeriaptSDK.Secret b, boolean expected) {
        byte[] left = a.exportForProtocol(), right = b.exportForProtocol();
        try { require(Arrays.equals(left, right) == expected, "secret relation"); }
        finally { Arrays.fill(left, (byte) 0); Arrays.fill(right, (byte) 0); }
    }
    private static final class Queue implements Executor {
        private Runnable pending;
        @Override public void execute(Runnable task) { require(pending == null, "queue full"); pending = task; }
        void run() { Runnable task = pending; require(task != null, "queue empty"); pending = null; task.run(); }
    }
    static void run(AssetManager assets, List<String> passed) throws Exception {
        require(QPeriaptAndroid.runtimeAbiVersion() == 2 && "0.2.0".equals(QPeriaptAndroid.runtimeVersion()), "runtime identity");
        Policy policy = new Policy(assets, "signed-policy-vectors.json");
        Policy revoked = new Policy(assets, "sdk-policy-revocation-vectors.json");
        Policy allowed = new Policy(assets, "sdk-policy-update-vectors.json");
        require(Arrays.equals(policy.root, revoked.root) && Arrays.equals(policy.root, allowed.root), "fixed fixture trust root");
        byte[] badSignature = policy.signature.clone(); badSignature[0] ^= 1;
        denied(-3, () -> QPeriaptSDK.Runtime.fromSignedPolicy(policy.policy, badSignature, policy.root));
        try (QPeriaptSDK.Runtime sender = policy.open(); QPeriaptSDK.Runtime receiver = policy.open();
             QPeriaptSDK.Key key = receiver.generateKey()) {
            for (int size : new int[] {0, 32, 65536}) {
                byte[] context = new byte[size];
                Arrays.fill(context, (byte) 42);
                try (QPeriaptSDK.Encapsulation enc = sender.encapsulate(key.publicKey(), context);
                     QPeriaptSDK.Secret dec = key.decapsulate(enc.ciphertext(), context)) {
                    same(enc.secret(), dec, true);
                    for (QPeriaptSDK.KeyPurpose purpose : QPeriaptSDK.KeyPurpose.values()) {
                        byte[] label = "android/sdk/v1".getBytes(StandardCharsets.US_ASCII);
                        try (QPeriaptSDK.DerivedKey a = enc.secret().deriveKey(purpose, label, context);
                             QPeriaptSDK.DerivedKey b = dec.deriveKey(purpose, label, context)) {
                            byte[] first = a.exportForProtocol(), second = b.exportForProtocol();
                            try { require(first.length == 32 && Arrays.equals(first, second), "KDF relation"); }
                            finally { Arrays.fill(first, (byte) 0); Arrays.fill(second, (byte) 0); }
                        }
                    }
                    byte[] damaged = enc.ciphertext().encoded(); damaged[0] ^= 1;
                    try (QPeriaptSDK.Secret rejected = key.decapsulate(new QPeriaptSDK.Ciphertext(damaged), context)) {
                        same(enc.secret(), rejected, false);
                    }
                }
            }
            passed.add("sdkOwnersAndPurposeKeys");
            byte[] expanded = QPeriaptSDK.Expert.exportExpanded(key);
            try (QPeriaptSDK.Key imported = QPeriaptSDK.Expert.importExpanded(expanded, receiver)) {
                require(Arrays.equals(key.publicKey().encoded(), imported.publicKey().encoded()), "expert transfer");
            } finally { Arrays.fill(expanded, (byte) 0); }
            Queue queue = new Queue();
            Future<QPeriaptSDK.Key> cancelled = receiver.generateKeyAsync(queue);
            require(cancelled.cancel(true), "queued cancellation"); queue.run();
            try { cancelled.get(5, TimeUnit.SECONDS); throw new AssertionError("cancelled future returned"); }
            catch (CancellationException expected) { require(cancelled.isCancelled(), "cancelled state"); }
            byte[] context = new byte[] {1, 2, 3};
            Future<QPeriaptSDK.Encapsulation> pending = sender.encapsulateAsync(queue, key.publicKey(), context);
            Arrays.fill(context, (byte) 9); queue.run();
            try (QPeriaptSDK.Encapsulation enc = pending.get(5, TimeUnit.SECONDS);
                 QPeriaptSDK.Secret dec = key.decapsulate(enc.ciphertext(), new byte[] {1, 2, 3})) {
                same(enc.secret(), dec, true);
            }
            passed.add("sdkExpertCancellationAndInputSnapshot");
            try (QPeriaptSDK.PolicyUpdate update = receiver.preparePolicyUpdate(revoked.policy, revoked.signature)) {
                require(Arrays.equals(receiver.trustedState(), update.states().previous()), "previous state");
                // In-memory fixture, not a durable storage claim.
                byte[] stored = update.states().next();
                try (QPeriaptSDK.Runtime disabled = update.activateAfterPersisting()) {
                    require(!disabled.isEnabled(), "disabled policy");
                    denied(-3, disabled::generateKey);
                    denied(-9, key::publicKey);
                    try (QPeriaptSDK.Runtime recovered = QPeriaptSDK.Runtime.fromSignedPolicy(revoked.policy,
                            revoked.signature, policy.root, stored, 32, 4);
                         QPeriaptSDK.PolicyUpdate enable = recovered.preparePolicyUpdate(allowed.policy, allowed.signature)) {
                        require(Arrays.equals(recovered.trustedState(), enable.states().previous()), "recovery state");
                        byte[] reenabledState = enable.states().next(); // In-memory fixture persistence before activation.
                        try (QPeriaptSDK.Runtime next = enable.activateAfterPersisting()) {
                            require(next.isEnabled() && Arrays.equals(next.trustedState(), reenabledState), "re-enabled policy");
                            next.generateKey().close();
                        }
                    }
                }
            }
            passed.add("sdkSignedPolicyRevocationAndRecovery");
        }
    }
}
