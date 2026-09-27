// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.android;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Owned SDK surface over the additive ABI 2 extension, available from Android API 23.
 * Private keys stay in the native registry unless explicitly exported through Expert.
 * These objects prevent accidental misuse;
 * they do not isolate secrets from hostile code in the same process.
 *
 * <p>Use try-with-resources or explicit close. Garbage collection is not a disposal
 * mechanism in this Android API. Runtime close revokes and drains all child handles,
 * even if a Java child reference was abandoned. Native handle and call budgets bound
 * retained resources; exhaustion reports an error instead of evicting active keys.</p>
 */
public final class QPeriaptSDK {
    private static final Logger LOGGER = Logger.getLogger("dev.qperiapt.android.sdk");

    private QPeriaptSDK() { }

    /** Global protocol directions; both peers use the same purpose per direction. */
    public enum KeyPurpose {
        INITIATOR_TRAFFIC(1), RESPONDER_TRAFFIC(2),
        INITIATOR_CONFIRMATION(3), RESPONDER_CONFIRMATION(4), EXPORTER(5);
        private final int code;
        KeyPurpose(int code) { this.code = code; }
    }

    /** Immutable public encapsulation key, never a private-key representation. */
    public static final class PublicKey {
        private final byte[] bytes;
        public PublicKey(byte[] bytes) {
            requireLength("public key", bytes, 1216);
            this.bytes = bytes.clone();
        }
        public byte[] encoded() { return bytes.clone(); }
    }

    /** Correct-length invalid PQ ciphertexts retain implicit rejection. */
    public static final class Ciphertext {
        private final byte[] bytes;
        public Ciphertext(byte[] bytes) {
            requireLength("ciphertext", bytes, 1120);
            this.bytes = bytes.clone();
        }
        public byte[] encoded() { return bytes.clone(); }
    }

    /** Verified immutable configuration. The host must persist trustedState before use. */
    public static final class Runtime implements AutoCloseable {
        private final long handle;
        private Runtime(long handle) { this.handle = handle; }

        public static Runtime fromSignedPolicy(byte[] policy, byte[] signature, byte[] trustRoot,
                byte[] previousState, int maxLiveKeys, int maxInFlight) {
            Objects.requireNonNull(policy, "policy");
            Objects.requireNonNull(signature, "signature");
            Objects.requireNonNull(trustRoot, "trustRoot");
            Objects.requireNonNull(previousState, "previousState");
            if (QPeriaptAndroid.sdkExtensionVersionNative() != 1) {
                throw new IllegalStateException("Q-Periapt SDK extension mismatch");
            }
            return createOwner(() -> QPeriaptAndroid.sdkRuntimeNewNative(
                    policy, signature, trustRoot, previousState, maxLiveKeys, maxInFlight), Runtime::new);
        }

        public static Runtime fromSignedPolicy(byte[] policy, byte[] signature, byte[] trustRoot) {
            return fromSignedPolicy(policy, signature, trustRoot, new byte[0], 32, 4);
        }

        public byte[] trustedState() { return QPeriaptAndroid.sdkRuntimeStateNative(handle); }
        /** A valid policy may disable key operations while allowing future signed updates. */
        public boolean isEnabled() { return QPeriaptAndroid.sdkRuntimeEnabledNative(handle); }
        public PolicyUpdate preparePolicyUpdate(byte[] policy, byte[] signature) {
            Objects.requireNonNull(policy, "policy");
            Objects.requireNonNull(signature, "signature");
            return createOwner(() -> QPeriaptAndroid.sdkRuntimePrepareUpdateNative(handle, policy, signature), PolicyUpdate::new);
        }

        public Key generateKey() {
            return createOwner(() -> QPeriaptAndroid.sdkKeyGenerateNative(handle), Key::new);
        }

        public Encapsulation encapsulate(PublicKey peer, byte[] applicationContext) {
            Objects.requireNonNull(peer, "peer");
            checkContext(applicationContext);
            byte[] ciphertext = new byte[1120];
            return createOwner(() -> QPeriaptAndroid.sdkEncapsulateNative(
                    handle, peer.bytes, applicationContext, ciphertext),
                    secret -> new Encapsulation(new Ciphertext(ciphertext), new Secret(secret)));
        }

        /** Revoke all child owners. Native leases keep active operations alive until they finish. */
        @Override public void close() { QPeriaptAndroid.sdkCloseNative(handle); }

        public Future<Key> generateKeyAsync(Executor executor) {
            return submit(executor, this::generateKey, null);
        }

        public Future<Encapsulation> encapsulateAsync(Executor executor, PublicKey peer, byte[] context) {
            Objects.requireNonNull(peer, "peer");
            checkContext(context);
            byte[] snapshot = context.clone();
            return submit(executor, () -> encapsulate(peer, snapshot), snapshot);
        }
    }

    /** Explicit plaintext transfer. The caller must protect and erase every byte-array copy. */
    public static final class Expert {
        private Expert() { }
        public static Key importExpanded(byte[] bytes, Runtime runtime) {
            Objects.requireNonNull(runtime, "runtime");
            requireLength("expert key import", bytes, 2440);
            return createOwner(() -> QPeriaptAndroid.sdkExpertKeyImportNative(runtime.handle, bytes), Key::new);
        }
        public static byte[] exportExpanded(Key key) {
            Objects.requireNonNull(key, "key");
            return QPeriaptAndroid.sdkExpertKeyExportNative(key.handle);
        }
    }

    /** Public state pair for root-scoped, atomic host compare-and-persist. */
    public static final class PolicyStates {
        private final byte[] previous;
        private final byte[] next;
        private PolicyStates(byte[] bytes) {
            requireLength("policy states", bytes, 72);
            previous = Arrays.copyOfRange(bytes, 0, 36);
            next = Arrays.copyOfRange(bytes, 36, 72);
        }
        public byte[] previous() { return previous.clone(); }
        public byte[] next() { return next.clone(); }
    }

    /** A prepared policy without key operations. Close cannot undo host persistence. */
    public static final class PolicyUpdate implements AutoCloseable {
        private final long handle;
        private PolicyUpdate(long handle) { this.handle = handle; }
        public PolicyStates states() { return new PolicyStates(QPeriaptAndroid.sdkPolicyUpdateStatesNative(handle)); }
        /**
         * Call only after atomic persistence. Revokes old owners and returns an independent,
         * possibly disabled runtime. On failure after persistence, stop old-runtime use and
         * recover from the signed policy and persisted state; the SDK cannot inspect storage.
         */
        public Runtime activateAfterPersisting() {
            return createOwner(() -> QPeriaptAndroid.sdkPolicyUpdateActivateNative(handle), Runtime::new);
        }
        @Override public void close() { QPeriaptAndroid.sdkCloseNative(handle); }
    }

    /** One native key owner. Aliasing a Java reference does not clone its secret. */
    public static final class Key implements AutoCloseable {
        private final long handle;
        private Key(long handle) { this.handle = handle; }
        public PublicKey publicKey() { return new PublicKey(QPeriaptAndroid.sdkKeyPublicNative(handle)); }
        public Secret decapsulate(Ciphertext ciphertext, byte[] applicationContext) {
            Objects.requireNonNull(ciphertext, "ciphertext");
            checkContext(applicationContext);
            return createOwner(() -> QPeriaptAndroid.sdkDecapsulateNative(
                    handle, ciphertext.bytes, applicationContext), Secret::new);
        }
        @Override public void close() { QPeriaptAndroid.sdkCloseNative(handle); }
        public Future<Secret> decapsulateAsync(Executor executor, Ciphertext ciphertext, byte[] context) {
            Objects.requireNonNull(ciphertext, "ciphertext");
            checkContext(context);
            byte[] snapshot = context.clone();
            return submit(executor, () -> decapsulate(ciphertext, snapshot), snapshot);
        }
    }

    /** Closing this result closes its secret; the ciphertext is public. */
    public static final class Encapsulation implements AutoCloseable {
        private final Ciphertext ciphertext;
        private final Secret secret;
        private Encapsulation(Ciphertext ciphertext, Secret secret) {
            this.ciphertext = ciphertext;
            this.secret = secret;
        }
        public Ciphertext ciphertext() { return ciphertext; }
        public Secret secret() { return secret; }
        @Override public void close() { secret.close(); }
    }

    /** Native combined-secret owner. No automatic byte-array getter. */
    public static final class Secret implements AutoCloseable {
        private final long handle;
        private Secret(long handle) { this.handle = handle; }
        /** Label: 1..255 printable ASCII bytes; context: at most 64 KiB. */
        public DerivedKey deriveKey(KeyPurpose purpose, byte[] protocolLabel, byte[] context) {
            Objects.requireNonNull(purpose, "purpose");
            Objects.requireNonNull(protocolLabel, "protocolLabel");
            checkContext(context);
            return createOwner(() -> QPeriaptAndroid.sdkSecretDeriveNative(
                    handle, purpose.code, protocolLabel, context), DerivedKey::new);
        }
        /** Caller owns this copy and must wipe it; closing the native owner cannot erase it. */
        public byte[] exportForProtocol() { return QPeriaptAndroid.sdkSecretExportNative(handle); }
        @Override public void close() { QPeriaptAndroid.sdkCloseNative(handle); }
    }

    /** Purpose-derived cipher/MAC key; cannot be used as a KEM secret. */
    public static final class DerivedKey implements AutoCloseable {
        private final long handle;
        private DerivedKey(long handle) { this.handle = handle; }
        /** Explicit copy for a cipher/MAC; the caller owns and must erase it. */
        public byte[] exportForProtocol() { return QPeriaptAndroid.sdkDerivedKeyExportNative(handle); }
        @Override public void close() { QPeriaptAndroid.sdkCloseNative(handle); }
    }

    private interface HandleCall { long call(); }
    private interface OwnerFactory<T> { T create(long handle); }

    /** Includes Java result-allocation failure in the native ownership transaction. */
    private static <T> T createOwner(HandleCall call, OwnerFactory<T> factory) {
        long handle = call.call();
        try {
            return factory.create(handle);
        } catch (RuntimeException | Error failure) {
            try {
                QPeriaptAndroid.sdkCloseNative(handle);
            } catch (RuntimeException | Error disposal) {
                failure.addSuppressed(disposal);
            }
            throw failure;
        }
    }

    private static void requireLength(String operation, byte[] bytes, int length) {
        Objects.requireNonNull(bytes, operation);
        if (bytes.length != length) {
            throw new QPeriaptAndroid.QPeriaptException(operation, -2, "ERR_LENGTH");
        }
    }
    private static void checkContext(byte[] context) {
        Objects.requireNonNull(context, "applicationContext");
        if (context.length > 65536) {
            throw new QPeriaptAndroid.QPeriaptException("application context", -2, "ERR_LENGTH");
        }
    }

    /**
     * API 23-compatible publication fence around FutureTask's result/cancel race.
     * cancel never interrupts native work. It may report done before the worker
     * finishes; the worker closes any result it cannot deliver. The supplied
     * executor owns its queue and concurrency bounds.
     */
    static final class OwnedTask<T extends AutoCloseable> extends FutureTask<T> {
        private final Object publication = new Object();
        private final AtomicBoolean started = new AtomicBoolean();
        private final byte[] input;
        OwnedTask(Callable<T> work, byte[] input) { super(work); this.input = input; }

        @Override public boolean cancel(boolean mayInterruptIfRunning) {
            synchronized (publication) { return super.cancel(false); }
        }
        @Override protected void set(T value) {
            synchronized (publication) {
                if (!isCancelled()) {
                    super.set(value);
                    return;
                }
            }
            try {
                value.close();
            } catch (Exception | LinkageError failure) {
                LOGGER.log(Level.SEVERE, "Cancelled SDK result disposal failed", failure);
            }
        }
        @Override protected void setException(Throwable failure) {
            synchronized (publication) {
                if (!isCancelled()) {
                    super.setException(failure);
                    return;
                }
            }
            LOGGER.log(Level.SEVERE, "Cancelled SDK worker failed", failure);
        }
        @Override public void run() {
            // FutureTask permits repeated run calls; only its admitted worker
            // may erase a snapshot still being read by the native operation.
            if (!started.compareAndSet(false, true)) return;
            try { super.run(); } finally { clearInput(); }
        }
        void clearInput() { if (input != null) Arrays.fill(input, (byte) 0); }
    }

    private static <T extends AutoCloseable> Future<T> submit(Executor executor, Callable<T> work, byte[] input) {
        // Clear the task-owned snapshot even when executor validation/allocation fails.
        try {
            Objects.requireNonNull(executor, "executor");
            OwnedTask<T> task = new OwnedTask<>(work, input);
            executor.execute(task);
            return task;
        } catch (RuntimeException | Error failure) {
            if (input != null) Arrays.fill(input, (byte) 0);
            throw failure;
        }
    }
}
