// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/** Explicit independently retained trust and first-use inputs; no trust is read from a peer or disk. */
public final class ConfigurationInputs {
    private ConfigurationInputs() { }
    static byte[] copy(byte[] value, int minimum, int maximum, String name) {
        Objects.requireNonNull(value, name);
        if (value.length < minimum || value.length > maximum) throw new IllegalArgumentException(name + " width");
        return value.clone();
    }
    private static boolean nonzero(byte[] bytes) {
        for (byte value : bytes) if (value != 0) return true;
        return false;
    }
    public static final class SdkTrust {
        final int mode;
        private final byte[] scope, initialRoot, recoveryRoot;
        private SdkTrust(int mode, byte[] scope, byte[] root, byte[] recovery) {
            this.mode = mode; this.scope = copy(scope, 32, 32, "deployment scope");
            initialRoot = copy(root, 1952, 1952, "SDK root");
            recoveryRoot = copy(recovery, mode == 1 ? 0 : 1952, mode == 1 ? 0 : 1952, "recovery root");
            if ((mode == 2) != nonzero(this.scope)) throw new IllegalArgumentException("SDK trust scope");
        }
        public static SdkTrust fixed(byte[] initialRoot) { return new SdkTrust(1, new byte[32], initialRoot, new byte[0]); }
        public static SdkTrust recoverable(byte[] scope, byte[] initialRoot, byte[] recoveryRoot) {
            return new SdkTrust(2, scope, initialRoot, recoveryRoot);
        }
        byte[][] snapshot() { return new byte[][] {scope.clone(), initialRoot.clone(), recoveryRoot.clone()}; }
    }
    public static final class ProtocolPolicy {
        final long version;
        private final byte[] family, root, digest, policy;
        public ProtocolPolicy(byte[] family, byte[] root, String unsignedVersion, byte[] digest, byte[] signedPolicy) {
            this.family = copy(family, 32, 32, "protocol family"); this.root = copy(root, 1985, 1985, "protocol root");
            this.digest = copy(digest, 32, 32, "protocol digest"); policy = copy(signedPolicy, 1, 8192, "protocol policy");
            Objects.requireNonNull(unsignedVersion, "protocol version");
            if (!unsignedVersion.matches("[1-9][0-9]{0,19}")) throw new IllegalArgumentException("protocol version");
            BigInteger number = new BigInteger(unsignedVersion);
            if (number.bitLength() > 64 || !nonzero(this.family) || !nonzero(this.digest)) {
                throw new IllegalArgumentException("protocol checkpoint");
            }
            version = number.longValue();
        }
        byte[][] snapshot() { return new byte[][] {family.clone(), root.clone(), digest.clone(), policy.clone()}; }
    }
    /** Owned caller-supplied DER identity. Close wipes this copy; supplied input and native copies have their own lifetimes. */
    public static final class LocalTlsIdentity implements AutoCloseable {
        private final byte[] certificate, privateKey;
        private boolean closed;
        public LocalTlsIdentity(byte[] certificate, byte[] privateKey) {
            this.certificate = copy(certificate, 1, 8192, "TLS certificate");
            this.privateKey = copy(privateKey, 1, 8192, "TLS private key");
        }
        synchronized byte[][] snapshot() {
            if (closed) throw new IllegalStateException("TLS input is closed");
            return new byte[][] {certificate.clone(), privateKey.clone()};
        }
        @Override public synchronized void close() { Arrays.fill(privateKey, (byte) 0); closed = true; }
    }
    public static final class Initial {
        final SdkTrust trust;
        final ProtocolPolicy protocol;
        final LocalTlsIdentity tls;
        private final byte[] policy, signature, enrollment;
        public Initial(SdkTrust trust, byte[] signedPolicy, byte[] signature, byte[] recoveryEnrollment,
                ProtocolPolicy protocol, LocalTlsIdentity tls) {
            this.trust = Objects.requireNonNull(trust, "SDK trust"); this.protocol = Objects.requireNonNull(protocol, "protocol");
            this.tls = Objects.requireNonNull(tls, "TLS identity");
            policy = copy(signedPolicy, 1, 65536, "SDK policy"); this.signature = copy(signature, 3309, 3309, "SDK signature");
            enrollment = copy(recoveryEnrollment, trust.mode == 1 ? 0 : 3309, trust.mode == 1 ? 0 : 3309, "recovery enrollment");
        }
        byte[][] snapshot(byte[] path) {
            byte[][] sdk = trust.snapshot(), proto = protocol.snapshot(), identity = tls.snapshot();
            try {
                return new byte[][] {path, sdk[0], sdk[1], sdk[2], policy.clone(), signature.clone(), enrollment.clone(),
                    proto[0], proto[1], proto[2], proto[3], identity[0], identity[1]};
            } catch (Throwable failure) { Arrays.fill(identity[1], (byte) 0); throw failure; }
        }
    }
}
