// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Independently pinned witness endpoint; construction grants no receipt or network permission. */
public final class ConfigurationWitness {
    final int carrier, timeout;
    private final byte[] identity, publicKey, address, peer, name;
    private final ConfigurationInputs.LocalTlsIdentity tls;
    private ConfigurationWitness(int carrier, byte[] identity, byte[] publicKey, String address, int timeout,
            byte[] peer, String name, ConfigurationInputs.LocalTlsIdentity tls) {
        this.carrier = carrier; this.timeout = timeout;
        this.identity = ConfigurationInputs.copy(identity, 32, 32, "witness identity");
        this.publicKey = ConfigurationInputs.copy(publicKey, 1985, 1985, "witness key");
        this.address = text(address);
        this.peer = ConfigurationInputs.copy(peer, carrier == 2 ? 1 : 0, carrier == 2 ? 8192 : 0, "witness TLS peer");
        this.name = carrier == 2 ? text(name) : new byte[0]; this.tls = tls;
        if (timeout < 1 || timeout > 10000 || !EnrollmentIntent.nonzero(this.identity)) throw new IllegalArgumentException("witness scope");
    }
    private static byte[] text(String value) {
        byte[] bytes = Native.path(value);
        if (bytes.length > 128) throw new IllegalArgumentException("witness endpoint width");
        return bytes;
    }
    public static ConfigurationWitness signedTcp(byte[] identity, byte[] publicKey, String address, int timeoutMilliseconds) {
        return new ConfigurationWitness(1, identity, publicKey, address, timeoutMilliseconds, new byte[0], null, null);
    }
    public static ConfigurationWitness mutualTls(byte[] identity, byte[] publicKey, String address, int timeoutMilliseconds,
            byte[] peerCertificate, String serverName, ConfigurationInputs.LocalTlsIdentity localIdentity) {
        return new ConfigurationWitness(2, identity, publicKey, address, timeoutMilliseconds,
            peerCertificate, serverName, Objects.requireNonNull(localIdentity, "local TLS identity"));
    }
    byte[][] snapshot() {
        byte[][] local = tls == null ? new byte[][] {new byte[0], new byte[0]} : tls.snapshot();
        try { return new byte[][] {identity.clone(), publicKey.clone(), address.clone(), peer.clone(), local[0], local[1], name.clone()}; }
        catch (Throwable failure) { java.util.Arrays.fill(local[1], (byte) 0); throw failure; }
    }
}
