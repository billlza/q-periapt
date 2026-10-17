// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Independent peer expectations are separate from the untrusted signed bundle. */
public final class PeerConfiguration {
    public enum Quality { ONE_TIME_BOTH, REUSABLE_BOTH, SIGNED_CLASSICAL_ONE_TIME_PQ, ONE_TIME_CLASSICAL_LAST_RESORT_PQ }
    public enum Role { INITIATOR, RESPONDER }
    public static final class Device {
        private final AccountPin account;
        private final byte[] device;
        private final Counter64 generation;
        public Device(AccountPin account, byte[] device, Counter64 generation) {
            this.account = Objects.requireNonNull(account, "peer account");
            this.device = ConfigurationInputs.copy(device, 16, 16, "peer device");
            this.generation = Objects.requireNonNull(generation, "generation");
            if (!EnrollmentIntent.nonzero(this.device) || generation.bits == 0) throw new IllegalArgumentException("peer identity");
        }
        private byte[][] snapshot() {
            byte[][] pin = account.snapshot();
            return new byte[][] {pin[0], pin[1], pin[2], pin[3], device.clone()};
        }
    }
    private final Device initiator, responder;
    private final byte[] directory, bundle, peerCertificate, name;
    public PeerConfiguration(Device initiator, Device responder, byte[] directory, byte[] signedBundle,
            byte[] trustedPeerCertificate, String serverName) {
        this.initiator = Objects.requireNonNull(initiator, "initiator"); this.responder = Objects.requireNonNull(responder, "responder");
        this.directory = ConfigurationInputs.copy(directory, 32, 32, "directory");
        if (!EnrollmentIntent.nonzero(this.directory)) throw new IllegalArgumentException("directory identity");
        bundle = ConfigurationInputs.copy(signedBundle, 1, 65536, "peer bundle");
        peerCertificate = ConfigurationInputs.copy(trustedPeerCertificate, 1, 8192, "peer certificate");
        name = Native.path(serverName);
        if (name.length > 128) throw new IllegalArgumentException("peer TLS name width");
    }
    byte[][] snapshot(Ids.Session session) {
        byte[][] left = initiator.snapshot(), right = responder.snapshot();
        return new byte[][] {left[0], left[1], left[2], left[3], left[4], right[0], right[1], right[2], right[3], right[4],
            directory.clone(), bundle.clone(), peerCertificate.clone(), name.clone(), session == null ? new byte[0] : session.encoded()};
    }
    long[] counters() { return new long[] {initiator.account.version.bits, initiator.generation.bits, responder.account.version.bits, responder.generation.bits}; }
}
