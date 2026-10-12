// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Arrays;
import java.util.Objects;

/** Independently retained policy floor, not live authorization by itself. */
public final class PolicyCheckpoint {
    private final Counter64 version;
    private final byte[] digest;
    public PolicyCheckpoint(Counter64 version, byte[] digest) {
        this.version = Objects.requireNonNull(version, "policy version");
        this.digest = ConfigurationInputs.copy(digest, 32, 32, "policy digest");
        if (version.bits == 0 || version.bits == -1 || !EnrollmentIntent.nonzero(this.digest))
            throw new IllegalArgumentException("policy checkpoint");
    }
    public Counter64 version() { return version; }
    static PolicyCheckpoint decode(byte[] wire) {
        if (wire.length != 40) throw new IllegalStateException("native policy checkpoint width");
        long version = java.nio.ByteBuffer.wrap(wire).getLong();
        byte[] digest = Arrays.copyOfRange(wire, 8, 40);
        if (version == 0 || version == -1 || !EnrollmentIntent.nonzero(digest))
            throw new IllegalStateException("malformed native policy checkpoint");
        return new PolicyCheckpoint(Counter64.fromBits(version), digest);
    }
    public byte[] digest() { return digest.clone(); }
    @Override public boolean equals(Object other) {
        return other instanceof PolicyCheckpoint && version.equals(((PolicyCheckpoint) other).version)
            && Arrays.equals(digest, ((PolicyCheckpoint) other).digest);
    }
    @Override public int hashCode() { return 31 * version.hashCode() + Arrays.hashCode(digest); }
}
