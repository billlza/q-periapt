// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Arrays;
import java.util.Objects;

/** Independently retained roster floor, not live authorization by itself. */
public final class RosterCheckpoint {
    private final Counter64 version;
    private final byte[] digest;
    public RosterCheckpoint(Counter64 version, byte[] digest) {
        this.version = Objects.requireNonNull(version, "roster version");
        this.digest = ConfigurationInputs.copy(digest, 32, 32, "roster digest");
        if (version.bits == 0 || version.bits == -1 || !EnrollmentIntent.nonzero(this.digest))
            throw new IllegalArgumentException("roster checkpoint");
    }
    public Counter64 version() { return version; }
    static RosterCheckpoint decode(byte[] wire) {
        if (wire.length != 40) throw new IllegalStateException("native roster checkpoint width");
        long version = java.nio.ByteBuffer.wrap(wire).getLong();
        byte[] digest = Arrays.copyOfRange(wire, 8, 40);
        if (version == 0 || version == -1 || !EnrollmentIntent.nonzero(digest))
            throw new IllegalStateException("malformed native roster checkpoint");
        return new RosterCheckpoint(Counter64.fromBits(version), digest);
    }
    public byte[] digest() { return digest.clone(); }
    @Override public boolean equals(Object other) {
        return other instanceof RosterCheckpoint && version.equals(((RosterCheckpoint) other).version)
            && Arrays.equals(digest, ((RosterCheckpoint) other).digest);
    }
    @Override public int hashCode() { return 31 * version.hashCode() + Arrays.hashCode(digest); }
}
