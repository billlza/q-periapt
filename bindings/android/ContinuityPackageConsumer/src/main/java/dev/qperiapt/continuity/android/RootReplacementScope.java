// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Independently retained original checkpoint and witness. Receipt contents cannot select these. */
public final class RootReplacementScope {
    private final AccountAuthorityCheckpoint checkpoint;
    private final byte[] witness, publicKey;
    public RootReplacementScope(AccountAuthorityCheckpoint checkpoint, byte[] witness, byte[] publicKey) {
        this.checkpoint = Objects.requireNonNull(checkpoint, "original registry checkpoint");
        this.witness = ConfigurationInputs.copy(witness, 32, 32, "witness identity");
        this.publicKey = ConfigurationInputs.copy(publicKey, 1985, 1985, "witness public key");
        if (!EnrollmentIntent.nonzero(this.witness)) throw new IllegalArgumentException("zero witness identity");
    }
    public AccountAuthorityCheckpoint checkpoint() { return checkpoint; }
    public byte[] witness() { return witness.clone(); }
    public byte[] publicKey() { return publicKey.clone(); }
    byte[][] snapshot() { return new byte[][] {checkpoint.wire(), witness.clone(), publicKey.clone()}; }
}
