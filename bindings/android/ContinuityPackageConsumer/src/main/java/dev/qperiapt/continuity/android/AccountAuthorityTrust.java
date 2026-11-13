// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Original host registry scope and independently retained witness pin. */
public final class AccountAuthorityTrust {
    private final Ids.AccountAuthority identity;
    private final byte[] family, witness, publicKey;
    public AccountAuthorityTrust(Ids.AccountAuthority identity, byte[] family, byte[] witness, byte[] publicKey) {
        this.identity = Objects.requireNonNull(identity, "registry identity");
        this.family = ConfigurationInputs.copy(family, 32, 32, "family");
        this.witness = ConfigurationInputs.copy(witness, 32, 32, "witness identity");
        this.publicKey = ConfigurationInputs.copy(publicKey, 1985, 1985, "witness public key");
        if (!EnrollmentIntent.nonzero(this.family) || !EnrollmentIntent.nonzero(this.witness))
            throw new IllegalArgumentException("zero registry scope");
    }
    byte[][] snapshot(byte[] path) { return new byte[][] {path, identity.encoded(), family.clone(), witness.clone(), publicKey.clone()}; }
}
