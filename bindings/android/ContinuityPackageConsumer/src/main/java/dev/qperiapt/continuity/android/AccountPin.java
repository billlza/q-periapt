// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Independent account expectation, never inferred from an incoming certificate or roster. */
public final class AccountPin {
    private final byte[] account, root, family, digest;
    final Counter64 version;
    public AccountPin(byte[] account, byte[] root, byte[] family, Counter64 version, byte[] digest) {
        this.account = ConfigurationInputs.copy(account, 32, 32, "account");
        this.root = ConfigurationInputs.copy(root, 1985, 1985, "account root");
        this.family = ConfigurationInputs.copy(family, 32, 32, "family");
        this.digest = ConfigurationInputs.copy(digest, 32, 32, "roster digest");
        this.version = Objects.requireNonNull(version, "roster version");
        if (version.bits == 0 || version.bits == -1 || !EnrollmentIntent.nonzero(this.account)
                || !EnrollmentIntent.nonzero(this.family) || !EnrollmentIntent.nonzero(this.digest)) {
            throw new IllegalArgumentException("account checkpoint");
        }
    }
    byte[][] snapshot() { return new byte[][] {account.clone(), root.clone(), family.clone(), digest.clone()}; }
}
