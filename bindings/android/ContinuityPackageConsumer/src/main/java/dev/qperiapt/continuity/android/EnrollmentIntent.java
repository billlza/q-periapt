// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Independently approved scope, retained unchanged for explicit resume. */
public final class EnrollmentIntent {
    private final byte[] root, device, family;
    final Counter64 generation, validFrom, validUntil;
    public EnrollmentIntent(byte[] root, byte[] device, Counter64 generation, byte[] family,
            Counter64 validFrom, Counter64 validUntil) {
        this.root = ConfigurationInputs.copy(root, 1985, 1985, "enrollment root");
        this.device = ConfigurationInputs.copy(device, 16, 16, "device");
        this.family = ConfigurationInputs.copy(family, 32, 32, "family");
        this.generation = Objects.requireNonNull(generation, "generation");
        this.validFrom = Objects.requireNonNull(validFrom, "valid from");
        this.validUntil = Objects.requireNonNull(validUntil, "valid until");
        if (generation.bits == 0 || generation.bits == -1 || validUntil.bits == -1 || validFrom.compareTo(validUntil) >= 0
                || !nonzero(this.device) || !nonzero(this.family)) throw new IllegalArgumentException("enrollment scope");
    }
    static boolean nonzero(byte[] value) { for (byte item : value) if (item != 0) return true; return false; }
    byte[][] snapshot() { return new byte[][] {root.clone(), device.clone(), family.clone()}; }
}
