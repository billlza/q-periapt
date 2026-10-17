// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Independently approved canonical plan; public grammar alone grants no authority. */
public final class RootReplacementPlan {
    private final byte[] bytes;
    public RootReplacementPlan(byte[] approved) {
        bytes = ConfigurationInputs.copy(approved, 8, 131072, "approved root plan");
        if (!WireHeader.matches(bytes, "QPAFPL01")) throw new IllegalArgumentException("root plan header");
    }
    public byte[] encoded() { return bytes.clone(); }
}
