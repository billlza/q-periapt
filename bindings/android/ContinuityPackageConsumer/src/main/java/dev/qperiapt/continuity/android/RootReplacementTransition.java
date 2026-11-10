// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Original noncommit plus a separately approved next plan and its freeze receipt. */
public final class RootReplacementTransition {
    private final RootReplacementPlan original, next;
    private final byte[] noncommit, freeze;
    public RootReplacementTransition(RootReplacementPlan original, RootReplacementPlan independentlyApprovedNext,
            byte[] originalNoncommit, byte[] nextFreeze) {
        this.original = Objects.requireNonNull(original, "original root plan");
        next = Objects.requireNonNull(independentlyApprovedNext, "independently approved next plan");
        noncommit = ConfigurationInputs.copy(originalNoncommit, 3449, 3449, "original noncommit receipt");
        freeze = ConfigurationInputs.copy(nextFreeze, 1, 131072, "next freeze receipt");
    }
    byte[][] snapshot() { return new byte[][] {original.encoded(), next.encoded(), noncommit.clone(), freeze.clone()}; }
}
