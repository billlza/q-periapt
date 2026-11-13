// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Independently approved committed winner and original losing-plan noncommit. */
public final class RootReplacementAdoption {
    private final RootReplacementPlan original;
    private final RootReplacementProposal winner;
    private final byte[] noncommit, retirement;
    public RootReplacementAdoption(RootReplacementPlan original, RootReplacementProposal independentlyApprovedWinner,
            byte[] originalNoncommit, byte[] winnerRetirement) {
        this.original = Objects.requireNonNull(original, "original root plan");
        winner = Objects.requireNonNull(independentlyApprovedWinner, "independently approved winner");
        noncommit = ConfigurationInputs.copy(originalNoncommit, 3449, 3449, "original noncommit receipt");
        retirement = ConfigurationInputs.copy(winnerRetirement, 3449, 3449, "winner retirement receipt");
    }
    byte[][] snapshot() { return new byte[][] {original.encoded(), winner.encoded(), noncommit.clone(), retirement.clone()}; }
}
