// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;

/** Exact local original-operation result. A later head does not prove non-commit. */
public final class RosterRefreshResolution {
    public enum Outcome { COMMITTED, EXPIRED_UNCOMMITTED, SUPERSEDED_UNCOMMITTED, SUPERSEDED_UNKNOWN }
    private final Outcome outcome;
    private final Ids.Journal journal;
    private final RosterCheckpoint previous, target, observed;
    private final Counter64 observedAt;
    RosterRefreshResolution(byte[] bytes) {
        if (bytes.length != 168) throw new IllegalStateException("native roster resolution width");
        ByteBuffer input = ByteBuffer.wrap(bytes);
        int code = input.getInt(), reserved = input.getInt();
        if (code < 1 || code > 4 || reserved != 0) throw new IllegalStateException("native roster resolution header");
        outcome = Outcome.values()[code - 1];
        try {
            journal = new Ids.Journal(PolicyCodec.take(input, 32));
            previous = PolicyCodec.roster(input); target = PolicyCodec.roster(input); observed = PolicyCodec.roster(input);
            observedAt = Counter64.fromBits(input.getLong());
            if (observedAt.bits == 0 || previous.version().compareTo(target.version()) >= 0
                    || observed.version().compareTo(previous.version()) < 0
                    || (observed.version().equals(previous.version()) && !observed.equals(previous))) invalid();
            int order = observed.version().compareTo(target.version());
            boolean consistent = code == 1 ? observed.equals(target) : code == 2 ? order < 0
                : code == 3 ? order == 0 && !observed.equals(target) : order > 0;
            if (!consistent) invalid();
        } catch (IllegalArgumentException failure) { throw new IllegalStateException("malformed native roster resolution", failure); }
    }
    private static void invalid() { throw new IllegalArgumentException("roster resolution order or outcome"); }
    public Outcome outcome() { return outcome; }
    public Ids.Journal journal() { return journal; }
    public RosterCheckpoint previous() { return previous; }
    public RosterCheckpoint target() { return target; }
    public RosterCheckpoint observed() { return observed; }
    public Counter64 observedAt() { return observedAt; }
}
