// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Historical coordination progress. Local abandonment is never witness Closed. */
public final class RosterRefreshProgress {
    public enum Phase { ABSENT, STAGED, RESERVED, APPLIED, CLOSED, ABANDONED_BEFORE_PREPARATION }
    private final Phase phase;
    private final boolean retired;
    private final RosterRefreshScope scope;
    private final RosterRefreshProposal proposal;
    RosterRefreshProgress(byte[] bytes) {
        if (bytes.length != 624) throw new IllegalStateException("native roster progress width");
        ByteBuffer input = ByteBuffer.wrap(bytes);
        int code = input.getInt(), retirement = input.getInt();
        if (code < 0 || code > 5 || retirement < 0 || retirement > 1
                || ((code != 3 && code != 4) && retirement != 0)
                || EnrollmentIntent.nonzero(Arrays.copyOfRange(bytes, 617, 624)))
            throw new IllegalStateException("native roster progress flags");
        phase = Phase.values()[code]; retired = retirement == 1;
        if (code == 0) {
            if (EnrollmentIntent.nonzero(bytes)) throw new IllegalStateException("absent roster progress fields");
            scope = null; proposal = null; return;
        }
        try {
            scope = RosterRefreshScope.read(input);
            byte[] retained = PolicyCodec.take(input, 417);
            if (code == 1 || code == 5) {
                if (EnrollmentIntent.nonzero(retained)) throw new IllegalArgumentException("unprepared roster proposal");
                proposal = null;
            } else {
                proposal = new RosterRefreshProposal(retained);
                if (!scope.equals(proposal.scope())) throw new IllegalArgumentException("roster progress scope mismatch");
            }
        } catch (IllegalArgumentException failure) { throw new IllegalStateException("malformed native roster progress", failure); }
    }
    public Phase phase() { return phase; }
    /** Meaningful only for APPLIED and CLOSED. */
    public boolean retired() { return retired; }
    /** Null exactly for ABSENT. */
    public RosterRefreshScope scope() { return scope; }
    /** Null for ABSENT, STAGED and ABANDONED_BEFORE_PREPARATION. */
    public RosterRefreshProposal proposal() { return proposal; }
}
