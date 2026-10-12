// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Original policy-operation history. No phase grants live traffic authority. */
public final class PolicyRenewalStatus {
    public enum Phase { ABSENT, PENDING, COMMITTED, ABANDONED_UNCOMMITTED }
    public enum Reason { EXPIRED, ROSTER_ADVANCED }
    private final Phase phase;
    private final Reason reason;
    private final Ids.PolicyRenewal operation;
    private final Ids.PolicyStatement statement;
    private final PolicyCheckpoint target;
    private final RosterCheckpoint observedRoster;
    private final Counter64 observedAt;

    PolicyRenewalStatus(byte[] wire) {
        if (wire.length != 160) throw new IllegalStateException("native policy status width");
        ByteBuffer input = ByteBuffer.wrap(wire); int kind = input.getInt(), cause = input.getInt();
        if (kind < 0 || kind > 3) throw new IllegalStateException("native policy status phase");
        phase = Phase.values()[kind];
        if (kind == 0) {
            if (EnrollmentIntent.nonzero(Arrays.copyOfRange(wire, 4, 160)))
                throw new IllegalStateException("native absent policy status fields");
            reason = null; operation = null; statement = null; target = null; observedRoster = null; observedAt = null;
            return;
        }
        try {
            operation = new Ids.PolicyRenewal(PolicyCodec.take(input, 32));
            statement = new Ids.PolicyStatement(PolicyCodec.take(input, 32));
            target = PolicyCodec.policy(input);
            if (kind == 3) {
                if (cause < 1 || cause > 2) throw new IllegalArgumentException("abandonment reason");
                reason = Reason.values()[cause - 1]; observedRoster = PolicyCodec.roster(input);
                long at = input.getLong(); if (at == 0) throw new IllegalArgumentException("observation time");
                observedAt = Counter64.fromBits(at);
            } else {
                if (cause != 0 || EnrollmentIntent.nonzero(Arrays.copyOfRange(wire, 112, 160)))
                    throw new IllegalArgumentException("unexpected abandonment observation");
                reason = null; observedRoster = null; observedAt = null;
            }
        } catch (IllegalArgumentException failure) { throw new IllegalStateException("malformed native policy status", failure); }
    }
    public Phase phase() { return phase; }
    /** Null only for ABSENT. */
    public Ids.PolicyRenewal operation() { return operation; }
    /** Null only for ABSENT. */
    public Ids.PolicyStatement statement() { return statement; }
    /** Null only for ABSENT. */
    public PolicyCheckpoint target() { return target; }
    /** Present only for ABANDONED_UNCOMMITTED. */
    public Reason reason() { return reason; }
    /** Present only for ABANDONED_UNCOMMITTED. */
    public RosterCheckpoint observedRoster() { return observedRoster; }
    /** Present only for ABANDONED_UNCOMMITTED. */
    public Counter64 observedAt() { return observedAt; }
}
