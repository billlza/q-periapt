// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Local original-operation history. Absence never proves witness non-commit. */
public final class IndependentPolicyProgress {
    public enum Phase { ABSENT, RESERVED, APPLIED, CLOSED }
    private final Phase phase;
    private final boolean retired;
    private final IndependentPolicyProposal proposal;
    private final PolicyCheckpoint target;
    IndependentPolicyProgress(byte[] bytes) {
        if (bytes.length != 344) throw new IllegalStateException("native policy progress width");
        ByteBuffer input = ByteBuffer.wrap(bytes); int kind = input.getInt(), retired = input.getInt();
        if (kind < 0 || kind > 3 || retired < 0 || retired > 1 || (kind < 2 && retired != 0))
            throw new IllegalStateException("native policy progress flags");
        phase = Phase.values()[kind]; this.retired = retired == 1;
        if (kind == 0) {
            if (EnrollmentIntent.nonzero(Arrays.copyOfRange(bytes, 8, 344))) throw new IllegalStateException("native absent policy progress fields");
            proposal = null; target = null;
        } else {
            proposal = IndependentPolicyProposal.fromNative(PolicyCodec.take(input, 296));
            try { target = PolicyCodec.policy(input); }
            catch (IllegalArgumentException failure) { throw new IllegalStateException("native policy progress checkpoint", failure); }
        }
    }
    public Phase phase() { return phase; }
    /** Durable terminal cleanup only; not a new authorization. */
    public boolean retired() { return retired; }
    /** Null only for ABSENT. */
    public IndependentPolicyProposal proposal() { return proposal; }
    /** Null only for ABSENT. */
    public PolicyCheckpoint target() { return target; }
}
