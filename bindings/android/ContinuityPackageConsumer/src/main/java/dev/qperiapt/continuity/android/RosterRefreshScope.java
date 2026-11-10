// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Objects;

/** Exact original roster transition, distinct from credential or policy renewal. */
public final class RosterRefreshScope {
    private final Ids.RosterRefresh operation;
    private final RosterCheckpoint previous, target;
    private final PolicyCheckpoint policy;
    private final Ids.PolicyAuthorization authorization;
    RosterRefreshScope(Ids.RosterRefresh operation, RosterCheckpoint previous, RosterCheckpoint target,
            PolicyCheckpoint policy, Ids.PolicyAuthorization authorization) {
        this.operation = Objects.requireNonNull(operation, "roster operation");
        this.previous = Objects.requireNonNull(previous, "previous roster");
        this.target = Objects.requireNonNull(target, "target roster");
        this.policy = Objects.requireNonNull(policy, "roster policy");
        this.authorization = authorization;
        if (previous.version().compareTo(target.version()) >= 0) throw new IllegalArgumentException("roster target must advance");
    }
    static RosterRefreshScope read(ByteBuffer input) {
        Ids.RosterRefresh operation = new Ids.RosterRefresh(PolicyCodec.take(input, 32));
        RosterCheckpoint previous = PolicyCodec.roster(input), target = PolicyCodec.roster(input);
        PolicyCheckpoint policy = PolicyCodec.policy(input);
        byte[] authorization = PolicyCodec.take(input, 32);
        int flag = input.getInt(), reserved = input.getInt();
        if (flag < 0 || flag > 1 || reserved != 0 || (flag == 1) != EnrollmentIntent.nonzero(authorization))
            throw new IllegalArgumentException("roster policy authorization presence");
        return new RosterRefreshScope(operation, previous, target, policy,
            flag == 1 ? new Ids.PolicyAuthorization(authorization) : null);
    }
    public Ids.RosterRefresh operation() { return operation; }
    public RosterCheckpoint previous() { return previous; }
    public RosterCheckpoint target() { return target; }
    public PolicyCheckpoint policy() { return policy; }
    /** Null exactly when the selected roster policy is the original P0. */
    public Ids.PolicyAuthorization policyAuthorization() { return authorization; }
    @Override public boolean equals(Object other) {
        if (!(other instanceof RosterRefreshScope)) return false;
        RosterRefreshScope value = (RosterRefreshScope) other;
        return operation.equals(value.operation) && previous.equals(value.previous) && target.equals(value.target)
            && policy.equals(value.policy) && Objects.equals(authorization, value.authorization);
    }
    @Override public int hashCode() { return Objects.hash(operation, previous, target, policy, authorization); }
}
