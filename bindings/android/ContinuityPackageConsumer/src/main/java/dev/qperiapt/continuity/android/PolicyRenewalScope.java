// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Objects;

/** Independently retained original expectation. An incoming approval cannot choose this scope. */
public final class PolicyRenewalScope {
    private final Ids.PolicyRenewal operation;
    private final Ids.Journal journal;
    private final byte[] originalOwner, originalCredential, currentCredential;
    private final RosterCheckpoint currentRoster;
    private final PolicyCheckpoint originalPolicy, previousPolicy;
    private final Ids.PolicyAuthorization previousAuthorization;

    public PolicyRenewalScope(Ids.PolicyRenewal operation, Ids.Journal journal, byte[] originalOwner,
            byte[] originalCredential, byte[] currentCredential, RosterCheckpoint currentRoster,
            PolicyCheckpoint originalPolicy, PolicyCheckpoint previousPolicy,
            Ids.PolicyAuthorization previousAuthorization) {
        this.operation = Objects.requireNonNull(operation, "policy operation");
        this.journal = Objects.requireNonNull(journal, "journal");
        this.originalOwner = PolicyCodec.identity(originalOwner, "original owner");
        this.originalCredential = PolicyCodec.identity(originalCredential, "original credential");
        this.currentCredential = PolicyCodec.identity(currentCredential, "current credential");
        this.currentRoster = Objects.requireNonNull(currentRoster, "current roster");
        this.originalPolicy = Objects.requireNonNull(originalPolicy, "original policy");
        this.previousPolicy = Objects.requireNonNull(previousPolicy, "previous policy");
        this.previousAuthorization = previousAuthorization;
        if (previousAuthorization == null ? !originalPolicy.equals(previousPolicy)
                : previousPolicy.version().compareTo(originalPolicy.version()) <= 0)
            throw new IllegalArgumentException("previous policy authorization");
    }
    static PolicyRenewalScope read(ByteBuffer input) {
        Ids.PolicyRenewal operation = new Ids.PolicyRenewal(PolicyCodec.take(input, 32));
        Ids.Journal journal = new Ids.Journal(PolicyCodec.take(input, 32));
        byte[] owner = PolicyCodec.take(input, 32), original = PolicyCodec.take(input, 32), current = PolicyCodec.take(input, 32);
        RosterCheckpoint roster = PolicyCodec.roster(input);
        PolicyCheckpoint policy = PolicyCodec.policy(input), previous = PolicyCodec.policy(input);
        byte[] authorization = PolicyCodec.take(input, 32); int present = input.getInt(), reserved = input.getInt();
        if (reserved != 0 || present < 0 || present > 1 || (present == 1) != EnrollmentIntent.nonzero(authorization))
            throw new IllegalArgumentException("policy authorization presence");
        return new PolicyRenewalScope(operation, journal, owner, original, current, roster, policy, previous,
            present == 1 ? new Ids.PolicyAuthorization(authorization) : null);
    }
    void write(ByteBuffer output) {
        output.put(operation.encoded()).put(journal.encoded()).put(originalOwner).put(originalCredential).put(currentCredential);
        PolicyCodec.checkpoint(output, currentRoster); PolicyCodec.checkpoint(output, originalPolicy); PolicyCodec.checkpoint(output, previousPolicy);
        output.put(previousAuthorization == null ? new byte[32] : previousAuthorization.encoded());
        output.putInt(previousAuthorization == null ? 0 : 1).putInt(0);
    }
    public Ids.PolicyRenewal operation() { return operation; }
    public Ids.Journal journal() { return journal; }
    public byte[] originalOwner() { return originalOwner.clone(); }
    public byte[] originalCredential() { return originalCredential.clone(); }
    public byte[] currentCredential() { return currentCredential.clone(); }
    public RosterCheckpoint currentRoster() { return currentRoster; }
    public PolicyCheckpoint originalPolicy() { return originalPolicy; }
    public PolicyCheckpoint previousPolicy() { return previousPolicy; }
    /** Null exactly when the previous policy is the original P0. */
    public Ids.PolicyAuthorization previousAuthorization() { return previousAuthorization; }
}
