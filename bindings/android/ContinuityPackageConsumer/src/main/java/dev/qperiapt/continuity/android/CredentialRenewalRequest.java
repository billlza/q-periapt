// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Exact original issuer inputs. Retain all fields and the operation before submission;
 * retry an unknown submission with that same request. This is neither a grant nor a
 * reservation. The issuer must independently authenticate, authorize and deduplicate. */
public final class CredentialRenewalRequest {
    static final int NATIVE_BYTES = 33120;
    private final Ids.CredentialRenewal operation;
    private final Ids.Journal journal;
    private final Ids.Account account;
    private final byte[] originalOwner, originalPolicyDigest;
    private final PolicyCheckpoint currentPolicy;
    private final Ids.PolicyAuthorization currentPolicyAuthorization;
    private final RosterCheckpoint previousRosterCheckpoint, originalRosterCheckpoint;
    private final Counter64 previousValidFrom, previousValidUntil;
    private final byte[] originalCredential, originalRoster, previousCredential, previousRoster;

    private CredentialRenewalRequest(ByteBuffer input) {
        operation = new Ids.CredentialRenewal(PolicyCodec.take(input, 32));
        journal = new Ids.Journal(PolicyCodec.take(input, 32));
        originalOwner = PolicyCodec.identity(PolicyCodec.take(input, 32), "original owner");
        originalPolicyDigest = PolicyCodec.identity(PolicyCodec.take(input, 32), "original policy");
        currentPolicy = PolicyCodec.policy(input);
        byte[] authorization = PolicyCodec.take(input, 32);
        int present = input.getInt(), reserved = input.getInt();
        if (reserved != 0 || (present != 0 && present != 1)
                || (present == 1) != EnrollmentIntent.nonzero(authorization))
            throw new IllegalArgumentException("current policy authorization");
        currentPolicyAuthorization = present == 1 ? new Ids.PolicyAuthorization(authorization) : null;
        if (present == 0 && !Arrays.equals(currentPolicy.digest(), originalPolicyDigest))
            throw new IllegalArgumentException("unbound current policy");
        previousRosterCheckpoint = PolicyCodec.roster(input); originalRosterCheckpoint = PolicyCodec.roster(input);
        if (originalRosterCheckpoint.version().compareTo(previousRosterCheckpoint.version()) >= 0
                && !originalRosterCheckpoint.equals(previousRosterCheckpoint))
            throw new IllegalArgumentException("credential predecessor roster");
        previousValidFrom = Counter64.fromBits(input.getLong()); previousValidUntil = Counter64.fromBits(input.getLong());
        if (previousValidFrom.compareTo(previousValidUntil) >= 0 || previousValidUntil.bits == -1)
            throw new IllegalArgumentException("credential validity");
        account = new Ids.Account(PolicyCodec.take(input, 32));
        originalCredential = PolicyCodec.publicRecord(input); originalRoster = PolicyCodec.publicRecord(input);
        previousCredential = PolicyCodec.publicRecord(input); previousRoster = PolicyCodec.publicRecord(input);
    }
    static CredentialRenewalRequest fromNative(byte[] wire) {
        if (wire.length != NATIVE_BYTES) throw new IllegalStateException("native credential request width");
        try { return new CredentialRenewalRequest(ByteBuffer.wrap(wire)); }
        catch (IllegalArgumentException failure) { throw new IllegalStateException("malformed native credential request", failure); }
    }
    public Ids.CredentialRenewal operation() { return operation; }
    public Ids.Journal journal() { return journal; }
    public Ids.Account account() { return account; }
    public byte[] originalOwner() { return originalOwner.clone(); }
    public byte[] originalPolicyDigest() { return originalPolicyDigest.clone(); }
    public PolicyCheckpoint currentPolicy() { return currentPolicy; }
    /** Null means no policy authorization has been adopted; it is not a failure value. */
    public Ids.PolicyAuthorization currentPolicyAuthorization() { return currentPolicyAuthorization; }
    public RosterCheckpoint previousRosterCheckpoint() { return previousRosterCheckpoint; }
    public RosterCheckpoint originalRosterCheckpoint() { return originalRosterCheckpoint; }
    public Counter64 previousValidFrom() { return previousValidFrom; }
    public Counter64 previousValidUntil() { return previousValidUntil; }
    public byte[] originalCredential() { return originalCredential.clone(); }
    public byte[] originalRoster() { return originalRoster.clone(); }
    public byte[] previousCredential() { return previousCredential.clone(); }
    public byte[] previousRoster() { return previousRoster.clone(); }
}
