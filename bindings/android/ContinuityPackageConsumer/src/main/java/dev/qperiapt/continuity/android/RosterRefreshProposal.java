// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Complete original R expectation. Parsing these public bytes grants no approval. */
public final class RosterRefreshProposal {
    private final byte[] value;
    private final RosterRefreshScope scope;
    public RosterRefreshProposal(byte[] retainedBytes) {
        value = ConfigurationInputs.copy(retainedBytes, 417, 417, "roster proposal");
        if (!Arrays.equals(Arrays.copyOf(value, 8), "QPRWNP01".getBytes(StandardCharsets.US_ASCII))) invalid();
        for (int offset : new int[] {8, 40, 72, 104, 337, 385})
            if (!EnrollmentIntent.nonzero(field(offset))) invalid();
        ByteBuffer input = ByteBuffer.wrap(value);
        byte[] authorization = field(289);
        if (value[288] < 0 || value[288] > 1 || (value[288] == 1) != EnrollmentIntent.nonzero(authorization)) invalid();
        scope = new RosterRefreshScope(new Ids.RosterRefresh(field(136)),
            new RosterCheckpoint(Counter64.fromBits(input.getLong(168)), field(176)),
            new RosterCheckpoint(Counter64.fromBits(input.getLong(208)), field(216)),
            new PolicyCheckpoint(Counter64.fromBits(input.getLong(248)), field(256)),
            value[288] == 1 ? new Ids.PolicyAuthorization(authorization) : null);
        long fence = input.getLong(321), revision = input.getLong(329);
        if ((scope.policyAuthorization() == null) != Arrays.equals(field(256), field(104))
                || fence == 0 || fence == -1 || input.getLong(369) != fence
                || revision == 0 || Long.compareUnsigned(revision, -2L) >= 0
                || input.getLong(377) != revision + 1 || Arrays.equals(field(337), field(385))) invalid();
    }
    private byte[] field(int offset) { return Arrays.copyOfRange(value, offset, offset + 32); }
    private static void invalid() { throw new IllegalArgumentException("roster proposal grammar"); }
    static RosterRefreshProposal fromNative(byte[] bytes) {
        try { return new RosterRefreshProposal(bytes); }
        catch (IllegalArgumentException failure) { throw new IllegalStateException("malformed native roster proposal", failure); }
    }
    static RosterRefreshProposal preparation(byte[] bytes) {
        if (bytes.length != 424) throw new IllegalStateException("native roster preparation width");
        int present = ByteBuffer.wrap(bytes).getInt();
        if (present < 0 || present > 1 || EnrollmentIntent.nonzero(Arrays.copyOfRange(bytes, 421, 424)))
            throw new IllegalStateException("native roster preparation flags");
        byte[] proposal = Arrays.copyOfRange(bytes, 4, 421);
        if (present == 1) return fromNative(proposal);
        if (EnrollmentIntent.nonzero(proposal)) throw new IllegalStateException("absent roster preparation fields");
        return null;
    }
    public byte[] encoded() { return value.clone(); }
    public RosterRefreshScope scope() { return scope; }
}
