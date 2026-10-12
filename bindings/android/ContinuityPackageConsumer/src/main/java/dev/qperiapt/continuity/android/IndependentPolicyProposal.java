// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Complete original witness expectation. Parsing never grants approval or authority. */
public final class IndependentPolicyProposal {
    private final byte[] value;
    public IndependentPolicyProposal(byte[] retainedBytes) {
        value = ConfigurationInputs.copy(retainedBytes, 296, 296, "independent policy proposal");
        if (!Arrays.equals(Arrays.copyOf(value, 8), "QPPWNP01".getBytes(StandardCharsets.US_ASCII))) invalid();
        for (int offset : new int[] {8,40,72,104,136,168,216,264})
            if (!EnrollmentIntent.nonzero(Arrays.copyOfRange(value, offset, offset + 32))) invalid();
        ByteBuffer input = ByteBuffer.wrap(value); long fence = input.getLong(200), revision = input.getLong(208);
        if (fence == 0 || fence == -1 || input.getLong(248) != fence || revision == 0 || revision == -1 || revision == -2
                || input.getLong(256) != revision + 1 || Arrays.equals(Arrays.copyOfRange(value, 216, 248), Arrays.copyOfRange(value, 264, 296))) invalid();
    }
    private static void invalid() { throw new IllegalArgumentException("independent policy proposal grammar"); }
    static IndependentPolicyProposal fromNative(byte[] bytes) {
        try { return new IndependentPolicyProposal(bytes); }
        catch (IllegalArgumentException failure) { throw new IllegalStateException("malformed native policy proposal", failure); }
    }
    static IndependentPolicyProposal preparation(byte[] bytes) {
        if (bytes.length != 304) throw new IllegalStateException("native policy preparation width");
        ByteBuffer input = ByteBuffer.wrap(bytes); int present = input.getInt(), reserved = input.getInt();
        if (reserved != 0 || present < 0 || present > 1) throw new IllegalStateException("native policy preparation presence");
        byte[] proposal = PolicyCodec.take(input, 296);
        if (present == 1) return fromNative(proposal);
        if (EnrollmentIntent.nonzero(proposal)) throw new IllegalStateException("native absent policy preparation fields");
        return null;
    }
    public byte[] encoded() { return value.clone(); }
    public Ids.PolicyRenewal operation() { return new Ids.PolicyRenewal(Arrays.copyOfRange(value, 136, 168)); }
    public Ids.PolicyStatement statement() { return new Ids.PolicyStatement(Arrays.copyOfRange(value, 168, 200)); }
}
