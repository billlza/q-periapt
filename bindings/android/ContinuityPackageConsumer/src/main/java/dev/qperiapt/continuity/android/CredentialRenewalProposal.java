// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Exact public expectation for independent witness approval; possession is not approval. */
public final class CredentialRenewalProposal {
    private final byte[] value;
    CredentialRenewalProposal(byte[] bytes) {
        value = bytes.clone();
        if (value.length != 296 || !Arrays.equals(Arrays.copyOf(value, 8), "QPCRNP01".getBytes(StandardCharsets.US_ASCII))) malformed();
        for (int offset : new int[] {8,40,72,104,136,168,216,264})
            if (!EnrollmentIntent.nonzero(Arrays.copyOfRange(value, offset, offset + 32))) malformed();
        ByteBuffer input = ByteBuffer.wrap(value); long fence = input.getLong(200), revision = input.getLong(208);
        if (fence == 0 || fence == -1 || input.getLong(248) != fence || revision == 0 || revision == -1 || revision == -2
                || input.getLong(256) != revision + 1 || Arrays.equals(Arrays.copyOfRange(value, 216, 248), Arrays.copyOfRange(value, 264, 296))) malformed();
    }
    private static void malformed() { throw new IllegalStateException("malformed native credential renewal proposal"); }
    public byte[] encoded() { return value.clone(); }
    public Ids.CredentialRenewal operation() { return new Ids.CredentialRenewal(Arrays.copyOfRange(value, 136, 168)); }
    public Ids.CredentialStatement statement() { return new Ids.CredentialStatement(Arrays.copyOfRange(value, 168, 200)); }
}
