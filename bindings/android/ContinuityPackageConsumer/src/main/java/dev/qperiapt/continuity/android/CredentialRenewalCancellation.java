// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Original target-free expectation. It neither proves Closed nor grants cleanup permission. */
public final class CredentialRenewalCancellation {
    private final byte[] value;
    CredentialRenewalCancellation(byte[] bytes) {
        value = bytes.clone();
        if (value.length != 248 || !Arrays.equals(Arrays.copyOf(value, 8), "QPCRNC01".getBytes(StandardCharsets.US_ASCII))) malformed();
        for (int offset : new int[] {8,40,72,104,136,168,216})
            if (!EnrollmentIntent.nonzero(Arrays.copyOfRange(value, offset, offset + 32))) malformed();
        ByteBuffer input = ByteBuffer.wrap(value);
        for (int offset : new int[] {200,208}) { long counter = input.getLong(offset); if (counter == 0 || counter == -1) malformed(); }
    }
    private static void malformed() { throw new IllegalStateException("malformed native credential cancellation"); }
    public byte[] encoded() { return value.clone(); }
    public Ids.CredentialRenewal operation() { return new Ids.CredentialRenewal(Arrays.copyOfRange(value, 136, 168)); }
    public Ids.CredentialStatement statement() { return new Ids.CredentialStatement(Arrays.copyOfRange(value, 168, 200)); }
}
