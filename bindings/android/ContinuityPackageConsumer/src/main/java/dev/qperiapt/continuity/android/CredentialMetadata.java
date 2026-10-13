// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Canonical public output shape only; this class never authenticates an approval. */
final class CredentialMetadata {
    private final byte[] bytes;
    final Ids.CredentialRenewal operation;
    final Ids.CredentialStatement credential, statement;
    final Ids.PolicyContinuationStatement continuation;
    final Ids.PolicyStatement independent;
    final boolean adopts;

    CredentialMetadata(byte[] source, boolean proposal, boolean extended) {
        bytes = source.clone();
        int base = proposal ? 296 : 248;
        if (bytes.length != base && (!extended || bytes.length != base + 33)) malformed();
        int version = bytes[7] - '0';
        if (version < 1 || version > (extended ? 3 : 1) || bytes.length != base + (version == 1 ? 0 : 33)
                || !Arrays.equals(Arrays.copyOf(bytes, 8), ((proposal ? "QPCRNP0" : "QPCRNC0") + version).getBytes(StandardCharsets.US_ASCII))) malformed();
        for (int offset : proposal ? new int[] {8,40,72,104,136,168,216,264} : new int[] {8,40,72,104,136,168,216})
            if (!EnrollmentIntent.nonzero(Arrays.copyOfRange(bytes, offset, offset + 32))) malformed();
        ByteBuffer input = ByteBuffer.wrap(bytes);
        long fence = input.getLong(200), revision = input.getLong(208);
        if (fence == 0 || fence == -1 || revision == 0 || revision == -1) malformed();
        if (proposal && (revision == -2 || input.getLong(248) != fence || input.getLong(256) != revision + 1
                || Arrays.equals(Arrays.copyOfRange(bytes, 216, 248), Arrays.copyOfRange(bytes, 264, 296)))) malformed();
        if (version != 1 && (bytes[base] < 0 || bytes[base] > 1 || (version == 3 && bytes[base] != 0)
                || !EnrollmentIntent.nonzero(Arrays.copyOfRange(bytes, base + 1, base + 33)))) malformed();
        operation = new Ids.CredentialRenewal(Arrays.copyOfRange(bytes, 136, 168));
        credential = new Ids.CredentialStatement(Arrays.copyOfRange(bytes, 168, 200));
        continuation = version == 2 ? new Ids.PolicyContinuationStatement(Arrays.copyOfRange(bytes, base + 1, base + 33)) : null;
        independent = version == 3 ? new Ids.PolicyStatement(Arrays.copyOfRange(bytes, base + 1, base + 33)) : null;
        adopts = version == 2 && bytes[base] == 1;
        statement = adopts ? new Ids.CredentialStatement(continuation.encoded()) : credential;
    }
    byte[] encoded() { return bytes.clone(); }
    static CredentialMetadata framed(byte[] wire, boolean proposal) {
        int base = proposal ? 296 : 248, capacity = base + 33;
        if (wire.length != 4 + capacity) malformed();
        int length = ByteBuffer.wrap(wire).getInt();
        if (length != base && length != capacity) malformed();
        for (int i = 4 + length; i < wire.length; ++i) if (wire[i] != 0) malformed();
        return new CredentialMetadata(Arrays.copyOfRange(wire, 4, 4 + length), proposal, true);
    }
    private static void malformed() { throw new IllegalStateException("malformed native credential metadata"); }
}
