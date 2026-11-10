// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Prepared local storage or exact public genesis requiring independent witness enrollment. */
public final class StoragePreparation {
    private final boolean witness;
    private final byte[] journal, subject, digest;
    StoragePreparation(byte[] wire) {
        if (wire.length != 164) throw new IllegalStateException("native preparation width");
        int protection = ByteBuffer.wrap(wire).getInt();
        journal = Arrays.copyOfRange(wire, 4, 36); subject = Arrays.copyOfRange(wire, 36, 132); digest = Arrays.copyOfRange(wire, 132, 164);
        witness = protection == 2;
        if ((protection != 1 && protection != 2) || !EnrollmentIntent.nonzero(journal)) malformed();
        if (witness) {
            if (!Arrays.equals(journal, Arrays.copyOfRange(subject, 0, 32))
                    || !EnrollmentIntent.nonzero(Arrays.copyOfRange(subject, 32, 64))
                    || !EnrollmentIntent.nonzero(Arrays.copyOfRange(subject, 64, 96)) || !EnrollmentIntent.nonzero(digest)) malformed();
        } else if (EnrollmentIntent.nonzero(subject) || EnrollmentIntent.nonzero(digest)) malformed();
    }
    private static void malformed() { throw new IllegalStateException("native preparation scope"); }
    public boolean requiresWitnessEnrollment() { return witness; }
    public byte[] journalId() { return journal.clone(); }
    /** Null for local-only protection. */
    public byte[] witnessSubject() { return witness ? subject.clone() : null; }
    public byte[] imageDigest() { return witness ? digest.clone() : null; }
}
