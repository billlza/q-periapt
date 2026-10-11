// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Durable progress only: ACTIVE is not a statement of current traffic authority. */
public final class EnrollmentStatus {
    public enum Phase { PREPARING, REQUESTED, ACCEPTED, ACTIVATING, ACTIVE, REFRESHING, ROSTER_RESOLVED }
    public static final class Checkpoint {
        private final Counter64 version;
        private final byte[] digest;
        private Checkpoint(ByteBuffer input) {
            version = Counter64.fromBits(input.getLong()); digest = new byte[32]; input.get(digest);
            if (version.bits == 0 || version.bits == -1 || !EnrollmentIntent.nonzero(digest)) malformed();
        }
        public Counter64 version() { return version; }
        public byte[] digest() { return digest.clone(); }
    }
    private final Phase phase;
    private final byte[] signing, journal;
    private final Checkpoint previous, next;
    private static void malformed() { throw new IllegalStateException("malformed native enrollment status"); }
    EnrollmentStatus(byte[] wire) {
        if (wire.length != 148) malformed();
        ByteBuffer input = ByteBuffer.wrap(wire);
        int number = input.getInt();
        if (number < 1 || number > 7) malformed();
        phase = Phase.values()[number - 1];
        signing = new byte[32]; input.get(signing);
        byte[] id = new byte[32]; input.get(id);
        if (!EnrollmentIntent.nonzero(signing) || EnrollmentIntent.nonzero(id) != (number >= 3)) malformed();
        journal = number >= 3 ? id : null;
        if (number >= 6) {
            previous = new Checkpoint(input); next = new Checkpoint(input);
            if (previous.version.compareTo(next.version) >= 0) malformed();
        } else {
            if (EnrollmentIntent.nonzero(Arrays.copyOfRange(wire, 68, 148))) malformed();
            previous = null; next = null;
        }
    }
    public Phase phase() { return phase; }
    public byte[] signingKeyId() { return signing.clone(); }
    /** Null until a journal has been accepted. */
    public byte[] journalId() { return journal == null ? null : journal.clone(); }
    /** Original refresh pair, present only for REFRESHING or ROSTER_RESOLVED. */
    public Checkpoint previous() { return previous; }
    public Checkpoint next() { return next; }
}
