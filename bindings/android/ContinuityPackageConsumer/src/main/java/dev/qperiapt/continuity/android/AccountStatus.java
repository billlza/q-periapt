// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Local aggregate journal state. COMMITTED does not assert remote delivery. */
public final class AccountStatus {
    public enum Phase { ABSENT, RESERVED, COMMITTED, ABANDONING, ABANDONED, RETIRED }
    private final Phase phase;
    private final Ids.AccountAbandonment report;
    AccountStatus(byte[] wire) {
        if (wire == null || wire.length != 33 || (wire[0] & 255) > 5) malformed();
        phase = Phase.values()[wire[0]];
        byte[] bytes = java.util.Arrays.copyOfRange(wire, 1, 33);
        boolean present = phase == Phase.ABANDONING || phase == Phase.ABANDONED;
        if (EnrollmentIntent.nonzero(bytes) != present) malformed();
        report = present ? new Ids.AccountAbandonment(bytes) : null;
    }
    private static void malformed() { throw new IllegalStateException("malformed native account status"); }
    public Phase phase() { return phase; }
    /** Exact retained abandonment report, present only for ABANDONING/ABANDONED. */
    public Ids.AccountAbandonment report() { return report; }
}
