// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Historical original-operation facts. Pending does not mean uncommitted;
 * Committed supplies no current traffic or cleanup permission by itself.
 */
public final class CredentialRenewalStatus {
    public enum Phase { ABSENT, PENDING, COMMITTED, EXPIRED_UNCOMMITTED, CLOSED }
    private final Phase phase;
    private final Ids.CredentialRenewal operation;
    private final Ids.CredentialStatement statement;
    private final RosterCheckpoint checkpoint;
    private final Counter64 observedAt;
    CredentialRenewalStatus(byte[] wire) {
        if (wire.length != 116) malformed();
        ByteBuffer input = ByteBuffer.wrap(wire); int kind = input.getInt();
        if (kind < 0 || kind > 4) malformed();
        phase = Phase.values()[kind];
        byte[] operation = new byte[32], statement = new byte[32], digest = new byte[32];
        input.get(operation); input.get(statement); long version = input.getLong(); input.get(digest); long at = input.getLong();
        if (kind == 0) {
            if (EnrollmentIntent.nonzero(Arrays.copyOfRange(wire, 4, 116))) malformed();
            this.operation = null; this.statement = null; checkpoint = null; observedAt = null; return;
        }
        if (!EnrollmentIntent.nonzero(operation) || !EnrollmentIntent.nonzero(statement) || ((kind == 3) != (at != 0))) malformed();
        this.operation = new Ids.CredentialRenewal(operation); this.statement = new Ids.CredentialStatement(statement);
        observedAt = kind == 3 ? Counter64.fromBits(at) : null;
        if (kind == 1) {
            if (version != 0 || EnrollmentIntent.nonzero(digest)) malformed();
            checkpoint = null;
        } else {
            if (version == 0 || version == -1 || !EnrollmentIntent.nonzero(digest)) malformed();
            checkpoint = new RosterCheckpoint(Counter64.fromBits(version), digest);
        }
    }
    private static void malformed() { throw new IllegalStateException("malformed native credential renewal status"); }
    public Phase phase() { return phase; }
    /** Null only for ABSENT. */
    public Ids.CredentialRenewal operation() { return operation; }
    /** Null only for ABSENT. */
    public Ids.CredentialStatement statement() { return statement; }
    /** Historical target for COMMITTED/CLOSED, observed head for EXPIRED_UNCOMMITTED; otherwise null. */
    public RosterCheckpoint checkpoint() { return checkpoint; }
    /** Present only for EXPIRED_UNCOMMITTED. */
    public Counter64 observedAt() { return observedAt; }
}
