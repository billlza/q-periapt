// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Objects;

/** Expected public association. Permission also requires the original live registry. */
public final class AccountAuthorityCheckpoint {
    private final Ids.ApplicationAccount application;
    private final Counter64 revision;
    private final Ids.Account account;
    public AccountAuthorityCheckpoint(Ids.ApplicationAccount application, Counter64 revision, Ids.Account account) {
        this.application = Objects.requireNonNull(application, "application account");
        this.revision = Objects.requireNonNull(revision, "revision");
        this.account = Objects.requireNonNull(account, "protocol account");
        if (revision.bits == 0 || revision.bits == -1) throw new IllegalArgumentException("registry revision");
    }
    public Ids.ApplicationAccount application() { return application; }
    public Counter64 revision() { return revision; }
    public Ids.Account account() { return account; }
    byte[] wire() { return ByteBuffer.allocate(72).put(application.encoded()).putLong(revision.bits).put(account.encoded()).array(); }
    static AccountAuthorityCheckpoint fromWire(byte[] wire) {
        if (wire.length != 72) throw new IllegalStateException("native registry checkpoint width");
        ByteBuffer reader = ByteBuffer.wrap(wire); byte[] application = new byte[32], account = new byte[32];
        reader.get(application); long revision = reader.getLong(); reader.get(account);
        if (revision == 0 || revision == -1 || !EnrollmentIntent.nonzero(application) || !EnrollmentIntent.nonzero(account))
            throw new IllegalStateException("native registry checkpoint scope");
        return new AccountAuthorityCheckpoint(new Ids.ApplicationAccount(application), Counter64.fromBits(revision), new Ids.Account(account));
    }
    @Override public boolean equals(Object other) {
        if (!(other instanceof AccountAuthorityCheckpoint)) return false;
        AccountAuthorityCheckpoint checkpoint = (AccountAuthorityCheckpoint) other;
        return application.equals(checkpoint.application) && revision.equals(checkpoint.revision) && account.equals(checkpoint.account);
    }
    @Override public int hashCode() { return Objects.hash(application, revision, account); }
}
