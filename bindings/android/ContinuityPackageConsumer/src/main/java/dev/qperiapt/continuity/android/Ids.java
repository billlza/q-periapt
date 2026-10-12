// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.security.SecureRandom;
import java.util.Arrays;

/** Public operation identities; retain original IDs across uncertain results. */
public final class Ids {
    private Ids() { }
    public abstract static class Value {
        private final byte[] bytes;
        private Value(byte[] bytes) {
            this.bytes = ConfigurationInputs.copy(bytes, 32, 32, "identity");
            if (!EnrollmentIntent.nonzero(this.bytes)) throw new IllegalArgumentException("zero identity");
        }
        public final byte[] encoded() { return bytes.clone(); }
        @Override public final boolean equals(Object other) {
            return other != null && other.getClass() == getClass() && Arrays.equals(bytes, ((Value) other).bytes);
        }
        @Override public final int hashCode() { return 31 * getClass().hashCode() + Arrays.hashCode(bytes); }
    }
    public static final class Initiation extends Value {
        public Initiation(byte[] bytes) { super(bytes); }
        public static Initiation random() {
            byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes); return new Initiation(bytes);
        }
    }
    public static final class Session extends Value { public Session(byte[] bytes) { super(bytes); } }
    public static final class Message extends Value { public Message(byte[] bytes) { super(bytes); } }
    public static final class AccountAuthority extends Value { public AccountAuthority(byte[] bytes) { super(bytes); } }
    public static final class ApplicationAccount extends Value { public ApplicationAccount(byte[] bytes) { super(bytes); } }
    public static final class Account extends Value { public Account(byte[] bytes) { super(bytes); } }
    public static final class RosterRefresh extends Value { public RosterRefresh(byte[] bytes) { super(bytes); } }
    public static final class Journal extends Value { public Journal(byte[] bytes) { super(bytes); } }
    public static final class RetiredReport extends Value { public RetiredReport(byte[] bytes) { super(bytes); } }
    public static final class PolicyRenewal extends Value { public PolicyRenewal(byte[] bytes) { super(bytes); } }
    public static final class PolicyStatement extends Value { public PolicyStatement(byte[] bytes) { super(bytes); } }
    public static final class PolicyAuthorization extends Value { public PolicyAuthorization(byte[] bytes) { super(bytes); } }
    public static final class CredentialRenewal extends Value { public CredentialRenewal(byte[] bytes) { super(bytes); } }
    public static final class CredentialStatement extends Value { public CredentialStatement(byte[] bytes) { super(bytes); } }
}
