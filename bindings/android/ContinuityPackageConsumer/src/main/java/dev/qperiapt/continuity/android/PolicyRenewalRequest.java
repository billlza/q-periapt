// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Objects;

/** Owned original request. Retain every field and the exact approvals across restart.
 * Construction checks shape; native staging rechecks signatures and actual journal state.
 */
public final class PolicyRenewalRequest {
    static final int NATIVE_BYTES = 33176;
    private final PolicyRenewalScope scope;
    private final Ids.Account account;
    private final RosterCheckpoint originalRosterCheckpoint;
    private final byte[] originalCredential, originalRoster, currentCredential, currentRoster;
    public PolicyRenewalRequest(PolicyRenewalScope scope, Ids.Account account, RosterCheckpoint originalRosterCheckpoint,
            byte[] originalCredential, byte[] originalRoster, byte[] currentCredential, byte[] currentRoster) {
        this.scope = Objects.requireNonNull(scope, "renewal scope");
        this.account = Objects.requireNonNull(account, "account");
        this.originalRosterCheckpoint = Objects.requireNonNull(originalRosterCheckpoint, "original roster checkpoint");
        if (originalRosterCheckpoint.version().compareTo(scope.currentRoster().version()) >= 0
                && !originalRosterCheckpoint.equals(scope.currentRoster()))
            throw new IllegalArgumentException("original roster checkpoint");
        this.originalCredential = ConfigurationInputs.copy(originalCredential, 1, 8192, "original credential");
        this.originalRoster = ConfigurationInputs.copy(originalRoster, 1, 8192, "original roster");
        this.currentCredential = ConfigurationInputs.copy(currentCredential, 1, 8192, "current credential");
        this.currentRoster = ConfigurationInputs.copy(currentRoster, 1, 8192, "current roster");
    }
    static PolicyRenewalRequest fromNative(byte[] wire) {
        if (wire.length != NATIVE_BYTES) throw new IllegalStateException("native policy request width");
        try {
            ByteBuffer input = ByteBuffer.wrap(wire);
            return new PolicyRenewalRequest(PolicyRenewalScope.read(input), new Ids.Account(PolicyCodec.take(input, 32)),
                PolicyCodec.roster(input), PolicyCodec.publicRecord(input), PolicyCodec.publicRecord(input),
                PolicyCodec.publicRecord(input), PolicyCodec.publicRecord(input));
        } catch (IllegalArgumentException failure) { throw new IllegalStateException("malformed native policy request", failure); }
    }
    byte[] nativeWire() {
        ByteBuffer output = ByteBuffer.allocate(NATIVE_BYTES); scope.write(output); output.put(account.encoded());
        PolicyCodec.checkpoint(output, originalRosterCheckpoint);
        for (byte[] bytes : new byte[][] {originalCredential, originalRoster, currentCredential, currentRoster})
            PolicyCodec.publicRecord(output, bytes);
        return output.array();
    }
    public PolicyRenewalScope scope() { return scope; }
    public Ids.Account account() { return account; }
    public RosterCheckpoint originalRosterCheckpoint() { return originalRosterCheckpoint; }
    public byte[] originalCredential() { return originalCredential.clone(); }
    public byte[] originalRoster() { return originalRoster.clone(); }
    public byte[] currentCredential() { return currentCredential.clone(); }
    public byte[] currentRoster() { return currentRoster.clone(); }
}
