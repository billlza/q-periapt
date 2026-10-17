// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Public test interchange only: explicit fields, never native struct memory or an approval. */
final class PolicyProbeRecords {
    private PolicyProbeRecords() { }
    private static long bits(Counter64 value) { return Long.parseUnsignedLong(value.toString()); }
    private static void checkpoint(ByteBuffer output, RosterCheckpoint value) { output.putLong(bits(value.version())).put(value.digest()); }
    private static void checkpoint(ByteBuffer output, PolicyCheckpoint value) { output.putLong(bits(value.version())).put(value.digest()); }
    private static byte[] take(ByteBuffer input, int length) { byte[] value = new byte[length]; input.get(value); return value; }
    private static RosterCheckpoint roster(ByteBuffer input) { return new RosterCheckpoint(counter(input), take(input, 32)); }
    private static PolicyCheckpoint policy(ByteBuffer input) { return new PolicyCheckpoint(counter(input), take(input, 32)); }
    private static void record(ByteBuffer output, byte[] value) { output.putInt(value.length).put(value); output.position(output.position() + 8192 - value.length); }
    private static byte[] record(ByteBuffer input) {
        int length = input.getInt(); require(length > 0 && length <= 8192, "public record length");
        byte[] value = take(input, length);
        for (int i = length; i < 8192; ++i) require(input.get() == 0, "public record tail");
        return value;
    }
    static byte[] request(PolicyRenewalRequest value) {
        ByteBuffer out = ByteBuffer.allocate(33176); PolicyRenewalScope scope = value.scope();
        out.put(scope.operation().encoded()).put(scope.journal().encoded()).put(scope.originalOwner());
        out.put(scope.originalCredential()).put(scope.currentCredential()); checkpoint(out, scope.currentRoster());
        checkpoint(out, scope.originalPolicy()); checkpoint(out, scope.previousPolicy());
        out.put(scope.previousAuthorization() == null ? new byte[32] : scope.previousAuthorization().encoded());
        out.putInt(scope.previousAuthorization() == null ? 0 : 1).putInt(0);
        out.put(value.account().encoded()); checkpoint(out, value.originalRosterCheckpoint());
        record(out, value.originalCredential()); record(out, value.originalRoster());
        record(out, value.currentCredential()); record(out, value.currentRoster());
        return out.array();
    }
    static PolicyRenewalRequest request(byte[] bytes) {
        require(bytes.length == 33176, "retained request width"); ByteBuffer input = ByteBuffer.wrap(bytes);
        Ids.PolicyRenewal operation = new Ids.PolicyRenewal(take(input, 32)); Ids.Journal journal = new Ids.Journal(take(input, 32));
        byte[] owner = take(input, 32), original = take(input, 32), current = take(input, 32);
        RosterCheckpoint roster = roster(input); PolicyCheckpoint policy = policy(input), previous = policy(input);
        byte[] authorization = take(input, 32); int present = input.getInt(), reserved = input.getInt();
        require(present >= 0 && present <= 1 && reserved == 0, "authorization flags");
        if (present == 0) for (byte b : authorization) require(b == 0, "absent authorization");
        PolicyRenewalScope scope = new PolicyRenewalScope(operation, journal, owner, original, current, roster, policy, previous,
            present == 0 ? null : new Ids.PolicyAuthorization(authorization));
        return new PolicyRenewalRequest(scope, new Ids.Account(take(input, 32)), roster(input),
            record(input), record(input), record(input), record(input));
    }
    static byte[] status(PolicyRenewalStatus value) {
        ByteBuffer out = ByteBuffer.allocate(160).putInt(value.phase().ordinal()).putInt(value.reason() == null ? 0 : value.reason().ordinal() + 1);
        if (value.operation() != null) out.put(value.operation().encoded()).put(value.statement().encoded());
        out.position(72); if (value.target() != null) checkpoint(out, value.target());
        out.position(112); if (value.observedRoster() != null) checkpoint(out, value.observedRoster());
        out.position(152); if (value.observedAt() != null) out.putLong(bits(value.observedAt()));
        return out.array();
    }
    static byte[] progress(IndependentPolicyProgress value) {
        ByteBuffer out = ByteBuffer.allocate(344).putInt(value.phase().ordinal()).putInt(value.retired() ? 1 : 0);
        if (value.proposal() != null) { out.put(value.proposal().encoded()); checkpoint(out, value.target()); }
        return out.array();
    }
}
