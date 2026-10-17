// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Synthetic framing controls plus real JNI rejection; not signature or lifecycle evidence. */
final class PolicyBridgeProbe {
    private PolicyBridgeProbe() { }
    private static byte[] id(int value) { byte[] bytes = new byte[32]; Arrays.fill(bytes, (byte)value); return bytes; }
    private static void rejected(Class<? extends Throwable> type, Runnable operation) {
        try { operation.run(); }
        catch (Throwable failure) {
            if (type.isInstance(failure)) return;
            throw new AssertionError("unexpected policy rejection", failure);
        }
        throw new AssertionError("policy input admitted");
    }
    private static void nativeCode(int expected, Runnable operation) {
        try { operation.run(); }
        catch (ContinuityFailure failure) {
            if (failure.code() == expected) return;
            throw new AssertionError("policy native status changed", failure);
        }
        throw new AssertionError("native failure became success");
    }
    private static PolicyRenewalRequest request() {
        RosterCheckpoint roster = new RosterCheckpoint(new Counter64("1"), id(6));
        PolicyCheckpoint policy = new PolicyCheckpoint(new Counter64("2"), id(7));
        PolicyRenewalScope scope = new PolicyRenewalScope(new Ids.PolicyRenewal(id(1)), new Ids.Journal(id(2)),
            id(3), id(4), id(5), roster, policy, policy, null);
        return new PolicyRenewalRequest(scope, new Ids.Account(id(8)), roster,
            new byte[] {11}, new byte[] {12,13}, new byte[] {14}, new byte[] {15,16});
    }
    private static void records() {
        PolicyRenewalRequest original = request(); byte[] wire = original.nativeWire();
        PolicyRenewalRequest decoded = PolicyRenewalRequest.fromNative(wire);
        if (!Arrays.equals(wire, decoded.nativeWire()) || !decoded.scope().operation().equals(original.scope().operation()))
            throw new AssertionError("policy request framing");
        byte[] copy = decoded.originalCredential(); copy[0] ^= 1;
        if (!Arrays.equals(original.originalCredential(), decoded.originalCredential())) throw new AssertionError("borrowed request field");
        for (int offset : new int[] {316,397,312}) {
            byte[] invalid = wire.clone(); invalid[offset] = 1;
            rejected(IllegalStateException.class, () -> PolicyRenewalRequest.fromNative(invalid));
        }
        byte[] truncated = Arrays.copyOf(wire, wire.length - 1);
        rejected(IllegalStateException.class, () -> PolicyRenewalRequest.fromNative(truncated));
        byte[] unsigned = wire.clone(); ByteBuffer.wrap(unsigned).putLong(160, -2L);
        if (!PolicyRenewalRequest.fromNative(unsigned).scope().currentRoster().version().toString().equals("18446744073709551614"))
            throw new AssertionError("unsigned policy request counter");
        byte[] absent = new byte[160];
        if (new PolicyRenewalStatus(absent).phase() != PolicyRenewalStatus.Phase.ABSENT) throw new AssertionError("absent policy status");
        absent[159] = 1; rejected(IllegalStateException.class, () -> new PolicyRenewalStatus(absent));
        ByteBuffer status = ByteBuffer.allocate(160).putInt(1).putInt(0).put(id(1)).put(id(2)).putLong(3).put(id(3));
        if (new PolicyRenewalStatus(status.array()).phase() != PolicyRenewalStatus.Phase.PENDING) throw new AssertionError("pending policy status");
        status.putInt(0, 3).putInt(4, 1).putLong(112, 4).position(120); status.put(id(4)).putLong(5);
        PolicyRenewalStatus terminal = new PolicyRenewalStatus(status.array());
        if (terminal.reason() != PolicyRenewalStatus.Reason.EXPIRED || !terminal.observedAt().equals(new Counter64("5")))
            throw new AssertionError("abandoned policy status");
        status.putInt(0, 2); rejected(IllegalStateException.class, () -> new PolicyRenewalStatus(status.array()));
    }
    private static void proposals() {
        byte[] wire = new byte[296]; ByteBuffer p = ByteBuffer.wrap(wire); p.put("QPPWNP01".getBytes(StandardCharsets.US_ASCII));
        for (int offset : new int[] {8,40,72,104,136,168,216,264}) { p.position(offset); p.put(id(offset)); }
        p.putLong(200, 1).putLong(208, 2).putLong(248, 1).putLong(256, 3);
        IndependentPolicyProposal proposal = new IndependentPolicyProposal(wire);
        if (!Arrays.equals(proposal.encoded(), wire)) throw new AssertionError("policy proposal roundtrip");
        wire[3] = 'C'; rejected(IllegalArgumentException.class, () -> new IndependentPolicyProposal(wire));
        ByteBuffer preparation = ByteBuffer.allocate(304).putInt(1).putInt(0).put(proposal.encoded());
        if (!Arrays.equals(IndependentPolicyProposal.preparation(preparation.array()).encoded(), proposal.encoded())) throw new AssertionError("retained preparation");
        preparation.putInt(0, 0); rejected(IllegalStateException.class, () -> IndependentPolicyProposal.preparation(preparation.array()));
        if (IndependentPolicyProposal.preparation(new byte[304]) != null) throw new AssertionError("absent preparation");
        ByteBuffer progress = ByteBuffer.allocate(344).putInt(2).putInt(1).put(proposal.encoded()).putLong(4).put(id(5));
        if (!new IndependentPolicyProgress(progress.array()).retired()) throw new AssertionError("retired policy progress");
        progress.putInt(0, 1); rejected(IllegalStateException.class, () -> new IndependentPolicyProgress(progress.array()));
        for (int n = 1; n <= 5; ++n)
            if (IndependentPolicyState.fromNative(ByteBuffer.allocate(4).putInt(n).array()).ordinal() != n - 1) throw new AssertionError("policy witness state");
        rejected(IllegalStateException.class, () -> IndependentPolicyState.fromNative(new byte[4]));
    }
    static void run() {
        records(); proposals();
        for (int repeat = 0; repeat < 128; ++repeat) {
            for (int operation = Native.POLICY_REQUEST; operation <= Native.POLICY_ACTIVATE; ++operation) {
                final int selected = operation;
                rejected(NullPointerException.class, () -> Native.policyCommand(0, selected, null));
            }
            rejected(IllegalArgumentException.class, () -> Native.policyCommand(0, 0, new byte[0][]));
            rejected(IllegalArgumentException.class, () -> Native.policyCommand(0, 15, new byte[0][]));
            nativeCode(2, () -> Native.policyCommand(0, Native.POLICY_STATUS, new byte[0][]));
            nativeCode(1, () -> Native.selectPolicy(0, 0));
        }
        PolicyRenewalRequest request = request();
        AccountPin pin = new AccountPin(id(8), new byte[1985], id(9), new Counter64("1"), id(6));
        ConfigurationInputs.ProtocolPolicy policy = new ConfigurationInputs.ProtocolPolicy(id(9), new byte[1985], "2", id(7), new byte[] {1});
        byte[][] inputs = PolicyCodec.join(new byte[][] {request.nativeWire()}, PolicyCodec.pin(pin), PolicyCodec.pin(pin),
            new byte[][] {new byte[7618]}, PolicyCodec.document(policy));
        for (int field = 0; field < inputs.length; ++field) {
            byte[][] invalid = inputs.clone(); invalid[field] = null;
            rejected(NullPointerException.class, () -> Native.policyCommand(0, Native.POLICY_STAGE, invalid));
        }
        byte[][] invalid = inputs.clone(); invalid[0] = inputs[0].clone(); invalid[0][397] = 1;
        rejected(IllegalArgumentException.class, () -> Native.policyCommand(0, Native.POLICY_STAGE, invalid));
        // A well-shaped 17-field stage reaches native signature/pin validation.
        nativeCode(101, () -> Native.policyCommand(0, Native.POLICY_STAGE, inputs));
    }
}
