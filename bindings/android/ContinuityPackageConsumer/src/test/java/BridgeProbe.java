// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Real JNI boundary checks; no fake native implementation. */
public final class BridgeProbe {
    private BridgeProbe() { }
    private static void rejected(Class<? extends Throwable> type, Runnable call) {
        try { call.run(); } catch (Throwable failure) {
            if (type.isInstance(failure)) return;
            throw new AssertionError("unexpected exception", failure);
        }
        throw new AssertionError("invalid input admitted");
    }
    public static void main(String[] ignored) {
        for (int repeat = 0; repeat < 128; ++repeat) {
            rejected(NullPointerException.class, () -> Native.prepareConfiguration(null, 1, 1, 1));
            rejected(IllegalArgumentException.class, () -> Native.prepareConfiguration(new byte[12][], 1, 1, 1));
            rejected(IllegalArgumentException.class, () -> Native.prepareConfiguration(new byte[13][], 4, 1, 1));
            rejected(IllegalArgumentException.class, () -> Native.prepareConfiguration(new byte[13][], 1, 3, 1));
            byte[][] shape = {new byte[1], new byte[32], new byte[1952], new byte[0], new byte[1],
                new byte[3309], new byte[0], new byte[32], new byte[1985], new byte[32], new byte[1], new byte[1], new byte[1]};
            shape[12] = null;
            rejected(NullPointerException.class, () -> Native.prepareConfiguration(shape, 1, 1, 1));
            shape[12] = new byte[8193];
            rejected(IllegalArgumentException.class, () -> Native.prepareConfiguration(shape, 1, 1, 1));
            rejected(IllegalArgumentException.class, () -> Native.beginEnrollment(0, null, null, 0, 0, 0));
            rejected(NullPointerException.class, () -> Native.beginEnrollment(0, null, null, 1, 0, 0));
            rejected(IllegalArgumentException.class, () -> Native.beginEnrollment(0, null, new long[2], 1, 0, 0));
            rejected(IllegalArgumentException.class, () -> Native.enrollmentQuery(0, 0));
            rejected(IllegalArgumentException.class, () -> Native.enrollmentAccept(0, new byte[5][], 1));
            rejected(NullPointerException.class, () -> Native.provisionAuthority(null));
            rejected(IllegalArgumentException.class, () -> Native.provisionAuthority(new byte[][] {new byte[0]}));
            rejected(IllegalArgumentException.class, () -> Native.prepareAuthority(new byte[4][], true));
            rejected(IllegalArgumentException.class, () -> Native.authorityCommand(0, 3, new byte[0][], 0));
            rejected(IllegalArgumentException.class, () -> Native.authorityCommand(0, 1, new byte[][] {new byte[31]}, 0));
            rejected(IllegalArgumentException.class, () -> Native.selectAuthority(0, 0, new byte[][] {new byte[71]}));
            rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, 0, new byte[0][], 0));
            rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, 10, new byte[0][], 0));
            rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, 9, new byte[0][], 0));
            rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, 9,
                new byte[][] {new byte[65537], new byte[32], new byte[1985], new byte[32], new byte[32], new byte[32]}, 1));
            rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, 1, new byte[0][], 1));
            rejected(NullPointerException.class, () -> Native.credentialCommand(0, 1, null, 0));
            rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, 6, new byte[][] {new byte[32], new byte[31]}, 0));
            rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, 2,
                new byte[][] {new byte[65537], new byte[32], new byte[1985], new byte[32], new byte[32], new byte[32]}, 1));
        }
        credentialCodecs();
        rejected(ContinuityFailure.class, () -> Native.enrollmentQuery(0, 1));
        rejected(IllegalArgumentException.class, () -> Native.path("\ud800"));
        rejected(IllegalArgumentException.class, () -> Native.path("a\u0000b"));
        rejected(IllegalArgumentException.class, () -> Native.path("\u20ac".repeat(1366)));
        rejected(NullPointerException.class, () -> Native.path(null));
        ConfigurationInputs.LocalTlsIdentity tls = new ConfigurationInputs.LocalTlsIdentity(new byte[] {1}, new byte[] {2});
        byte[][] copy = tls.snapshot();
        tls.close();
        rejected(IllegalStateException.class, tls::snapshot);
        if (copy[1][0] != 2) throw new AssertionError("caller snapshot was not independent");
        java.util.Arrays.fill(copy[1], (byte) 0);
        PolicyBridgeProbe.run();
        RosterBridgeProbe.run();
        RetiredBridgeProbe.run();
        RootBridgeProbe.run();
        System.out.println("configuration:bridge:passed");
    }
    private static void credentialCodecs() {
        rejected(IllegalStateException.class, () -> RosterCheckpoint.decode(new byte[40]));
        rejected(IllegalStateException.class, () -> RosterCheckpoint.decode(new byte[39]));
        byte[] checkpoint = new byte[40]; checkpoint[0] = (byte) 0x80; checkpoint[7] = 1; checkpoint[8] = 2;
        if (!RosterCheckpoint.decode(checkpoint).version().equals(new Counter64("9223372036854775809"))) throw new AssertionError("unsigned checkpoint");
        for (int command : new int[] {1,4,5}) {
            final int selected = command;
            rejected(ContinuityFailure.class, () -> Native.credentialCommand(0, selected, new byte[0][], 0));
        }
        for (int command : new int[] {3,6,7,8}) {
            final int selected = command;
            rejected(ContinuityFailure.class, () -> Native.credentialCommand(0, selected, new byte[][] {new byte[32], new byte[32]}, 0));
        }
        if (new CredentialRenewalStatus(new byte[116]).phase() != CredentialRenewalStatus.Phase.ABSENT)
            throw new AssertionError("absent status");
        rejected(IllegalStateException.class, () -> new CredentialRenewalStatus(new byte[120]));
        byte[] pending = new byte[116]; pending[3] = 1; pending[4] = 1; pending[36] = 2;
        if (new CredentialRenewalStatus(pending).checkpoint() != null) throw new AssertionError("pending checkpoint");
        byte[] contaminated = pending.clone(); contaminated[75] = 1;
        rejected(IllegalStateException.class, () -> new CredentialRenewalStatus(contaminated));
        byte[] committed = pending.clone(); committed[3] = 2; committed[75] = 2; committed[76] = 3;
        CredentialRenewalStatus terminal = new CredentialRenewalStatus(committed);
        if (!terminal.checkpoint().version().equals(new Counter64("2"))) throw new AssertionError("status counter");
        byte[] expired = committed.clone(); expired[3] = 3;
        rejected(IllegalStateException.class, () -> new CredentialRenewalStatus(expired));
        expired[115] = 4;
        if (!new CredentialRenewalStatus(expired).observedAt().equals(new Counter64("4"))) throw new AssertionError("observed clock");
        committed[115] = 1;
        rejected(IllegalStateException.class, () -> new CredentialRenewalStatus(committed));
        rejected(IllegalStateException.class, () -> new CredentialRenewalProposal(new byte[296]));
        rejected(IllegalStateException.class, () -> new CredentialRenewalCancellation(new byte[248]));
    }
}
