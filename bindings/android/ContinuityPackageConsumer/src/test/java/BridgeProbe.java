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
        }
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
        System.out.println("configuration:bridge:passed");
    }
}
