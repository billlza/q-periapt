// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Framing and actual JNI refusal controls, not a lifecycle qualification. */
public final class PendingWriteBridgeProbe {
    private PendingWriteBridgeProbe() { }
    private static void rejected(Class<? extends Throwable> expected, Runnable action) {
        try { action.run(); }
        catch (Throwable failure) {
            if (expected.isInstance(failure)) return;
            throw new AssertionError("unexpected pending write failure", failure);
        }
        throw new AssertionError("invalid pending write input admitted");
    }
    private static byte[] framed() {
        byte[] wire = new byte[436 + 569 + 1]; ByteBuffer out = ByteBuffer.wrap(wire);
        out.putInt(569).putInt(1); out.put("QPWRPL01".getBytes(StandardCharsets.US_ASCII));
        Arrays.fill(wire, 16, 401, (byte)7); Arrays.fill(wire, 404, 436, (byte)2);
        out.position(436); out.put("QPWRMD01".getBytes(StandardCharsets.US_ASCII));
        out.put(wire, 16, 353).putLong(96).put(new byte[96]).putLong(96).put(new byte[96]).put((byte)1);
        return wire;
    }
    public static void main(String[] ignored) {
        run();
        System.out.println("pending-write:bridge:passed");
    }
    static void run() {
        byte[] original = framed(); PendingWriteRecoveryRequest request = new PendingWriteRecoveryRequest(original);
        Arrays.fill(original, (byte)0); Arrays.fill(request.metadata(), (byte)0);
        if (request.proposal()[8] != 7 || request.metadata()[8] != 7 || request.metadata().length != 569)
            throw new AssertionError("pending request borrowed mutable source");
        for (int offset : new int[] {0,4,8,401,402,403,436,444,797}) {
            byte[] broken = framed(); broken[offset] ^= 1;
            rejected(IllegalStateException.class, () -> new PendingWriteRecoveryRequest(broken));
        }
        byte[] extended = Arrays.copyOf(framed(), framed().length + 1);
        rejected(IllegalStateException.class, () -> new PendingWriteRecoveryRequest(extended));
        byte[] overflow = framed(); ByteBuffer.wrap(overflow).putLong(797, -1);
        rejected(IllegalStateException.class, () -> new PendingWriteRecoveryRequest(overflow));
        for (int i = 0; i < 32; ++i) {
            rejected(NullPointerException.class, () -> Native.pendingWriteCommand(0, 1, null));
            rejected(IllegalArgumentException.class, () -> Native.pendingWriteCommand(0, 1, new byte[1][]));
            rejected(IllegalArgumentException.class, () -> Native.pendingWriteCommand(0, 3, new byte[0][]));
            rejected(ContinuityFailure.class, () -> Native.pendingWriteCommand(0, 1, new byte[0][]));
            rejected(IllegalArgumentException.class, () -> Native.pendingWriteCommand(0, 2,
                new byte[][] {new byte[392], new byte[1]}));
        }
        rejected(IllegalArgumentException.class, () -> Native.pendingWriteCommand(0, 2,
            new byte[][] {new byte[393], new byte[8388609]}));
    }
}
