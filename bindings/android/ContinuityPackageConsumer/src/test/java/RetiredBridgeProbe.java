// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Synthetic result framing plus real JNI rejection. No retirement lifecycle claim. */
public final class RetiredBridgeProbe {
    private RetiredBridgeProbe() { }
    private static void require(boolean value, String text) { if (!value) throw new AssertionError(text); }
    private static void rejected(Class<? extends Throwable> expected, Runnable action) {
        try { action.run(); }
        catch (Throwable failure) {
            if (expected.isInstance(failure)) return;
            throw new AssertionError("unexpected retirement boundary result", failure);
        }
        throw new AssertionError("invalid retirement input admitted");
    }
    private static byte[] inventory() {
        byte[] bytes = new byte[313]; System.arraycopy("QPRCLP01".getBytes(StandardCharsets.US_ASCII), 0, bytes, 0, 8); return bytes;
    }
    private static byte[] proposal() {
        ByteBuffer out = ByteBuffer.allocate(360); out.putInt(1).put("QPRRPT01".getBytes(StandardCharsets.US_ASCII));
        out.put(inventory()); out.put(325, (byte)1); return out.array();
    }
    private static byte[] report() {
        ByteBuffer out = ByteBuffer.allocate(48 + 323); out.putLong(323).putInt(1).putInt(0);
        out.put(16, (byte)1); out.position(48); out.put("QPRDMD01".getBytes(StandardCharsets.US_ASCII)); return out.array();
    }
    public static void main(String[] ignored) {
        run();
        System.out.println("retirement:bridge:passed");
    }
    static void run() {
        byte[] bytes = inventory(); RetiredInventory value = new RetiredInventory(bytes);
        bytes[0] = 0; require(value.encoded()[0] == 'Q', "inventory borrowed caller storage");
        byte[] exposed = value.encoded(); exposed[0] = 0; require(value.encoded()[0] == 'Q', "inventory exposed mutable storage");
        require(RetiredReportProposal.decode(new byte[360], false) == null, "local proposal absence changed");
        rejected(IllegalStateException.class, () -> RetiredReportProposal.decode(new byte[360], true));
        RetiredReportProposal prepared = RetiredReportProposal.decode(proposal(), true);
        require(prepared.inventory().encoded().length == 313 && prepared.report().encoded()[0] == 1, "proposal framing changed");
        for (int offset : new int[] {3,4,12,357,358,359}) {
            byte[] malformed = proposal(); malformed[offset] ^= 2;
            rejected(IllegalStateException.class, () -> RetiredReportProposal.decode(malformed, false));
        }
        byte[] absentWithPayload = new byte[360]; absentWithPayload[100] = 1;
        rejected(IllegalStateException.class, () -> RetiredReportProposal.decode(absentWithPayload, false));
        byte[] zeroId = proposal(); Arrays.fill(zeroId, 325, 357, (byte)0);
        rejected(IllegalStateException.class, () -> RetiredReportProposal.decode(zeroId, true));
        byte[] full = report(); RetiredDeviceReport parsed = new RetiredDeviceReport(full); full[48] = 0;
        require(parsed.canonicalBytes()[0] == 'Q' && parsed.viewCount() == 1, "report borrowed source storage");
        for (int offset : new int[] {0,8,12,48}) {
            byte[] malformed = report(); malformed[offset] ^= 1;
            rejected(IllegalStateException.class, () -> new RetiredDeviceReport(malformed));
        }
        byte[] emptyId = report(); emptyId[16] = 0;
        rejected(IllegalStateException.class, () -> new RetiredDeviceReport(emptyId));
        require(RetiredErasureState.decode(new byte[4]) == RetiredErasureState.RETAINED, "retained state changed");
        require(RetiredErasureState.decode(new byte[] {0,0,0,1}) == RetiredErasureState.ERASED, "erased state changed");
        rejected(IllegalStateException.class, () -> RetiredErasureState.decode(new byte[] {0,0,0,2}));
        for (int repeat = 0; repeat < 128; ++repeat) {
            rejected(NullPointerException.class, () -> Native.prepareRetired(null, null));
            rejected(IllegalArgumentException.class, () -> Native.prepareRetired(new byte[9][], new long[2]));
            rejected(IllegalArgumentException.class, () -> Native.prepareRetired(new byte[8][], new long[3]));
            for (int operation = 1; operation <= 11; ++operation) {
                final int selected = operation;
                rejected(NullPointerException.class, () -> Native.retiredCommand(0, selected, null));
                rejected(IllegalArgumentException.class, () -> Native.retiredCommand(0, selected, new byte[4][]));
            }
            rejected(IllegalArgumentException.class, () -> Native.retiredCommand(0, 12, new byte[0][]));
            rejected(ContinuityFailure.class, () -> Native.retiredCommand(0, Native.RETIRED_INVENTORY, new byte[0][]));
        }
        rejected(IllegalArgumentException.class, () -> Native.retiredCommand(0, Native.RETIRED_PREPARE_REPORT, new byte[][] {new byte[3689]}));
        rejected(IllegalArgumentException.class, () -> Native.retiredCommand(0, Native.RETIRED_PREPARE_ACK,
            new byte[][] {new byte[3690], new byte[3730], new byte[8388609]}));
        rejected(IllegalArgumentException.class, () -> new RetiredEnrollmentAuthority(new byte[32], new byte[1985], new byte[57795], new byte[96], new byte[3754]));
    }
}
