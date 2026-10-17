// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Wire-contract checks and real JNI refusals; no aggregate delivery claim. */
final class AccountBridgeProbe {
    private AccountBridgeProbe() { }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static byte[] id(int value) { byte[] bytes = new byte[32]; Arrays.fill(bytes, (byte)value); return bytes; }
    private static void rejected(Class<? extends Throwable> type, Runnable action) {
        try { action.run(); }
        catch (Throwable failure) {
            if (type.isInstance(failure)) return;
            throw new AssertionError("unexpected account rejection", failure);
        }
        throw new AssertionError("invalid account input admitted");
    }
    private static void closed(Runnable action) {
        try { action.run(); }
        catch (ContinuityFailure failure) {
            require(failure.code() == 2, "native closed status changed"); return;
        }
        throw new AssertionError("closed owner returned success");
    }
    private static byte[] delivery(int outcome, int exchanges) {
        ByteBuffer b = ByteBuffer.allocate(88);
        b.put(Arrays.copyOf(id(1),16)).put(id(2)).put(id(3)).putInt(outcome).putInt(exchanges);
        return b.array();
    }
    private static byte[][] fields(int count) {
        return new byte[][] {id(1),id(2),new byte[] {'a'},new byte[0],new byte[0],new byte[count * 32]};
    }
    static void run() {
        Ids.Session session = new Ids.Session(id(2));
        for (int phase = 0; phase <= 5; phase++) {
            byte[] wire = new byte[33]; wire[0] = (byte)phase;
            boolean report = phase == 3 || phase == 4;
            if (report) System.arraycopy(id(7),0,wire,1,32);
            AccountStatus status = new AccountStatus(wire);
            require(status.phase().ordinal() == phase && (status.report() != null) == report, "account status");
            wire[1] ^= 1;
            if (report) require(Arrays.equals(status.report().encoded(),id(7)), "report aliases native buffer");
            byte[] invalid = new byte[33]; invalid[0] = (byte)phase;
            if (!report) invalid[1] = 1;
            rejected(IllegalStateException.class, () -> new AccountStatus(invalid));
        }
        for (byte[] wire : new byte[][] {null,new byte[32],new byte[34],new byte[] {6}})
            rejected(IllegalStateException.class, () -> new AccountStatus(wire));
        byte[] unknown = new byte[33]; unknown[0] = (byte)255;
        rejected(IllegalStateException.class, () -> new AccountStatus(unknown));
        for (int outcome = 1; outcome <= 6; outcome++) {
            byte[] wire = delivery(outcome,outcome == 2 ? 1 : 0);
            AccountDelivery parsed = new AccountDelivery(wire,session);
            require(parsed.outcome().ordinal() == outcome - 1, "account outcome");
            require(parsed.exchanges() == (outcome == 2 ? 1 : 0), "retained exchange count");
            wire[0] = 9; byte[] exposed = parsed.device(); exposed[0] = 8;
            require(parsed.device()[0] == 1, "device identity is mutable");
        }
        for (int outcome : new int[] {0,7,257,Integer.MIN_VALUE}) {
            byte[] invalid = delivery(outcome,1);
            rejected(IllegalStateException.class, () -> new AccountDelivery(invalid,session));
        }
        for (int count : new int[] {-1,9,257,Integer.MIN_VALUE}) {
            byte[] invalid = delivery(1,count);
            rejected(IllegalStateException.class, () -> new AccountDelivery(invalid,session));
        }
        rejected(IllegalStateException.class, () -> new AccountDelivery(delivery(2,0),session));
        rejected(IllegalStateException.class, () -> new AccountDelivery(delivery(1,1),new Ids.Session(id(4))));
        for (int[] region : new int[][] {{0,16},{16,48},{48,80}}) {
            byte[] invalid = delivery(1,1); Arrays.fill(invalid,region[0],region[1],(byte)0);
            rejected(IllegalStateException.class, () -> new AccountDelivery(invalid,session));
        }
        for (byte[] wire : new byte[][] {null,new byte[87],new byte[89]})
            rejected(IllegalStateException.class, () -> new AccountDelivery(wire,session));
        for (int repeat = 0; repeat < 64; repeat++) {
            rejected(IllegalArgumentException.class, () -> Native.accountCommand(0,0,new long[0],new byte[0][],0));
            rejected(IllegalArgumentException.class, () -> Native.accountCommand(0,4,new long[0],new byte[0][],0));
            rejected(NullPointerException.class, () -> Native.accountCommand(0,1,null,new byte[0][],0));
            rejected(NullPointerException.class, () -> Native.accountCommand(0,1,new long[0],null,0));
            for (int count : new int[] {0,33})
                rejected(IllegalArgumentException.class, () -> Native.accountCommand(0,3,new long[count],fields(count),0));
            for (int selected : new int[] {-1,2})
                rejected(IllegalArgumentException.class, () -> Native.accountCommand(0,3,new long[2],fields(2),selected));
            for (int command : new int[] {1,2}) {
                rejected(IllegalArgumentException.class, () -> Native.accountCommand(0,command,new long[1],new byte[0][],0));
                rejected(IllegalArgumentException.class, () -> Native.accountCommand(0,command,new long[0],new byte[0][],1));
            }
            for (int field = 0; field < 6; field++) {
                byte[][] absent = fields(2); absent[field] = null;
                rejected(NullPointerException.class, () -> Native.accountCommand(0,3,new long[2],absent,0));
                byte[][] oversized = fields(2); oversized[field] = new byte[new int[] {33,33,129,16385,1025,65}[field]];
                rejected(IllegalArgumentException.class, () -> Native.accountCommand(0,3,new long[2],oversized,0));
            }
            closed(() -> Native.accountCommand(0,1,new long[0],new byte[0][],0));
            closed(() -> Native.accountCommand(0,2,new long[0],new byte[][] {id(1)},0));
        }
    }
}
