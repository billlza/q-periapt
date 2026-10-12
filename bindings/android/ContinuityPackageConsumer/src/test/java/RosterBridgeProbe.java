// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Synthetic framing checks and actual JNI rejection; no lifecycle/security claim. */
final class RosterBridgeProbe {
    private RosterBridgeProbe() { }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static byte[] id(int value) { byte[] bytes = new byte[32]; Arrays.fill(bytes, (byte)value); return bytes; }
    private static void rejected(Class<? extends Throwable> type, Runnable action) {
        try { action.run(); }
        catch (Throwable failure) {
            if (type.isInstance(failure)) return;
            throw new AssertionError("unexpected roster rejection", failure);
        }
        throw new AssertionError("roster input admitted");
    }
    private static void code(int expected, Runnable action) {
        try { action.run(); }
        catch (ContinuityFailure failure) {
            if (failure.code() == expected) return;
            throw new AssertionError("native roster status changed", failure);
        }
        throw new AssertionError("native roster failure became success");
    }
    private static byte[] proposal() {
        ByteBuffer b = ByteBuffer.allocate(417); b.put("QPRWNP01".getBytes(StandardCharsets.US_ASCII));
        for (int offset : new int[] {8,40,72,104,136,176,216,337,385}) { b.position(offset); b.put(id(offset % 251 + 1)); }
        b.putLong(168,1); b.putLong(208,2); b.putLong(248,1);
        b.position(256); b.put(Arrays.copyOfRange(b.array(),104,136));
        b.putLong(321,3); b.putLong(329,4); b.putLong(369,3); b.putLong(377,5);
        return b.array();
    }
    private static byte[] progress(int phase) {
        byte[] proposal = proposal(); ByteBuffer b = ByteBuffer.allocate(624); b.putInt(phase);
        if (phase == 0) return b.array();
        b.position(8); b.put(proposal,136,152); b.put(proposal,289,32); b.putInt(proposal[288]); b.putInt(0);
        if (phase >= 2 && phase <= 4) b.put(proposal);
        return b.array();
    }
    private static byte[] resolution(int outcome) {
        ByteBuffer b = ByteBuffer.allocate(168); b.putInt(outcome).putInt(0).put(id(1));
        b.putLong(1).put(id(2)).putLong(2).put(id(3));
        b.putLong(outcome==2 ? 1 : outcome==4 ? 3 : 2).put(id(outcome==2 ? 2 : outcome==3 || outcome==4 ? 4 : 3));
        b.putLong(Long.MIN_VALUE); return b.array();
    }
    private static byte[][] pin() { return new byte[][] {id(1),new byte[1985],id(2),ByteBuffer.allocate(8).putLong(1).array(),id(3)}; }
    static void run() {
        byte[] original = proposal(); RosterRefreshProposal parsed = new RosterRefreshProposal(original);
        original[0] ^= 1; require(parsed.encoded()[0]=='Q',"proposal aliased caller bytes");
        byte[] exposed = parsed.encoded(); exposed[0] ^= 1; require(parsed.encoded()[0]=='Q',"proposal leaked mutable bytes");
        for (int offset : new int[] {0,288,321,377}) {
            byte[] invalid=proposal(); invalid[offset]^=2;
            rejected(IllegalArgumentException.class,()->new RosterRefreshProposal(invalid));
        }
        byte[] higher=proposal(); ByteBuffer b=ByteBuffer.wrap(higher); b.putLong(168,Long.MIN_VALUE);b.putLong(208,Long.MIN_VALUE+1);
        require(new RosterRefreshProposal(higher).scope().previous().version().toString().equals("9223372036854775808"),"unsigned roster counter lost");
        for (int phase=0;phase<=5;phase++) {
            RosterRefreshProgress value=new RosterRefreshProgress(progress(phase));
            require(value.phase().ordinal()==phase,"roster phase changed");
            require((value.scope()==null)==(phase==0),"roster scope presence changed");
            require((value.proposal()!=null)==(phase>=2&&phase<=4),"roster proposal presence changed");
        }
        for(int phase:new int[]{0,1,2,5}) {
            byte[] invalid=progress(phase);ByteBuffer.wrap(invalid).putInt(4,1);
            rejected(IllegalStateException.class,()->new RosterRefreshProgress(invalid));
        }
        byte[] mismatch=progress(3);mismatch[8]^=1;
        rejected(IllegalStateException.class,()->new RosterRefreshProgress(mismatch));
        byte[] tail=progress(4);tail[623]=1;
        rejected(IllegalStateException.class,()->new RosterRefreshProgress(tail));
        byte[] absent=new byte[424];require(RosterRefreshProposal.preparation(absent)==null,"absent roster preparation changed");
        byte[] preparation=new byte[424];ByteBuffer.wrap(preparation).putInt(1).put(proposal());
        require(RosterRefreshProposal.preparation(preparation).scope().equals(parsed.scope()),"retained roster scope changed");
        preparation[423]=1;rejected(IllegalStateException.class,()->RosterRefreshProposal.preparation(preparation));
        for(int outcome=1;outcome<=4;outcome++) {
            RosterRefreshResolution result=new RosterRefreshResolution(resolution(outcome));
            require(result.outcome().ordinal()==outcome-1,"resolution outcome changed");
            require(result.observedAt().toString().equals("9223372036854775808"),"unsigned resolution time lost");
        }
        byte[] contradiction=resolution(1);ByteBuffer.wrap(contradiction).putInt(3);
        rejected(IllegalStateException.class,()->new RosterRefreshResolution(contradiction));
        for(int repeat=0;repeat<64;repeat++) {
            for(int command=1;command<=11;command++) {
                final int selected=command;
                rejected(NullPointerException.class,()->Native.rosterCommand(0,selected,null));
                rejected(IllegalArgumentException.class,()->Native.rosterCommand(0,selected,new byte[11][]));
            }
            rejected(IllegalArgumentException.class,()->Native.rosterCommand(0,0,new byte[0][]));
            code(2,()->Native.rosterCommand(0,Native.ROSTER_PREPARATION,new byte[0][]));
            code(2,()->Native.rosterCommand(0,Native.ROSTER_PROGRESS,new byte[0][]));
        }
        byte[][] invalid=PolicyCodec.join(new byte[][]{id(1),ByteBuffer.allocate(4).putInt(2).array(),new byte[1],new byte[1]},pin());
        rejected(IllegalArgumentException.class,()->Native.rosterCommand(0,Native.ROSTER_PREPARE,invalid));
        byte[][] invalidLocal=PolicyCodec.join(new byte[][]{new byte[40],ByteBuffer.allocate(4).putInt(2).array(),new byte[1]},pin());
        rejected(IllegalArgumentException.class,()->Native.rosterCommand(0,Native.ROSTER_REFRESH_WITH_POLICY,invalidLocal));
        byte[][] oversized=PolicyCodec.join(new byte[][]{new byte[65537]},pin());
        rejected(IllegalArgumentException.class,()->Native.rosterCommand(0,Native.ROSTER_ADMIT_PEER,oversized));
    }
}
