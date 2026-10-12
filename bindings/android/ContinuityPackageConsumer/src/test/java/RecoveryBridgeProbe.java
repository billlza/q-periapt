// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Synthetic record validation and real native owner/input refusals. */
final class RecoveryBridgeProbe {
    private RecoveryBridgeProbe() { }
    private static byte[] id(int value) { byte[] out=new byte[32];Arrays.fill(out,(byte)value);return out; }
    private static void require(boolean value,String message) { if(!value) throw new AssertionError(message); }
    private static void rejected(Class<? extends Throwable> type,Runnable action) {
        try { action.run(); } catch(Throwable failure) {
            if(type.isInstance(failure)) return;throw new AssertionError("unexpected recovery exception",failure);
        }
        throw new AssertionError("invalid recovery input admitted");
    }
    private static void failed(int expected,Runnable action) {
        try { action.run(); } catch(ContinuityFailure failure) {
            require(failure.code()==expected,"unexpected native recovery code "+failure.code());return;
        }
        throw new AssertionError("native recovery failure became success");
    }
    private static byte[] reconciliation() {
        ByteBuffer out=ByteBuffer.allocate(2856);out.put(id(1)).putInt(2).putInt(0);
        for(int i=0;i<2;i++) out.put(Arrays.copyOf(id(i+2),16)).put(id(i+4)).put(id(i+6)).putInt(i==0 ? 2 : 4).putInt(0);
        return out.array();
    }
    static void run() {
        byte[] wire=reconciliation();AccountRecoveryRecords.Reconciliation result=new AccountRecoveryRecords.Reconciliation(wire);
        require(result.members().size()==2 && result.members().get(1).state()==AccountRecoveryRecords.MemberState.DELIVERY_UNKNOWN,"unknown outcome lost");
        wire[0]=9;require(result.operation().encoded()[0]==1,"operation aliased");
        byte[] device=result.members().get(0).device();device[0]=9;require(result.members().get(0).device()[0]==2,"device alias");
        rejected(UnsupportedOperationException.class,() -> result.members().clear());
        for(int offset:new int[] {36,124,216}) {
            byte[] invalid=reconciliation();invalid[offset]=1;
            rejected(IllegalStateException.class,() -> new AccountRecoveryRecords.Reconciliation(invalid));
        }
        byte[] unordered=reconciliation();System.arraycopy(unordered,40,unordered,128,16);
        rejected(IllegalStateException.class,() -> new AccountRecoveryRecords.Reconciliation(unordered));
        for(int state:new int[] {0,7,257,Integer.MIN_VALUE}) {
            byte[] invalid=reconciliation();ByteBuffer.wrap(invalid).putInt(120,state);
            rejected(IllegalStateException.class,() -> new AccountRecoveryRecords.Reconciliation(invalid));
        }
        byte[] epoch=new byte[104];ByteBuffer.wrap(epoch).putLong(0,Long.MIN_VALUE).putLong(8,Long.MIN_VALUE+1);
        require(new ClosureRecords.Epoch(epoch).epoch().toString().equals("9223372036854775808"),"unsigned epoch lost");
        byte[] inconsistent=epoch.clone();ByteBuffer.wrap(inconsistent).putLong(40,1);
        rejected(IllegalStateException.class,() -> new ClosureRecords.Epoch(inconsistent));
        for(int phase:new int[] {0,1,2}) {
            byte[] status=new byte[36];ByteBuffer.wrap(status).putInt(phase);
            if(phase!=0) System.arraycopy(id(1),0,status,4,32);
            require(new ClosureRecords.Status(status).phase().ordinal()==phase,"session phase changed");
        }
        byte[] truncatedPhase=new byte[36];ByteBuffer.wrap(truncatedPhase).putInt(257);System.arraycopy(id(1),0,truncatedPhase,4,32);
        rejected(IllegalStateException.class,() -> new ClosureRecords.Status(truncatedPhase));
        rejected(IllegalStateException.class,() -> AccountRecoveryRecords.status(truncatedPhase));
        for(int repeat=0;repeat<64;repeat++) {
            rejected(IllegalArgumentException.class,() -> Native.prepareRecovery(new byte[0][],3,0));
            rejected(IllegalArgumentException.class,() -> Native.prepareRecovery(new byte[0][],1,0));
            rejected(NullPointerException.class,() -> Native.prepareRecovery(null,0,0));
            rejected(IllegalArgumentException.class,() -> Native.prepareRecovery(new byte[][] {id(1),id(2)},0,0));
            rejected(IllegalArgumentException.class,() -> Native.recoveryCommand(0,0,new byte[0][],0,0,0));
            rejected(IllegalArgumentException.class,() -> Native.recoveryCommand(0,1,new byte[][] {id(1)},1,0,0));
            rejected(IllegalArgumentException.class,() -> Native.recoveryCommand(0,2,new byte[0][],0,0,1));
            rejected(IllegalArgumentException.class,() -> Native.recoveryCommand(0,5,new byte[0][],-1,0,0));
            rejected(IllegalArgumentException.class,() -> Native.recoveryCommand(0,7,new byte[0][],0,-1,0));
            rejected(IllegalArgumentException.class,() -> Native.recoveryCommand(0,23,new byte[][] {new byte[361]},0,0,0));
            failed(2,() -> Native.recoveryCommand(0,20,new byte[0][],0,0,0));
            try(ContinuityRecovery owner=ContinuityRecovery.prepare("/unused-recovery-boundary",RecoveryWitness.local())) {
                failed(6,owner::sessionCount);owner.cancel();failed(302,owner::finishOpen);
            }
        }
    }
}
