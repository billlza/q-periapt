// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Typed public framing and real JNI boundary rejection; not root lifecycle qualification. */
public final class RootBridgeProbe {
    private RootBridgeProbe() { }
    private static void require(boolean value, String reason) { if (!value) throw new AssertionError(reason); }
    private static void rejected(Class<? extends Throwable> expected, Runnable action) {
        try { action.run(); }
        catch (Throwable failure) {
            if (expected.isInstance(failure)) return;
            throw new AssertionError("unexpected root boundary result", failure);
        }
        throw new AssertionError("invalid root boundary admitted");
    }
    private static byte[] tagged(String header, int length) {
        byte[] bytes = new byte[length]; System.arraycopy(header.getBytes(StandardCharsets.US_ASCII), 0, bytes, 0, 8); return bytes;
    }
    private static byte[] proposal() {
        return ByteBuffer.allocate(65540).putInt(8).put("QPARPL02".getBytes(StandardCharsets.US_ASCII)).array();
    }
    public static void main(String[] ignored) {
        run();
        System.out.println("root:bridge:passed");
    }
    static void run() {
        byte[] planBytes=tagged("QPAFPL01",32); RootReplacementPlan plan=new RootReplacementPlan(planBytes);
        Arrays.fill(planBytes,(byte)0); require(plan.encoded()[0]=='Q',"plan borrowed input");
        byte[] leaked=plan.encoded();leaked[0]=0;require(plan.encoded()[0]=='Q',"plan exposed mutable input");
        rejected(IllegalArgumentException.class,()->new RootReplacementPlan(new byte[7]));
        rejected(IllegalArgumentException.class,()->new RootReplacementPlan(tagged("QPARPL01",32)));
        rejected(IllegalArgumentException.class,()->new RootReplacementPlan(tagged("QPAFPL01",131073)));
        RootReplacementProposal proposed=RootReplacementProposal.fromNative(proposal());
        require(Arrays.equals(proposed.encoded(),tagged("QPARPL02",8)),"proposal framing");
        for(int offset:new int[]{0,4,65539}) {
            byte[] changed=proposal();changed[offset]^=1;
            rejected(IllegalStateException.class,()->RootReplacementProposal.fromNative(changed));
        }
        byte[] id=new byte[32];id[0]=1;
        AccountAuthorityCheckpoint checkpoint=new AccountAuthorityCheckpoint(new Ids.ApplicationAccount(id),new Counter64("1"),new Ids.Account(id));
        byte[] witness=id.clone(),publicKey=new byte[1985];publicKey[0]=1;
        RootReplacementScope scope=new RootReplacementScope(checkpoint,witness,publicKey);
        witness[0]=0;publicKey[0]=0;require(scope.witness()[0]==1&&scope.publicKey()[0]==1,"scope borrowed trust");
        byte[][] snapshot=scope.snapshot();snapshot[0][0]=0;require(scope.snapshot()[0][0]==1,"scope exposed checkpoint");
        rejected(IllegalArgumentException.class,()->new RootReplacementScope(checkpoint,new byte[32],new byte[1985]));
        byte[] noncommit=new byte[3449],freeze=new byte[]{1};
        RootReplacementTransition transition=new RootReplacementTransition(plan,plan,noncommit,freeze);
        freeze[0]=0;require(transition.snapshot()[3][0]==1,"transition borrowed receipt");
        RootReplacementAdoption adoption=new RootReplacementAdoption(plan,proposed,noncommit,noncommit);
        noncommit[0]=1;require(adoption.snapshot()[2][0]==0&&transition.snapshot()[2][0]==0,"noncommit borrowed receipt");
        for(int state=1;state<=4;++state)require(RootReplacementState.decode(ByteBuffer.allocate(4).putInt(state).array()).ordinal()==state-1,"root state");
        rejected(IllegalStateException.class,()->RootReplacementState.decode(new byte[4]));
        rejected(IllegalStateException.class,()->RootReplacementState.decode(new byte[]{0,0,0,5}));
        for(int repetition=0;repetition<128;++repetition) {
            for(int operation=1;operation<=11;++operation) {
                final int selected=operation;
                rejected(NullPointerException.class,()->Native.rootCommand(0,0,selected,null,null));
                rejected(IllegalArgumentException.class,()->Native.rootCommand(0,0,selected,new byte[12][],new long[2]));
            }
            rejected(IllegalArgumentException.class,()->Native.rootCommand(0,0,12,new byte[0][],new long[0]));
            rejected(IllegalArgumentException.class,()->Native.rootCommand(0,1,Native.ROOT_STATE,new byte[0][],new long[0]));
            rejected(ContinuityFailure.class,()->Native.rootCommand(0,0,Native.ROOT_STATE,new byte[0][],new long[0]));
            rejected(ContinuityFailure.class,()->Native.rootCommand(0,0,Native.ROOT_BIND_FREEZE,new byte[][]{new byte[1]},new long[0]));
        }
        rejected(IllegalArgumentException.class,()->Native.rootCommand(0,0,Native.ROOT_BIND_FREEZE,new byte[][]{new byte[131073]},new long[0]));
        rejected(IllegalArgumentException.class,()->Native.rootCommand(0,0,Native.ROOT_RESUME,new byte[8][],new long[0]));
    }
}
