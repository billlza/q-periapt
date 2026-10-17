// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Explicit noncommit keeps suspension; cancelling a controller differs from closing it. */
final class RootControls {
    private RootControls() { }
    private static byte[] code(int value) { return ByteBuffer.allocate(4).putInt(value).array(); }
    static boolean apply(ContinuityAccountAuthority root,Path inputs,Path installation,Path output,
            String profile,String mode,ConfigurationWitness witness,RootOwnedProbe.CutObserver observer) throws Exception {
        switch(mode) {
            case "root-cancel-preparing":
                require(root.rootReplacementState()==RootReplacementState.PREPARING,"preparation before cancellation");
                root.cancel();failed(302,root::rootReplacementState);publish(output,code(302));return true;
            case "root-noncommit-bad": {
                byte[] bad=read(inputs,"root-noncommit");bad[bad.length-1]^=1;
                failed(102,()->root.retainRootNoncommit(bad));
                require(root.rootReplacementState()==RootReplacementState.PREPARING,"invalid noncommit changed preparation");
                publish(output,code(102));return true;
            }
            case "root-noncommit-unknown":
                require(root.retainRootNoncommit(read(inputs,"root-noncommit"))==RootReplacementState.CLOSED,"noncommit terminal");
                RootOwnedProbe.cut(output,code(4),observer);return true;
            case "root-noncommit-replay": {
                require(root.rootReplacementState()==RootReplacementState.CLOSED,"original closed state lost");
                require(root.retainRootNoncommit(read(inputs,"root-noncommit"))==RootReplacementState.CLOSED,"same noncommit changed");
                byte[] freeze=read(inputs,"root-freeze");failed(112,()->root.bindRootFreeze(freeze));
                require(root.rootReplacementState()==RootReplacementState.CLOSED,"closed plan resumed authority");
                publish(output,code(4));return true;
            }
            case "root-cancel-successor":
                RootOwnedProbe.withTarget(root,inputs,installation,profile,witness,device->{
                    Path target=inputs.resolve("root-target");Ids.Session session=new Ids.Session(read(target,"connection-session"));
                    Ids.Message message=new Ids.Message(read(target,"connection-message"));
                    try(ContinuityPeer peer=device.preparePeerReopen(PeerProbe.configuration(target.resolve("peer")),
                            PeerConfiguration.Quality.ONE_TIME_BOTH,PeerConfiguration.Role.INITIATOR,session)) {
                        peer.finishOpen();root.cancel();failed(302,root::rootReplacementState);
                        require(peer.messageStatus(session,message)==ContinuityPeer.MessageStatus.ACKNOWLEDGED,"cancel revoked live successor");
                        publish(output,code(302));
                    }
                });return true;
            default:return false;
        }
    }
}
