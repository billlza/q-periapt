// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Remote roster admission preserves the original pending message and next slot. */
public final class RosterPeerProbe {
    private RosterPeerProbe() { }
    static void run(ContinuityDevice device, Path inputs, String mode, Path output) throws Exception {
        boolean revoked=mode.equals("peer-roster-revoke")||mode.equals("peer-roster-revoked-reopen");
        String prefix=revoked?"remote-roster-revoked":"remote-roster";
        Path peerInputs=inputs.resolve("peer");
        byte[] digest=read(inputs,prefix+"-digest"),roster=read(inputs,prefix);
        int refused=mode.equals("peer-roster-bad")?102:mode.equals("peer-roster-checkpoint")?105:mode.equals("peer-roster-cancelled")?302:0;
        if(refused==102)roster[roster.length-1]^=1;
        if(refused==105)digest[0]^=1;
        AccountPin pin=new AccountPin(read(peerInputs,"responder-account"),read(peerInputs,"responder-root"),read(inputs,"family"),
            counter(ByteBuffer.wrap(read(inputs,prefix+"-version"))),digest);
        if(refused!=0) {
            if(refused==302)device.cancel();
            failed(refused,()->device.admitPeerRoster(roster,pin));
            publish(output,ByteBuffer.allocate(4).putInt(refused).array());return;
        }
        Ids.Session session=new Ids.Session(read(inputs,"connection-session"));
        Ids.Message message=new Ids.Message(read(inputs,"connection-message"));
        PeerConfiguration configuration=PeerProbe.configuration(peerInputs);
        if(revoked) {
            RosterCheckpoint removed;
            if(mode.equals("peer-roster-revoke")) {
                try(ContinuityPeer retained=PeerRenewalProbe.peer(device,configuration,session)) {
                    require(retained.messageStatus(session,message)==ContinuityPeer.MessageStatus.ACKNOWLEDGED,"original acknowledgment changed");
                    Ids.Message denied=retained.nextMessage(session);
                    removed=device.admitPeerRoster(roster,pin);
                    failed(103,()->retained.send("127.0.0.1:1",session,denied,new byte[]{1},new byte[0]));
                }
            } else removed=device.admitPeerRoster(roster,pin);
            require(device.admitPeerRoster(roster,pin).equals(removed),"revocation exact replay");
            failed(103,()->{try(ContinuityPeer current=PeerRenewalProbe.peer(device,configuration,session)){require(current!=null,"peer owner");}});
            publish(output,PeerRenewalProbe.checkpoint(removed));return;
        }
        RosterCheckpoint accepted;byte[] next;
        if(mode.equals("peer-roster-admit")) {
            try(ContinuityPeer stale=PeerRenewalProbe.peer(device,configuration,session)) {
                require(stale.messageStatus(session,message)==ContinuityPeer.MessageStatus.COMMITTED,"original pending message");
                next=stale.nextMessage(session).encoded();
                accepted=device.admitPeerRoster(roster,pin);
                require(Arrays.equals(stale.nextMessage(session).encoded(),next),"same-member roster changed the next slot");
            }
            require(device.admitPeerRoster(roster,pin).equals(accepted),"remote roster exact replay");
        } else if(mode.equals("peer-roster-reopen")) {
            accepted=device.admitPeerRoster(roster,pin);next=read(inputs,"remote-roster-next");
        } else throw new IllegalArgumentException("remote roster operation");
        try(ContinuityPeer current=PeerRenewalProbe.peer(device,configuration,session)) {
            require(Arrays.equals(current.nextMessage(session).encoded(),next),"stale child or restart changed next slot");
            require(current.messageStatus(session,message)==ContinuityPeer.MessageStatus.COMMITTED,"roster admission lost original pending message");
        }
        publish(output,ByteBuffer.allocate(72).put(PeerRenewalProbe.checkpoint(accepted)).put(next).array());
    }
}
