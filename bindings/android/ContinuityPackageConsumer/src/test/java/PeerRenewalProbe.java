// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Remote grant admission retains the original session/outbox and rejects stale children. */
public final class PeerRenewalProbe {
    private PeerRenewalProbe() { }
    private static final byte[] BODY = "persisted before process exit".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AD = "configuration-v1".getBytes(StandardCharsets.UTF_8);
    static byte[] checkpoint(RosterCheckpoint value) {
        return ByteBuffer.allocate(40).putLong(Long.parseUnsignedLong(value.version().toString())).put(value.digest()).array();
    }
    static ContinuityPeer peer(ContinuityDevice device, PeerConfiguration configuration, Ids.Session session) {
        ContinuityPeer peer = device.preparePeerReopen(configuration, PeerConfiguration.Quality.ONE_TIME_BOTH, PeerConfiguration.Role.INITIATOR, session);
        try { peer.finishOpen(); return peer; }
        catch (Throwable failure) {
            try { peer.close(); } catch (Throwable cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }
    static void run(ContinuityDevice device, Path inputs, String mode, Path output) throws Exception {
        Ids.Session session = new Ids.Session(read(inputs,"connection-session"));
        Ids.Message preceding = new Ids.Message(read(inputs,"connection-message"));
        PeerConfiguration configuration = PeerProbe.configuration(inputs.resolve("peer"));
        if (mode.equals("credential-remote-uncertain") || mode.equals("credential-remote-retry")) {
            try (ContinuityPeer peer = peer(device,configuration,session)) {
                require(peer.messageStatus(session,preceding) == ContinuityPeer.MessageStatus.ACKNOWLEDGED,"preceding message changed");
                boolean uncertain = mode.equals("credential-remote-uncertain");
                Ids.Message message = uncertain ? peer.nextMessage(session) : new Ids.Message(read(inputs,"remote-message"));
                String address = new String(read(inputs,"connection-address"),StandardCharsets.US_ASCII);
                if (uncertain) {
                    try { peer.send(address,session,message,BODY,AD); throw new AssertionError("crashed receiver acknowledged"); }
                    catch (ContinuityFailure failure) { require(failure.code()==309 || failure.code()==310 || failure.code()==311 || failure.code()==303,"unexpected network failure"); }
                    require(peer.messageStatus(session,message)==ContinuityPeer.MessageStatus.COMMITTED,"original remote-renewal send not committed");
                } else {
                    require(peer.messageStatus(session,message)==ContinuityPeer.MessageStatus.COMMITTED,"pending remote-renewal message lost");
                    require(peer.send(address,session,message,BODY,AD).consumption()==ContinuityPeer.Consumption.CONFIRMED,"remote-renewal consumption");
                    require(peer.messageStatus(session,message)==ContinuityPeer.MessageStatus.ACKNOWLEDGED,"remote-renewal acknowledgment");
                }
                publish(output,ByteBuffer.allocate(64).put(session.encoded()).put(message.encoded()).array());
            }
            return;
        }
        if (mode.equals("credential-remote-self-refused")) {
            AccountPin local = new AccountPin(read(inputs,"trusted-account"),read(inputs,"enrollment-root"),read(inputs,"family"),
                counter(ByteBuffer.wrap(read(inputs,"renewal-version"))),read(inputs,"renewal-digest"));
            byte[] localGrant=read(inputs,"credential-renewal");
            Ids.CredentialRenewal localOperation=new Ids.CredentialRenewal(read(inputs,"credential-operation"));
            failed(211,()->device.admitPeerCredentialRenewal(localGrant,local,localOperation));
            publish(output,ByteBuffer.allocate(4).putInt(211).array()); return;
        }
        Path original = inputs.resolve("peer");
        AccountPin pin = new AccountPin(read(original,"responder-account"),read(original,"responder-root"),read(inputs,"family"),
            counter(ByteBuffer.wrap(read(inputs,"remote-version"))),read(inputs,"remote-digest"));
        byte[] grant=read(inputs,"remote-grant"); Ids.CredentialRenewal operation=new Ids.CredentialRenewal(read(inputs,"remote-operation"));
        Ids.Message message=new Ids.Message(read(inputs,"remote-message"));
        if (mode.equals("credential-remote-admit")) {
            byte[] badDigest=read(inputs,"remote-digest");badDigest[0]^=1;
            AccountPin wrong=new AccountPin(read(original,"responder-account"),read(original,"responder-root"),read(inputs,"family"),
                counter(ByteBuffer.wrap(read(inputs,"remote-version"))),badDigest);
            failed(105,()->device.admitPeerCredentialRenewal(grant,wrong,operation));
            byte[] badOperation=operation.encoded();badOperation[0]^=1;
            failed(211,()->device.admitPeerCredentialRenewal(grant,pin,new Ids.CredentialRenewal(badOperation)));
            byte[] next;
            RosterCheckpoint accepted;
            try (ContinuityPeer stale=peer(device,configuration,session)) {
                require(stale.messageStatus(session,message)==ContinuityPeer.MessageStatus.COMMITTED,"original pending status");
                next=stale.nextMessage(session).encoded();
                accepted=device.admitPeerCredentialRenewal(grant,pin,operation);
                failed(211,()->stale.nextMessage(session));
            }
            require(device.admitPeerCredentialRenewal(grant,pin,operation).equals(accepted),"remote grant exact replay");
            try (ContinuityPeer current=peer(device,configuration,session)) {
                require(Arrays.equals(current.nextMessage(session).encoded(),next),"stale child advanced the next slot");
                require(current.messageStatus(session,message)==ContinuityPeer.MessageStatus.COMMITTED,"grant lost original pending message");
            }
            publish(output,ByteBuffer.allocate(72).put(checkpoint(accepted)).put(next).array());
        } else if (mode.equals("credential-remote-reopen")) {
            RosterCheckpoint accepted=device.admitPeerCredentialRenewal(grant,pin,operation);
            try (ContinuityPeer current=peer(device,configuration,session)) {
                byte[] next=current.nextMessage(session).encoded();require(Arrays.equals(next,read(inputs,"remote-next")),"restart changed next slot");
                require(current.messageStatus(session,message)==ContinuityPeer.MessageStatus.COMMITTED,"restart lost original pending message");
                require(current.messageStatus(session,preceding)==ContinuityPeer.MessageStatus.ACKNOWLEDGED,"restart lost preceding acknowledgment");
                publish(output,ByteBuffer.allocate(72).put(checkpoint(accepted)).put(next).array());
            }
        } else throw new IllegalArgumentException("remote credential operation");
    }
}
