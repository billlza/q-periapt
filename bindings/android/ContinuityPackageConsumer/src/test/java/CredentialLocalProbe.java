// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Local-only expiry is an explicit durable fact, not an implicit new grant. */
public final class CredentialLocalProbe {
    private CredentialLocalProbe() { }
    public static void main(String[] args) throws Exception {
        if(args.length!=5) throw new IllegalArgumentException("inputs installation profile mode result");
        Path inputs=Path.of(args[0]), installation=Path.of(args[1]), output=Path.of(args[4]);
        String profile=args[2], mode=args[3]; boolean recovery=profile.equals("recoverable");
        require(recovery || profile.equals("fixed"),"profile");
        try(ContinuityConfiguration configuration=configuration(inputs,installation,recovery,false)) {
            configuration.finishOpen();
            try(ContinuityEnrollment enrollment=configuration.resumeEnrollment(intent(inputs),null)) {
                if(mode.equals("credential-local-identity") || mode.equals("credential-local-active") || mode.equals("credential-local-send")) {
                    byte[] identity=CredentialProbe.identity(enrollment);
                    Ids.Session session=new Ids.Session(read(inputs,"connection-session"));
                    try(ContinuityDevice device=enrollment.activate();ContinuityPeer peer=device.preparePeerReopen(
                            PeerProbe.configuration(inputs.resolve("peer")),PeerConfiguration.Quality.ONE_TIME_BOTH,PeerConfiguration.Role.INITIATOR,session)) {
                        peer.finishOpen(); Ids.Message message=peer.nextMessage(session);
                        require(peer.messageStatus(session,new Ids.Message(read(inputs,"connection-message")))==ContinuityPeer.MessageStatus.ACKNOWLEDGED,"original acknowledged message changed");
                        if(!mode.equals("credential-local-identity")) require(Arrays.equals(message.encoded(),read(inputs,"local-next-message")),"expiry advanced next message identity");
                        if(mode.equals("credential-local-send")) {
                            require(peer.send(new String(read(inputs,"connection-address"),StandardCharsets.US_ASCII),session,message,
                                    "persisted before process exit".getBytes(StandardCharsets.UTF_8),"configuration-v1".getBytes(StandardCharsets.UTF_8))
                                    .consumption()==ContinuityPeer.Consumption.CONFIRMED,"local expiry recovery delivery");
                            publish(output,ByteBuffer.allocate(64).put(session.encoded()).put(message.encoded()).array());
                        } else publish(output,ByteBuffer.allocate(96).put(identity).put(message.encoded()).array());
                    }
                } else if(mode.equals("credential-local-next-activate") || mode.equals("credential-local-next-reopen")) {
                    byte[] identity=CredentialProbe.identity(enrollment);
                    try(ContinuityDevice device=enrollment.activate()) { device.cancel(); }
                    publish(output,identity);
                } else if(mode.equals("credential-local-expired-activate") || mode.equals("credential-local-needs-approval")) {
                    failed(104,enrollment::activate);publish(output,ByteBuffer.allocate(4).putInt(104).array());
                } else if(mode.equals("credential-local-pending") || mode.equals("credential-local-next-status")) {
                    publish(output,CredentialProbe.status(enrollment.credentialRenewalStatus()));
                } else {
                    String prefix=mode.startsWith("credential-local-next-")?"local-second-":"local-first-";
                    Ids.CredentialRenewal operation=new Ids.CredentialRenewal(read(inputs,prefix+"operation"));
                    Ids.CredentialStatement statement=new Ids.CredentialStatement(read(inputs,prefix+"statement"));
                    if(mode.equals("credential-local-stage") || mode.equals("credential-local-rejected") || mode.equals("credential-local-next-stage") || mode.equals("credential-local-next-stage-blocked")) {
                        AccountPin pin=new AccountPin(read(inputs,"trusted-account"),read(inputs,"enrollment-root"),read(inputs,"family"),
                                counter(ByteBuffer.wrap(read(inputs,prefix+"version"))),read(inputs,prefix+"digest"));
                        byte[] grant=read(inputs,prefix+"grant");
                        if(mode.equals("credential-local-next-stage-blocked")) {
                            failed(211,()->enrollment.stageCredentialRenewal(grant,pin,operation));publish(output,ByteBuffer.allocate(4).putInt(211).array());
                        } else if(mode.equals("credential-local-rejected")) {
                            grant[grant.length-1]^=1;failed(102,()->enrollment.stageCredentialRenewal(grant,pin,operation));
                            publish(output,ByteBuffer.allocate(4).putInt(102).array());
                        } else publish(output,CredentialProbe.status(enrollment.stageCredentialRenewal(grant,pin,operation)));
                    } else if(mode.equals("credential-local-reconcile") || mode.equals("credential-local-next-expiry")) {
                        publish(output,CredentialProbe.status(enrollment.reconcileExpiredCredentialRenewal(operation,statement)));
                    } else throw new IllegalArgumentException("local credential operation");
                }
            }
        }
        System.out.println(profile+":"+mode+":passed");
    }
}
