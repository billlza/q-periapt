// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Original cancellation remains pending until an independent Closed decision. */
public final class CredentialTerminalProbe {
    private CredentialTerminalProbe() { }
    static boolean historical(String mode) {
        return mode.equals("credential-terminal-close-committed") || mode.equals("credential-terminal-expiry-committed")
            || mode.equals("credential-terminal-pending") || mode.equals("credential-terminal-reconcile-unknown")
            || mode.equals("credential-terminal-status-closed") || mode.equals("credential-terminal-reconcile")
            || mode.equals("credential-terminal-close-replay") || mode.equals("credential-terminal-commit-replay");
    }
    static void run(ContinuityEnrollment enrollment, Path inputs, String mode, Path output) throws Exception {
        if (mode.equals("credential-terminal-close-committed") || mode.equals("credential-terminal-expiry-committed")) {
            Ids.CredentialRenewal operation=new Ids.CredentialRenewal(read(inputs,"credential-operation"));
            Ids.CredentialStatement statement=new Ids.CredentialStatement(read(inputs,"credential-statement"));
            CredentialRenewalStatus result=mode.equals("credential-terminal-close-committed")
                ? enrollment.closeWitnessedCredentialRenewal(operation,statement) : enrollment.reconcileExpiredCredentialRenewal(operation,statement);
            publish(output,CredentialProbe.status(result));return;
        }
        if (mode.equals("credential-terminal-active") || mode.equals("credential-terminal-send")) {
            byte[] identity=CredentialProbe.identity(enrollment);
            Ids.Session session=new Ids.Session(read(inputs,"connection-session"));
            try (ContinuityDevice device=enrollment.activate(); ContinuityPeer peer=device.preparePeerReopen(
                    PeerProbe.configuration(inputs.resolve("peer")),PeerConfiguration.Quality.ONE_TIME_BOTH,PeerConfiguration.Role.INITIATOR,session)) {
                peer.finishOpen();Ids.Message message=peer.nextMessage(session);
                require(Arrays.equals(message.encoded(),read(inputs,"remote-next")),"cancellation advanced the next original message slot");
                for(String name:new String[]{"connection-message","remote-message"})
                    require(peer.messageStatus(session,new Ids.Message(read(inputs,name)))==ContinuityPeer.MessageStatus.ACKNOWLEDGED,"cancellation lost prior acknowledgment");
                if(mode.equals("credential-terminal-active")) publish(output,ByteBuffer.allocate(96).put(identity).put(message.encoded()).array());
                else {
                    String address=new String(read(inputs,"connection-address"),StandardCharsets.US_ASCII);
                    require(peer.send(address,session,message,"persisted before process exit".getBytes(StandardCharsets.UTF_8),
                        "configuration-v1".getBytes(StandardCharsets.UTF_8)).consumption()==ContinuityPeer.Consumption.CONFIRMED,"prior authority traffic failed");
                    publish(output,ByteBuffer.allocate(64).put(session.encoded()).put(message.encoded()).array());
                }
            }
            return;
        }
        Ids.CredentialRenewal operation=new Ids.CredentialRenewal(read(inputs,"terminal-operation"));
        Ids.CredentialStatement statement=new Ids.CredentialStatement(read(inputs,"terminal-statement"));
        switch(mode) {
            case "credential-terminal-stage", "credential-terminal-expired-stage-refused" -> {
                AccountPin pin=new AccountPin(read(inputs,"trusted-account"),read(inputs,"enrollment-root"),read(inputs,"family"),
                    counter(ByteBuffer.wrap(read(inputs,"terminal-version"))),read(inputs,"terminal-digest"));
                byte[] grant=read(inputs,"terminal-grant");
                if(mode.equals("credential-terminal-expired-stage-refused")) {
                    failed(104,()->enrollment.stageCredentialRenewal(grant,pin,operation));publish(output,ByteBuffer.allocate(4).putInt(104).array());
                } else publish(output,CredentialProbe.status(enrollment.stageCredentialRenewal(grant,pin,operation)));
            }
            case "credential-terminal-cancel-prepare" -> {
                CredentialRenewalCancellation cancellation=enrollment.prepareWitnessedCredentialCancellation();
                require(cancellation.operation().equals(operation) && cancellation.statement().equals(statement),"original cancellation identity");
                publish(output,cancellation.encoded());
            }
            case "credential-terminal-pending", "credential-terminal-reconcile" -> publish(output,CredentialProbe.status(enrollment.reconcileWitnessedCredentialRenewal(operation,statement)));
            case "credential-terminal-reconcile-unknown" -> {
                failed(218,()->enrollment.reconcileWitnessedCredentialRenewal(operation,statement));publish(output,ByteBuffer.allocate(4).putInt(218).array());
            }
            case "credential-terminal-commit-reserved-refused", "credential-terminal-commit-expired-refused" -> {
                int code=215;
                failed(code,()->enrollment.commitWitnessedCredentialRenewal(operation,statement));publish(output,ByteBuffer.allocate(4).putInt(code).array());
            }
            case "credential-terminal-activate-refused" -> {
                failed(215,enrollment::activate);publish(output,ByteBuffer.allocate(4).putInt(215).array());
            }
            case "credential-terminal-status-closed" -> publish(output,CredentialProbe.status(enrollment.credentialRenewalStatus()));
            case "credential-terminal-close-replay" -> publish(output,CredentialProbe.status(enrollment.closeWitnessedCredentialRenewal(operation,statement)));
            case "credential-terminal-commit-replay" -> publish(output,CredentialProbe.status(enrollment.commitWitnessedCredentialRenewal(operation,statement)));
            default -> throw new IllegalArgumentException("credential terminal operation");
        }
    }
}
