// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Expired signed P0 permits exact historical cleanup, never new authority. */
public final class CredentialPolicyExpiryProbe {
    private CredentialPolicyExpiryProbe() { }
    private static void run(Path inputs,Path installation,Path output,String profile,String mode,ConfigurationWitness witness) throws Exception {
        boolean recovery=profile.equals("recoverable");require(recovery || profile.equals("fixed"),"profile");
        try(ContinuityConfiguration configuration=configuration(inputs,installation,recovery,false)) {
            configuration.finishOpen();
            try(ContinuityEnrollment enrollment=configuration.resumeEnrollment(intent(inputs),witness)) {
                boolean current=mode.equals("credential-policy-stage") || mode.equals("credential-policy-commit-unknown")
                    || mode.equals("credential-policy-activate-expired") || mode.equals("credential-policy-stage-expired")
                    || mode.equals("credential-policy-commit-expired") || mode.equals("credential-policy-prepare");
                ContinuityAccountAuthority registry=null;
                try {
                    if(current) {registry=AuthorityProbe.open(inputs,installation);enrollment.selectAccountAuthority(registry,AuthorityProbe.expected(inputs));}
                    if(mode.equals("credential-policy-identity")) {publish(output,CredentialProbe.identity(enrollment));return;}
                    if(mode.equals("credential-policy-activate-expired")) {failed(104,enrollment::activate);publish(output,ByteBuffer.allocate(4).putInt(104).array());return;}
                    if(mode.equals("credential-policy-prepare") || mode.equals("credential-policy-prepare-replay")) {publish(output,enrollment.prepareWitnessedCredentialRenewal().encoded());return;}
                    if(mode.equals("credential-policy-status")) {publish(output,CredentialProbe.status(enrollment.credentialRenewalStatus()));return;}
                    Ids.CredentialRenewal operation=new Ids.CredentialRenewal(read(inputs,"credential-operation"));
                    Ids.CredentialStatement statement=new Ids.CredentialStatement(read(inputs,"credential-statement"));
                    switch(mode) {
                        case "credential-policy-stage", "credential-policy-stage-expired" -> {
                            AccountPin pin=new AccountPin(read(inputs,"trusted-account"),read(inputs,"enrollment-root"),read(inputs,"family"),
                                counter(ByteBuffer.wrap(read(inputs,"renewal-version"))),read(inputs,"renewal-digest"));
                            byte[] grant=read(inputs,"credential-renewal");
                            if(mode.equals("credential-policy-stage-expired")) {failed(104,()->enrollment.stageCredentialRenewal(grant,pin,operation));publish(output,ByteBuffer.allocate(4).putInt(104).array());}
                            else publish(output,CredentialProbe.status(enrollment.stageCredentialRenewal(grant,pin,operation)));
                        }
                        case "credential-policy-commit-unknown", "credential-policy-commit-expired" -> {
                            int code=mode.equals("credential-policy-commit-unknown")?218:104;
                            failed(code,()->enrollment.commitWitnessedCredentialRenewal(operation,statement));publish(output,ByteBuffer.allocate(4).putInt(code).array());
                        }
                        case "credential-policy-commit-recover", "credential-policy-commit-terminal" -> publish(output,CredentialProbe.status(enrollment.commitWitnessedCredentialRenewal(operation,statement)));
                        case "credential-policy-reconcile" -> publish(output,CredentialProbe.status(enrollment.reconcileWitnessedCredentialRenewal(operation,statement)));
                        case "credential-policy-close" -> publish(output,CredentialProbe.status(enrollment.closeWitnessedCredentialRenewal(operation,statement)));
                        default -> throw new IllegalArgumentException("expired-policy credential operation");
                    }
                } finally {if(registry!=null) registry.close();}
            }
        }
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=5) throw new IllegalArgumentException("inputs installation profile mode result");
        Path inputs=Path.of(args[0]),installation=Path.of(args[1]),output=Path.of(args[4]);
        WitnessProbe.withWitness(inputs,args[3],witness->run(inputs,installation,output,args[2],args[3],witness));
        System.out.println(args[2]+":"+args[3]+":passed");
    }
}
