// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;
import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Public required-witness roster operations over the original managed enrollment. */
public final class RosterWitnessProbe {
    private RosterWitnessProbe() { }
    private static RosterCheckpoint checkpoint(Path inputs,String prefix) throws Exception {
        return new RosterCheckpoint(counter(ByteBuffer.wrap(read(inputs,prefix+"version"))),read(inputs,prefix+"digest"));
    }
    private static byte[] state(RosterRefreshState value) { return ByteBuffer.allocate(4).putInt(value.ordinal()+1).array(); }
    private static void run(Path inputs,Path installation,Path output,String profile,String requested,ConfigurationWitness witness) throws Exception {
        boolean selected=requested.startsWith("roster-witness-selected-");
        String mode=selected?"roster-witness-"+requested.substring("roster-witness-selected-".length()):requested;
        require(witness!=null,"required witness");
        try(ContinuityConfiguration configuration=configuration(inputs,installation,profile.equals("recoverable"),false)) {
            configuration.finishOpen();
            try(ContinuityEnrollment enrollment=configuration.resumeEnrollment(intent(inputs),witness)) {
                boolean history=mode.equals("roster-witness-history-unmanaged")||mode.equals("roster-witness-activate-unmanaged");
                ContinuityAccountAuthority registry=null;
                try {
                    if(!history) { registry=AuthorityProbe.open(inputs,installation);enrollment.selectAccountAuthority(registry,AuthorityProbe.expected(inputs)); }
                    if(selected&&!mode.equals("roster-witness-prepare-unselected")
                            &&(mode.startsWith("roster-witness-prepare")||mode.startsWith("roster-witness-commit")||mode.startsWith("roster-witness-activate")||mode.startsWith("roster-witness-peer-")))
                        PolicyProbe.selectTarget(enrollment,inputs,installation,profile.equals("recoverable"));
                    if(mode.startsWith("roster-witness-peer-")) {
                        try(ContinuityDevice device=selected?enrollment.activatePolicyRenewal():enrollment.activate()) {
                            if(mode.startsWith("roster-witness-peer-roster-"))RosterPeerProbe.run(device,inputs,mode.substring("roster-witness-".length()),output);
                            else if(mode.equals("roster-witness-peer-unassociated"))PeerProbe.unassociated(device,inputs,output);
                            else PeerProbe.client(device,inputs,mode.substring("roster-witness-".length()),output);
                        }
                        return;
                    }
                    Ids.RosterRefresh operation=new Ids.RosterRefresh(read(inputs,"roster-operation"));
                    if(mode.equals("roster-witness-progress")) { publish(output,RosterProbeRecords.progress(enrollment.witnessedRosterRefreshProgress()));return; }
                    if(mode.startsWith("roster-witness-prepare")) {
                        RosterCheckpoint target=checkpoint(inputs,"renewal-");
                        AccountPin pin=new AccountPin(read(inputs,"trusted-account"),read(inputs,"enrollment-root"),read(inputs,"family"),target.version(),target.digest());
                        byte[] certificate=read(inputs,"grant-certificate"),roster=read(inputs,"renewal-roster");
                        int expected=mode.equals("roster-witness-prepare-bad")?102:mode.equals("roster-witness-prepare-cancelled")?302:mode.equals("roster-witness-prepare-unselected")?1:mode.equals("roster-witness-prepare-original-expired")?104:0;
                        if(expected==102)roster[roster.length-1]^=1;
                        if(expected==302)enrollment.cancel();
                        RosterPolicySource policy=expected==104?RosterPolicySource.ORIGINAL:(selected||expected==1?RosterPolicySource.SELECTED:RosterPolicySource.ORIGINAL);
                        if(expected!=0) { failed(expected,()->enrollment.prepareWitnessedRosterRefresh(operation,policy,certificate,roster,pin));publish(output,ByteBuffer.allocate(4).putInt(expected).array()); }
                        else publish(output,enrollment.prepareWitnessedRosterRefresh(operation,policy,certificate,roster,pin).encoded());
                        return;
                    }
                    if(mode.equals("roster-witness-recover")) {
                        RosterRefreshProposal proposal=enrollment.recoverWitnessedRosterRefreshPreparation();require(proposal!=null,"retained roster proposal");publish(output,proposal.encoded());return;
                    }
                    if(mode.equals("roster-witness-abandon-refused")) {
                        failed(211,()->enrollment.abandonUnpreparedRosterRefresh(operation));publish(output,ByteBuffer.allocate(4).putInt(211).array());return;
                    }
                    if(mode.equals("roster-witness-resolve-local")) {
                        RosterCheckpoint previous=checkpoint(inputs,"trusted-roster-"),target=checkpoint(inputs,"renewal-");
                        failed(216,()->enrollment.resolveRosterRefresh(previous,target));publish(output,ByteBuffer.allocate(4).putInt(216).array());return;
                    }
                    if(mode.equals("roster-witness-activate-unmanaged")) {
                        if(selected)failed(211,enrollment::activatePolicyRenewal);else failed(211,enrollment::activate);publish(output,ByteBuffer.allocate(4).putInt(211).array());return;
                    }
                    byte[] bytes=read(inputs,"roster-proposal");
                    if(mode.equals("roster-witness-substitute"))bytes[bytes.length-1]^=1;
                    RosterRefreshProposal original=new RosterRefreshProposal(bytes);
                    switch(mode) {
                        case "roster-witness-substitute" -> {
                            failed(211,()->enrollment.reconcileWitnessedRosterRefresh(original));publish(output,ByteBuffer.allocate(4).putInt(211).array());
                        }
                        case "roster-witness-commit-unknown", "roster-witness-close-unknown" -> {
                            if(mode.equals("roster-witness-commit-unknown")) failed(218,()->enrollment.commitWitnessedRosterRefresh(original,selected?RosterPolicySource.SELECTED:RosterPolicySource.ORIGINAL));
                            else failed(218,()->enrollment.closeWitnessedRosterRefresh(original));
                            publish(output,ByteBuffer.allocate(4).putInt(218).array());
                        }
                        case "roster-witness-reconcile", "roster-witness-history-unmanaged" -> publish(output,state(enrollment.reconcileWitnessedRosterRefresh(original)));
                        case "roster-witness-commit" -> publish(output,state(enrollment.commitWitnessedRosterRefresh(original,selected?RosterPolicySource.SELECTED:RosterPolicySource.ORIGINAL)));
                        case "roster-witness-close" -> publish(output,state(enrollment.closeWitnessedRosterRefresh(original)));
                        default -> throw new IllegalArgumentException("unknown roster witness mode");
                    }
                } finally { if(registry!=null)registry.close(); }
            }
        }
    }
    public static void main(String[] args) throws Exception {
        require(args.length==5,"roster witness arguments");require(args[2].equals("fixed")||args[2].equals("recoverable"),"trust profile");
        Path inputs=Path.of(args[0]),installation=Path.of(args[1]),output=Path.of(args[4]);
        WitnessProbe.withWitness(inputs,args[3],witness->run(inputs,installation,output,args[2],args[3],witness));
        System.out.println(args[2]+":"+args[3]+":passed");
    }
}
