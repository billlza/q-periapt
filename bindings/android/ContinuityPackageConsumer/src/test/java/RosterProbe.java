// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Fresh local roster adapter probe; witnessed and traffic scenarios are separate. */
public final class RosterProbe {
    private RosterProbe() { }
    private static long bits(Counter64 value) { return Long.parseUnsignedLong(value.toString()); }
    private static void checkpoint(ByteBuffer output, RosterCheckpoint value) {
        output.putLong(bits(value.version())).put(value.digest());
    }
    private static RosterCheckpoint checkpoint(Path input, String prefix) throws Exception {
        return new RosterCheckpoint(counter(ByteBuffer.wrap(read(input,prefix+"version"))),read(input,prefix+"digest"));
    }
    private static byte[] status(EnrollmentStatus value) {
        ByteBuffer out=ByteBuffer.allocate(148).putInt(value.phase().ordinal()+1).put(value.signingKeyId());
        byte[] journal=value.journalId();out.put(journal==null?new byte[32]:journal);
        if(value.previous()!=null)out.putLong(bits(value.previous().version())).put(value.previous().digest());
        else out.put(new byte[40]);
        if(value.next()!=null)out.putLong(bits(value.next().version())).put(value.next().digest());
        else out.put(new byte[40]);
        return out.array();
    }
    private static byte[] resolution(RosterRefreshResolution value) {
        ByteBuffer out=ByteBuffer.allocate(168).putInt(value.outcome().ordinal()+1).putInt(0).put(value.journal().encoded());
        checkpoint(out,value.previous());checkpoint(out,value.target());checkpoint(out,value.observed());
        return out.putLong(bits(value.observedAt())).array();
    }
    public static void main(String[] args) throws Exception {
        require(args.length==5,"roster probe arguments");
        Path inputs=Path.of(args[0]),installation=Path.of(args[1]),output=Path.of(args[4]);
        String profile=args[2],requested=args[3];boolean selected=requested.startsWith("roster-selected-");
        String mode=selected?"roster-"+requested.substring("roster-selected-".length()):requested;require(profile.equals("fixed")||profile.equals("recoverable"),"trust profile");
        try(ContinuityConfiguration configuration=configuration(inputs,installation,profile.equals("recoverable"),false)) {
            configuration.finishOpen();
            try(ContinuityEnrollment enrollment=configuration.resumeEnrollment(intent(inputs),null)) {
                if(selected&&!mode.equals("roster-unselected"))PolicyProbe.selectTarget(enrollment,inputs,installation,profile.equals("recoverable"));
                RosterCheckpoint previous=checkpoint(inputs,"trusted-roster-"),target=checkpoint(inputs,"renewal-");
                AccountPin pin=new AccountPin(read(inputs,"trusted-account"),read(inputs,"enrollment-root"),read(inputs,"family"),target.version(),target.digest());
                switch(mode) {
                    case "roster-peer-roster-bad", "roster-peer-roster-checkpoint", "roster-peer-roster-cancelled", "roster-peer-roster-admit", "roster-peer-roster-reopen", "roster-peer-roster-revoke", "roster-peer-roster-revoked-reopen" -> {
                        try(ContinuityDevice device=selected?enrollment.activatePolicyRenewal():enrollment.activate()) {
                            RosterPeerProbe.run(device,inputs,mode.substring("roster-".length()),output);
                        }
                    }
                    case "roster-peer-connect", "roster-peer-uncertain", "roster-peer-retry" -> {
                        try(ContinuityDevice device=selected?enrollment.activatePolicyRenewal():enrollment.activate()) {
                            PeerProbe.client(device,inputs,mode.substring("roster-".length()),output);
                        }
                    }
                    case "roster-refused", "roster-cancelled", "roster-refresh", "roster-unselected", "roster-original-expired" -> {
                        byte[] roster=read(inputs,"renewal-roster");
                        if(mode.equals("roster-refused"))roster[roster.length-1]^=1;
                        if(mode.equals("roster-cancelled"))enrollment.cancel();
                        int expected=mode.equals("roster-refused")?102:mode.equals("roster-cancelled")?302:mode.equals("roster-unselected")?1:mode.equals("roster-original-expired")?104:0;
                        if(expected!=0) {
                            if(expected==104)failed(expected,()->enrollment.refreshRoster(previous,roster,pin));
                            else failed(expected,()->enrollment.refreshRoster(previous,roster,pin,selected?RosterPolicySource.SELECTED:RosterPolicySource.ORIGINAL));
                            publish(output,ByteBuffer.allocate(4).putInt(expected).array());
                        } else publish(output,status(selected?enrollment.refreshRoster(previous,roster,pin,RosterPolicySource.SELECTED):enrollment.refreshRoster(previous,roster,pin)));
                    }
                    case "roster-resolve" -> publish(output,resolution(enrollment.resolveRosterRefresh(previous,target)));
                    case "roster-resolve-pending" -> {
                        failed(215,()->enrollment.resolveRosterRefresh(previous,target));
                        publish(output,ByteBuffer.allocate(4).putInt(215).array());
                    }
                    case "roster-activate" -> {
                        byte[] original=CredentialProbe.identity(enrollment);
                        try(ContinuityDevice device=selected?enrollment.activatePolicyRenewal():enrollment.activate()) { require(device!=null,"activated owner"); }
                        publish(output,original);
                    }
                    case "roster-identity" -> publish(output,CredentialProbe.identity(enrollment));
                    default -> throw new IllegalArgumentException("unknown roster probe mode");
                }
            }
        }
        System.out.println(profile+":"+requested+":passed");
    }
}
