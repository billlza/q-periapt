// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.charset.StandardCharsets;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Traverses every native report field and compares the host's retained snapshot. */
final class RecoveryProbeReports {
    private RecoveryProbeReports() { }
    static String hex(byte[] bytes) {
        StringBuilder result=new StringBuilder(bytes.length*2);for(byte b:bytes) result.append(Character.forDigit((b&255)>>>4,16)).append(Character.forDigit(b&15,16));return result.toString();
    }
    static String hex(Ids.Value value) { return hex(value.encoded()); }
    static byte[] decode(String text) {
        require(text.matches("[0-9a-f]{64}"),"identity encoding");byte[] result=new byte[32];
        for(int i=0;i<32;i++) result[i]=(byte)Integer.parseInt(text.substring(i*2,i*2+2),16);return result;
    }
    private static String optional(Counter64 value) { return (value==null ? "0 0" : "1 "+value); }
    private static void reservation(StringBuilder out,String index,ClosureRecords.Reservation value) {
        out.append("reserved ").append(index).append(' ').append(hex(value.message())).append(' ').append(value.plaintextBytes()).append(' ').append(value.associatedDataBytes()).append('\n');
    }
    private static void epochs(ContinuityRecovery owner,StringBuilder out,int member,java.util.List<CleanupReports.Epoch> reports) {
        int count=reports.size();require(count<=4,"epoch bound");
        for(int i=0;i<count;i++) {
            CleanupReports.Epoch complete=reports.get(i);ClosureRecords.Epoch e=complete.metadata();
            require(complete.unconfirmed().size()==e.unconfirmedCount() && complete.deliveries().size()==e.deliveryCount() && complete.skipped().size()==e.skippedCount(),"incomplete epoch snapshot");
            require(e.unconfirmedCount()<=64 && e.deliveryCount()<=128 && e.skippedCount()<=128,"nested report bounds");
            String at=member<0 ? Integer.toString(i) : member+" "+i;
            out.append("epoch ").append(at).append(' ').append(e.epoch()).append(' ').append(e.acknowledgedBefore()).append(' ').append(e.sent()).append(' ')
                .append(e.consumedBefore()).append(' ').append(e.received()).append(' ').append(optional(e.peerSent())).append(' ').append(e.resolution().ordinal()).append(' ')
                .append(e.resolutionReport()==null ? "0".repeat(64) : hex(e.resolutionReport())).append(' ').append(e.unconfirmedCount()).append(' ').append(e.deliveryCount()).append(' ').append(e.skippedCount()).append('\n');
            for(int j=0;j<e.unconfirmedCount();j++) {
                ClosureRecords.Unconfirmed u=complete.unconfirmed().get(j);
                out.append("unconfirmed ").append(at).append(' ').append(j).append(' ').append(hex(u.message())).append(' ').append(hex(u.ciphertextDigest())).append('\n');
            }
            for(int j=0;j<e.deliveryCount();j++) {
                ClosureRecords.Delivery d=complete.deliveries().get(j);
                out.append("delivery ").append(at).append(' ').append(j).append(' ').append(hex(d.message())).append(' ').append(d.index()).append(' ').append(d.plaintextBytes()).append('\n');
            }
            for(int j=0;j<e.skippedCount();j++) out.append("skipped ").append(at).append(' ').append(j).append(' ')
                .append(complete.skipped().get(j)).append('\n');
            final int epoch=i;
            failed(1,() -> {if(member<0) owner.sessionUnconfirmed(epoch,e.unconfirmedCount());else owner.accountUnconfirmed(member,epoch,e.unconfirmedCount());});
            failed(1,() -> {if(member<0) owner.sessionDelivery(epoch,e.deliveryCount());else owner.accountDelivery(member,epoch,e.deliveryCount());});
            failed(1,() -> {if(member<0) owner.sessionSkipped(epoch,e.skippedCount());else owner.accountSkipped(member,epoch,e.skippedCount());});
        }
        failed(1,() -> {if(member<0) owner.sessionEpoch(count);else owner.accountEpoch(member,count);});
    }
    static Ids.ClosureReport session(ContinuityRecovery owner,RecoveryProbeFiles files,Ids.Session session,boolean create) throws Exception {
        CleanupReports.Session complete=owner.beginSessionCleanupReport();ClosureRecords.Header h=complete.header();
        require(complete.reservations().size()==h.reservationCount() && complete.epochs().size()==h.epochCount(),"incomplete session snapshot");require(h.session().equals(session) && h.reservationCount()<=4,"session report scope");
        StringBuilder out=new StringBuilder("QPC-C-LOSS/1\nreport "+hex(h.report())+"\nheader "+hex(h.session())+" "+hex(h.context())+" "+hex(h.peerAccount())+" "+hex(h.peerDevice())+" ");
        out.append(h.role().ordinal()+1).append(' ').append(h.generation()).append(' ').append(h.confirmedEpoch()).append(' ').append(h.sendingEpoch()).append(' ').append(h.receivingEpoch())
            .append(' ').append(optional(h.pendingEpoch())).append(' ').append(h.reservationCount()).append(' ').append(h.epochCount()).append('\n');
        for(int i=0;i<h.reservationCount();i++) reservation(out,Integer.toString(i),complete.reservations().get(i));
        failed(1,() -> owner.sessionReservation(h.reservationCount()));epochs(owner,out,-1,complete.epochs());
        files.retain("c-member-loss-"+hex(session),out.toString().getBytes(StandardCharsets.UTF_8),create);
        ClosureRecords.Status current=owner.sessionStatus();require(current.phase()==ClosureRecords.Phase.PENDING && h.report().equals(current.report()),"session report changed");return h.report();
    }
    static Ids.AccountAbandonment account(ContinuityRecovery owner,RecoveryProbeFiles files,Ids.AccountOperation operation,boolean create) throws Exception {
        CleanupReports.Account complete=owner.beginAccountCleanupReport();AccountRecoveryRecords.Header h=complete.header();
        require(complete.members().size()==h.memberCount(),"incomplete account snapshot");require(h.operation().equals(operation),"account report scope");
        StringBuilder out=new StringBuilder("QPC-C-ACCOUNT-LOSS/1\nbatch "+hex(operation)+"\nreport "+hex(h.report())+"\nmembers "+h.memberCount()+"\n");
        for(int i=0;i<h.memberCount();i++) {
            CleanupReports.Member member=complete.members().get(i);AccountRecoveryRecords.Member m=member.metadata();
            require(member.epochs().size()==m.epochCount(),"incomplete member snapshot");
            out.append("member ").append(i).append(' ').append(hex(m.device())).append(' ').append(hex(m.context())).append(' ').append(hex(m.session())).append(' ')
                .append(m.role().ordinal()+1).append(' ').append(m.generation()).append(' ').append(m.confirmedEpoch()).append(' ').append(m.sendingEpoch()).append(' ').append(m.receivingEpoch())
                .append(' ').append(optional(m.pendingEpoch())).append(' ').append(m.epochCount()).append('\n');
            reservation(out,Integer.toString(i),member.reservation());epochs(owner,out,i,member.epochs());
        }
        failed(1,() -> owner.accountMember(h.memberCount()));failed(1,() -> owner.accountReservation(h.memberCount()));
        files.retain("c-account-loss-report",out.toString().getBytes(StandardCharsets.UTF_8),create);
        AccountStatus current=owner.accountStatus();require(current.phase()==AccountStatus.Phase.ABANDONING && h.report().equals(current.report()),"account report changed");return h.report();
    }
}
