// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;
import static dev.qperiapt.continuity.android.tests.RecoveryProbeReports.*;

/** Public Java recovery over original C-created fixtures; never sends business traffic. */
public final class RecoveryProbe {
    private RecoveryProbe() { }
    public static void main(String[] args) throws Exception {
        int offset=0;RecoveryWitness witness=RecoveryWitness.local();
        if(args.length==5) {
            if(args[0].equals("--witness")) witness=RecoveryWitness.signedTcp(args[1],5000);
            else if(args[0].equals("--witness-tls")) witness=RecoveryWitness.mutualTls(args[1],5000);
            else throw new IllegalArgumentException("recovery carrier");
            offset=2;
        }
        require(args.length-offset==3,"recovery arguments");String mode=args[offset];Path path=Path.of(args[offset+1]);byte[] original=decode(args[offset+2]);
        RecoveryProbeFiles files=new RecoveryProbeFiles(path);
        String answer;
        try(ContinuityRecovery owner=ContinuityRecovery.prepare(path.toString(),witness)) {
            owner.finishOpen();
            answer=mode.startsWith("recover-member-") ? member(owner,files,mode,new Ids.Session(original))
                : account(owner,files,mode,new Ids.AccountOperation(original));
        }
        capture(files,mode,original,answer);
        System.out.print(answer);
    }
    private static void capture(RecoveryProbeFiles files,String mode,byte[] original,String answer) throws Exception {
        String selected=System.getenv("QPC_RECOVERY_CAPTURE");require(selected!=null,"recovery capture required");Path out=Path.of(selected);
        if(mode.startsWith("recover-member-")) Files.write(out.resolve("member-report.txt"),files.read("c-member-loss-"+hex(original)),StandardOpenOption.CREATE_NEW);
        else if(mode.equals("recover-account-settled-retire")) Files.write(out.resolve("reconciliation.txt"),files.read("c-account-reconciliation"),StandardOpenOption.CREATE_NEW);
        else if(java.util.Set.of("recover-account-freeze","recover-account-freeze-reconcile","recover-account-witness-ack","recover-account-ack","recover-account-ack-reconcile",
                "recover-account-witness-retire","recover-account-retire","recover-account-retire-reconcile").contains(mode))
            Files.write(out.resolve("account-report.txt"),files.read("c-account-loss-report"),StandardOpenOption.CREATE_NEW);
        Files.write(out.resolve("result.txt"),answer.getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        Files.write(out.resolve("completed.txt"),new byte[] {1},StandardOpenOption.CREATE_NEW);
    }
    private static String member(ContinuityRecovery owner,RecoveryProbeFiles files,String mode,Ids.Session session) throws Exception {
        boolean create=mode.equals("recover-member-freeze");require(create || mode.equals("recover-member-ack"),"member mode");
        owner.selectSession(session);Ids.ClosureReport report=RecoveryProbeReports.session(owner,files,session,create);
        if(!create) {
            owner.acknowledgeSession(report);owner.acknowledgeSession(report);
            ClosureRecords.Status status=owner.sessionStatus();require(status.phase()==ClosureRecords.Phase.CLOSED && report.equals(status.report()),"accounted member changed");
        }
        return create ? "member-frozen\n" : "member-accounted\n";
    }
    private static Ids.AccountAbandonment saved(RecoveryProbeFiles files,Ids.AccountOperation operation) throws Exception {
        String text=new String(files.read("c-account-loss-report"),StandardCharsets.UTF_8);
        String prefix="QPC-C-ACCOUNT-LOSS/1\nbatch "+hex(operation)+"\nreport ";
        require(text.startsWith(prefix) && text.length()>prefix.length()+64 && text.charAt(prefix.length()+64)=='\n',"saved account report scope");
        return new Ids.AccountAbandonment(decode(text.substring(prefix.length(),prefix.length()+64)));
    }
    private static void phase(ContinuityRecovery owner,AccountStatus.Phase expected,Ids.AccountAbandonment report) {
        phase(owner.accountStatus(),expected,report);
    }
    private static void phase(AccountStatus actual,AccountStatus.Phase expected,Ids.AccountAbandonment report) {
        require(actual.phase()==expected && java.util.Objects.equals(actual.report(),report),"account state/report changed");
    }
    private static String reconciliation(ContinuityRecovery owner,RecoveryProbeFiles files,Ids.AccountOperation operation,boolean retire) throws Exception {
        AccountRecoveryRecords.Reconciliation result=owner.reconcileAccount();require(result.operation().equals(operation),"reconciled operation changed");
        StringBuilder out=new StringBuilder("QPC-C-RECONCILIATION/1\nbatch "+hex(operation)+"\nmembers "+result.members().size()+"\n");
        int index=0;
        for(AccountRecoveryRecords.ReconciledMember member:result.members()) {
            if(retire) require(member.state()!=AccountRecoveryRecords.MemberState.COMMITTED && member.state()!=AccountRecoveryRecords.MemberState.RESOLUTION_PENDING,"unsettled account retirement");
            out.append("member ").append(index++).append(' ').append(hex(member.device())).append(' ').append(hex(member.session())).append(' ')
                .append(hex(member.message())).append(' ').append(member.state().ordinal()+1).append('\n');
        }
        String text=out.toString();
        if(retire) {
            files.retain("c-account-reconciliation",text.getBytes(StandardCharsets.UTF_8),true);
            files.retain("c-account-reconciliation",text.getBytes(StandardCharsets.UTF_8),false);
            owner.retireAccount();owner.retireAccount();phase(owner,AccountStatus.Phase.RETIRED,null);failed(112,owner::reconcileAccount);
        } else failed(215,owner::retireAccount);
        return text;
    }
    private static String account(ContinuityRecovery owner,RecoveryProbeFiles files,String mode,Ids.AccountOperation operation) throws Exception {
        if(mode.equals("recover-account-reject")) {
            int code;
            try {owner.selectAccount(operation);throw new AssertionError("unapproved recovery admitted");}
            catch(ContinuityFailure failure) {code=failure.code();require(code==216 || code==211 || code==218,"wrong authority refusal");}
            failed(202,owner::sessionCount);return "account-selection-refused:"+code+"\n";
        }
        if(mode.equals("recover-account-retired") || mode.equals("recover-account-absent")) {
            int code=mode.equals("recover-account-retired") ? 112 : 201;
            failed(code,() -> owner.selectAccount(operation));failed(202,owner::sessionCount);return "account-selection-refused:"+code+"\n";
        }
        owner.selectAccount(operation);failed(108,owner::sessionCount);failed(108,owner::beginSessionCleanup);
        failed(108,owner::restoreSessionIndex);failed(108,() -> owner.accountMember(0));
        AccountStatus current=owner.accountStatus();
        switch(mode) {
            case "recover-account-results", "recover-account-settled-retire" -> {
                require(current.phase()==AccountStatus.Phase.COMMITTED,"committed reconciliation phase");
                return reconciliation(owner,files,operation,mode.equals("recover-account-settled-retire"));
            }
            case "recover-account-committed" -> {
                require(current.phase()==AccountStatus.Phase.COMMITTED,"committed account");failed(211,owner::beginAccountCleanup);failed(215,owner::retireAccount);
                phase(owner,AccountStatus.Phase.COMMITTED,null);return "account-committed-not-abandoned\n";
            }
            case "recover-account-witness-freeze" -> {
                require(current.phase()==AccountStatus.Phase.RESERVED,"reserved account");failed(218,owner::beginAccountCleanup);return "account-freeze-outcome-unavailable\n";
            }
            case "recover-account-freeze", "recover-account-freeze-reconcile" -> {
                boolean reconcile=mode.equals("recover-account-freeze-reconcile");
                require(current.phase()==(reconcile ? AccountStatus.Phase.ABANDONING : AccountStatus.Phase.RESERVED),"freeze original phase");failed(215,owner::retireAccount);
                Ids.AccountAbandonment report=RecoveryProbeReports.account(owner,files,operation,true);
                if(reconcile) require(report.equals(current.report()),"unknown freeze changed report");
                byte[] wrong=report.encoded();wrong[0]=(byte)(wrong[0]==1 ? 2 : 1);
                failed(211,() -> owner.acknowledgeAccount(new Ids.AccountAbandonment(wrong)));phase(owner,AccountStatus.Phase.ABANDONING,report);
                owner.cancel();failed(302,() -> owner.acknowledgeAccount(report));failed(302,owner::retireAccount);owner.accountMember(0);
                return "account-frozen:"+hex(report)+"\n";
            }
            case "recover-account-witness-ack", "recover-account-ack" -> {
                require(current.phase()==AccountStatus.Phase.ABANDONING,"frozen account");Ids.AccountAbandonment report=RecoveryProbeReports.account(owner,files,operation,false);
                if(mode.equals("recover-account-witness-ack")) {failed(218,() -> owner.acknowledgeAccount(report));return "account-acknowledgement-outcome-unavailable\n";}
                owner.acknowledgeAccount(report);owner.acknowledgeAccount(report);phase(owner,AccountStatus.Phase.ABANDONED,report);return "account-acknowledged:"+hex(report)+"\n";
            }
            case "recover-account-ack-reconcile" -> {
                Ids.AccountAbandonment report=saved(files,operation);phase(current,AccountStatus.Phase.ABANDONED,report);
                owner.acknowledgeAccount(report);owner.acknowledgeAccount(report);phase(owner,AccountStatus.Phase.ABANDONED,report);return "account-acknowledged:"+hex(report)+"\n";
            }
            case "recover-account-retire-reconcile" -> {
                saved(files,operation);phase(current,AccountStatus.Phase.RETIRED,null);owner.retireAccount();owner.retireAccount();phase(owner,AccountStatus.Phase.RETIRED,null);
                failed(112,owner::beginAccountCleanup);return "account-retired\n";
            }
            case "recover-account-witness-retire", "recover-account-retire" -> {
                Ids.AccountAbandonment report=saved(files,operation);phase(current,AccountStatus.Phase.ABANDONED,report);
                if(mode.equals("recover-account-witness-retire")) {failed(218,owner::retireAccount);return "account-retirement-outcome-unavailable\n";}
                owner.retireAccount();owner.retireAccount();phase(owner,AccountStatus.Phase.RETIRED,null);
                failed(112,owner::beginAccountCleanup);return "account-retired\n";
            }
            default -> throw new IllegalArgumentException("account recovery mode");
        }
    }
}
