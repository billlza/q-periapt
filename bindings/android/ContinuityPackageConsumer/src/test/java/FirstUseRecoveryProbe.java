// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;
import static dev.qperiapt.continuity.android.tests.RecoveryProbeReports.hex;

/** Recovery uses only the original Java-created installation and original IDs. */
public final class FirstUseRecoveryProbe {
    private FirstUseRecoveryProbe() { }
    private static byte[] reconciliation(AccountRecoveryRecords.Reconciliation value) {
        ByteBuffer out=ByteBuffer.allocate(36+84*value.members().size());out.put(value.operation().encoded()).putInt(value.members().size());
        for(AccountRecoveryRecords.ReconciledMember m:value.members()) out.put(m.device()).put(m.session().encoded()).put(m.message().encoded()).putInt(m.state().ordinal()+1);
        return out.array();
    }
    public static void main(String[] args) throws Exception {
        require(args.length==5 && (args[2].equals("fixed") || args[2].equals("recoverable")),"first-use recovery arguments");
        Path inputs=Path.of(args[0]),installation=Path.of(args[1]),output=Path.of(args[4]);String mode=args[3];byte[] result;
        RecoveryProbeFiles files=new RecoveryProbeFiles(installation);
        try(ContinuityRecovery owner=ContinuityRecovery.prepare(installation.toString(),RecoveryWitness.local())) {
            owner.finishOpen();
            if(mode.equals("recovery-account-query") || mode.equals("recovery-account-retire") || mode.equals("recovery-account-retired")) {
                Ids.AccountOperation operation=new Ids.AccountOperation(read(inputs,"account-operation"));
                if(mode.equals("recovery-account-retired")) {
                    failed(112,() -> owner.selectAccount(operation));failed(202,owner::sessionCount);result=ByteBuffer.allocate(4).putInt(112).array();
                } else {
                    require(owner.sessionCount()==2,"complete original session index");
                    require(!owner.sessionAt(0).equals(owner.sessionAt(1)),"duplicate session discovery");
                    owner.selectAccount(operation);failed(108,owner::sessionCount);failed(211,owner::beginAccountCleanupReport);
                    AccountRecoveryRecords.Reconciliation all=owner.reconcileAccount();require(all.operation().equals(operation),"operation changed");
                    result=reconciliation(all);
                    if(mode.equals("recovery-account-retire")) {
                        files.retain("android-account-reconciliation",result,true);owner.retireAccount();owner.retireAccount();
                        require(owner.accountStatus().phase()==AccountStatus.Phase.RETIRED,"account retirement");failed(112,owner::reconcileAccount);
                    }
                }
            } else {
                Ids.Session session=new Ids.Session(read(inputs,"recovery-session"));String archiveName="android-archive-"+hex(session);
                if(mode.equals("recovery-archive-tamper")) {
                    byte[] archive=files.read(archiveName);archive[archive.length-1]^=1;
                    failed(208,() -> owner.selectArchive(archive));failed(202,owner::sessionCount);result=ByteBuffer.allocate(4).putInt(208).array();
                } else if(mode.equals("recovery-archive-restore")) {
                    byte[] archive=files.read(archiveName);owner.selectArchive(archive);
                    require(owner.sessionStatus().phase()==ClosureRecords.Phase.CLOSED,"archive revived closed session");
                    owner.restoreSessionIndex();owner.restoreSessionIndex();require(Arrays.equals(owner.archive(),archive),"archive identity changed");result=archive;
                } else {
                    owner.selectSession(session);
                    if(mode.equals("recovery-session-freeze") || mode.equals("recovery-session-ack")) {
                        boolean create=mode.equals("recovery-session-freeze");
                        Ids.ClosureReport report=RecoveryProbeReports.session(owner,files,session,create);
                        if(create) files.retain(archiveName,owner.archive(),true);
                        else {owner.acknowledgeSession(report);owner.acknowledgeSession(report);require(owner.sessionStatus().phase()==ClosureRecords.Phase.CLOSED,"session acknowledgement");}
                        result=report.encoded();
                    } else if(mode.equals("recovery-session-retire")) {
                        ClosureRecords.Status status=owner.sessionStatus();require(status.phase()==ClosureRecords.Phase.CLOSED,"session not closed");
                        byte[] archive=owner.archive();require(Arrays.equals(archive,files.read(archiveName)),"original archive differs");
                        require(owner.retireSession(status.report()),"first index retirement absent");require(!owner.retireSession(status.report()),"index retirement not idempotent");result=archive;
                    } else throw new IllegalArgumentException("first-use recovery mode");
                }
            }
        }
        publish(output,result);System.out.println(args[2]+":"+mode+":passed");
    }
}
