// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Both installations use public Android configuration/enrollment; no private state is imported. */
public final class RootOwnedProbe {
    @FunctionalInterface public interface CutObserver { void beforeHalt(byte[] value) throws Exception; }
    private RootOwnedProbe() { }
    interface DeviceAction { void run(ContinuityDevice device) throws Exception; }
    private static final class Registry implements AutoCloseable {
        final ContinuityAccountAuthority value;
        private boolean closed;
        Registry(Path inputs, Path installation) throws Exception { value = AuthorityProbe.open(inputs, installation); }
        void revoke() { if (!closed) { value.close(); closed = true; } }
        @Override public void close() { revoke(); }
    }
    private static Path target(Path installation) {
        return installation.resolveSibling(installation.getFileName() + ".root-target");
    }
    private static byte[] state(RootReplacementState value) { return ByteBuffer.allocate(4).putInt(value.ordinal()+1).array(); }
    static byte[] checkpoint(AccountAuthorityCheckpoint value) {
        return ByteBuffer.allocate(72).put(value.application().encoded())
            .putLong(Long.parseUnsignedLong(value.revision().toString())).put(value.account().encoded()).array();
    }
    static RootReplacementScope scope(Path inputs) throws Exception {
        return new RootReplacementScope(AuthorityProbe.expected(inputs), read(inputs,"witness-id"), read(inputs,"witness-public"));
    }
    static void cut(Path output, byte[] value, CutObserver observer) throws Exception {
        publish(output,value); observer.beforeHalt(value.clone()); Runtime.getRuntime().halt(77); throw new AssertionError("root cut returned");
    }
    private static AccountPin pin(Path inputs) throws Exception {
        return new AccountPin(read(inputs,"trusted-account"),read(inputs,"enrollment-root"),read(inputs,"family"),
            counter(ByteBuffer.wrap(read(inputs,"trusted-roster-version"))),read(inputs,"trusted-roster-digest"));
    }
    private static void targetPreparation(Path inputs, Path installation, Path output, String profile,
            String mode, ConfigurationWitness witness) throws Exception {
        boolean original=mode.startsWith("root-original-target-");
        Path selected=inputs.resolve(original?"root-original-target":"root-target");
        Path location=original?installation.resolveSibling(installation.getFileName()+".root-original-target"):target(installation);
        boolean create=mode.endsWith("-create");
        try(ContinuityConfiguration configuration=configuration(selected,location,profile.equals("recoverable"),create)) {
            configuration.finishOpen();
            try(ContinuityEnrollment enrollment=create?configuration.createEnrollment(intent(selected),witness):configuration.resumeEnrollment(intent(selected),witness)) {
                if(create)publish(output,enrollment.request());
                else {
                    byte[] journal=enrollment.accept(read(selected,"grant-certificate"),read(selected,"grant-roster"),pin(selected));
                    StoragePreparation prepared=enrollment.prepareStorage();
                    require(prepared.requiresWitnessEnrollment()&&Arrays.equals(journal,prepared.journalId()),"root target protection");
                    publish(output,ByteBuffer.allocate(164).putInt(2).put(journal).put(prepared.witnessSubject()).put(prepared.imageDigest()).array());
                }
            }
        }
    }
    static void withTarget(ContinuityAccountAuthority root, Path inputs, Path installation,
            String profile, ConfigurationWitness witness, DeviceAction action) throws Exception {
        Path selected=inputs.resolve("root-target");
        try(ContinuityConfiguration configuration=configuration(selected,target(installation),profile.equals("recoverable"),false)) {
            configuration.finishOpen();
            try(ContinuityEnrollment enrollment=configuration.resumeEnrollment(intent(selected),witness);
                    ContinuityDevice device=root.activateRootSuccessor(enrollment)) {
                action.run(device);
            }
        }
    }
    private static void begin(ContinuityAccountAuthority root, Path inputs, Path installation, String profile,
            ConfigurationWitness witness) throws Exception {
        try(ContinuityConfiguration configuration=configuration(inputs,installation,profile.equals("recoverable"),false)) {
            configuration.finishOpen();
            try(ContinuityEnrollment enrollment=configuration.resumeEnrollment(intent(inputs),witness)) {
                enrollment.selectAccountAuthority(root,AuthorityProbe.expected(inputs));
                try(ContinuityDevice device=enrollment.activate();
                        ContinuityPeer peer=device.preparePeerReopen(PeerProbe.configuration(inputs.resolve("peer")),
                            PeerConfiguration.Quality.ONE_TIME_BOTH,PeerConfiguration.Role.INITIATOR,
                            new Ids.Session(read(inputs,"connection-session")))) {
                    peer.finishOpen();
                    root.beginRootReplacement(device,scope(inputs),new RootReplacementPlan(read(inputs,"root-plan")));
                    Ids.Session session=new Ids.Session(read(inputs,"connection-session"));
                    Ids.Message message=new Ids.Message(read(inputs,"connection-message"));
                    failed(2,()->peer.messageStatus(session,message));
                }
            }
        }
        require(root.rootReplacementState()==RootReplacementState.PREPARING,"original root preparation");
        failed(215,root::retiredInventory);
    }
    private static void revoked(ContinuityDevice device,Path inputs) throws Exception {
        Path selected=inputs.resolve("root-target");Ids.Session session=new Ids.Session(read(selected,"connection-session"));
        Ids.Message message=new Ids.Message(read(selected,"connection-message"));PeerConfiguration peer=PeerProbe.configuration(selected.resolve("peer"));
        failed(202,()->{try(ContinuityPeer closed=device.preparePeerReopen(peer,PeerConfiguration.Quality.ONE_TIME_BOTH,PeerConfiguration.Role.INITIATOR,session)) {
            closed.finishOpen();closed.messageStatus(session,message);
        }});
    }
    private static void cleanup(ContinuityAccountAuthority root, Path inputs, Path installation, Path output,
            String mode, CutObserver observer) throws Exception {
        switch(mode) {
            case "root-inventory": publish(output,root.retiredInventory().encoded());break;
            case "root-prepare-report": publish(output,root.prepareRetiredReport(read(inputs,"root-inventory-receipt")).encoded());break;
            case "root-report-unknown": {
                byte[] report=root.loadRetiredReport(read(inputs,"root-inventory-receipt"),read(inputs,"root-report-receipt")).canonicalBytes();
                publish(installation.resolve("root-host-report"),report);
                try(FileChannel parent=FileChannel.open(installation,StandardOpenOption.READ)) { parent.force(true); }
                cut(output,read(inputs,"root-report-proposal"),observer);break;
            }
            case "root-report-reopen": {
                byte[] report=root.loadRetiredReport(read(inputs,"root-inventory-receipt"),read(inputs,"root-report-receipt")).canonicalBytes();
                require(Arrays.equals(report,read(installation,"root-host-report")),"complete root report changed");publish(output,report);break;
            }
            case "root-prepare-ack": {
                RetiredReportProposal proposal=root.prepareRetiredAcknowledgement(read(inputs,"root-inventory-receipt"),
                    read(inputs,"root-report-receipt"),read(installation,"root-host-report"));
                require(Arrays.equals(proposal.encoded(),read(inputs,"root-report-proposal")),"root acknowledgement changed report");
                publish(output,proposal.encoded());break;
            }
            case "root-journal-unknown":root.eraseRetiredJournal(read(inputs,"root-ack"));cut(output,read(inputs,"root-report-proposal"),observer);break;
            case "root-signer-unknown":root.prepareRetiredSignerErasure(read(inputs,"root-ack"));root.eraseRetiredSigner();
                require(root.rootReplacementState()==RootReplacementState.COMMITTED,"signer erasure consumed root controller");
                cut(output,read(inputs,"root-report-proposal"),observer);break;
            case "root-verify":
                require(root.retiredJournalState()==RetiredErasureState.ERASED&&root.retiredSignerState()==RetiredErasureState.ERASED,"root cleanup terminal");
                publish(output,read(installation,"root-host-report"));break;
            default:throw new IllegalArgumentException("root cleanup operation");
        }
    }
    private static void run(Path inputs,Path installation,Path output,String profile,String mode,ConfigurationWitness witness,CutObserver observer) throws Exception {
        if(mode.equals("root-target-create")||mode.equals("root-target-prepare")
                ||mode.equals("root-original-target-create")||mode.equals("root-original-target-prepare")) {
            targetPreparation(inputs,installation,output,profile,mode,witness);return;
        }
        try(Registry registry=new Registry(inputs,installation)) {
            ContinuityAccountAuthority root=registry.value;
            if(mode.equals("root-begin-unknown")) {
                begin(root,inputs,installation,profile,witness);cut(output,state(root.rootReplacementState()),observer);return;
            }
            RootRecovery.resume(root,inputs,installation,mode);
            if(RootRecovery.apply(root,inputs,output,mode,observer))return;
            if(RootControls.apply(root,inputs,installation,output,profile,mode,witness,observer))return;
            switch(mode) {
                case "root-state":publish(output,state(root.rootReplacementState()));break;
                case "root-freeze-bad": {
                    byte[] corrupted=read(inputs,"root-freeze");corrupted[corrupted.length-1]^=1;
                    failed(102,()->root.bindRootFreeze(corrupted));require(root.rootReplacementState()==RootReplacementState.PREPARING,"bad freeze consumed original preparation");
                    publish(output,ByteBuffer.allocate(4).putInt(102).array());break;
                }
                case "root-freeze-unknown":cut(output,root.bindRootFreeze(read(inputs,"root-freeze")).encoded(),observer);break;
                case "root-freeze-replay":publish(output,root.bindRootFreeze(read(inputs,"root-freeze")).encoded());break;
                case "root-retain-unknown":cut(output,checkpoint(root.retainRootRetirement(read(inputs,"root-retirement"))),observer);break;
                case "root-retain-replay":publish(output,checkpoint(root.retainRootRetirement(read(inputs,"root-retirement"))));break;
                case "root-activate-unknown": {
                    Path selected=inputs.resolve("root-target");
                    try(ContinuityConfiguration configuration=configuration(selected,target(installation),profile.equals("recoverable"),false)) {
                        configuration.finishOpen();try(ContinuityEnrollment enrollment=configuration.resumeEnrollment(intent(selected),witness)) {
                            failed(218,()->root.activateRootSuccessor(enrollment));failed(2,root::rootReplacementState);failed(2,enrollment::status);
                        }
                    }
                    publish(output,ByteBuffer.allocate(4).putInt(218).array());break;
                }
                case "root-ack-tampered":
                    withTarget(root,inputs,installation,profile,witness,device->{
                        byte[] record=read(installation,"root-host-report");record[record.length-1]^=1;
                        byte[] inventory=read(inputs,"root-inventory-receipt"),report=read(inputs,"root-report-receipt");
                        failed(208,()->root.prepareRetiredAcknowledgement(inventory,report,record));failed(2,root::rootReplacementState);revoked(device,inputs);
                        publish(output,ByteBuffer.allocate(4).putInt(208).array());
                    });break;
                case "root-erase-wrong-purpose":
                    withTarget(root,inputs,installation,profile,witness,device->{
                        byte[] wrong=read(inputs,"root-report-receipt");failed(102,()->root.eraseRetiredJournal(wrong));
                        failed(2,root::rootReplacementState);revoked(device,inputs);publish(output,ByteBuffer.allocate(4).putInt(102).array());
                    });break;
                case "root-activate":withTarget(root,inputs,installation,profile,witness,device->publish(output,new byte[]{1}));break;
                case "root-peer-connect":case "root-peer-uncertain":case "root-peer-retry":
                    withTarget(root,inputs,installation,profile,witness,device->PeerProbe.client(device,inputs.resolve("root-target"),mode.substring(5),output));break;
                case "root-close-revokes":
                    withTarget(root,inputs,installation,profile,witness,device->{
                        Path selected=inputs.resolve("root-target");Ids.Session session=new Ids.Session(read(selected,"connection-session"));
                        Ids.Message message=new Ids.Message(read(selected,"connection-message"));
                        try(ContinuityPeer peer=device.preparePeerReopen(PeerProbe.configuration(selected.resolve("peer")),PeerConfiguration.Quality.ONE_TIME_BOTH,PeerConfiguration.Role.INITIATOR,session)) {
                            peer.finishOpen();require(peer.messageStatus(session,message)==ContinuityPeer.MessageStatus.ACKNOWLEDGED,"root successor not active before close");
                            registry.revoke();failed(202,()->peer.messageStatus(session,message));publish(output,ByteBuffer.allocate(4).putInt(202).array());
                        }
                    });break;
                default:
                    require(root.rootReplacementState()==RootReplacementState.COMMITTED,"cleanup before committed root");
                    withTarget(root,inputs,installation,profile,witness,device->cleanup(root,inputs,installation,output,mode,observer));
            }
        }
    }
    public static void main(String[] args) throws Exception { run(args,value -> { }); }
    public static void run(String[] args,CutObserver observer) throws Exception {
        require(args.length==5,"root owned arguments");
        Path inputs=Path.of(args[0]),installation=Path.of(args[1]),output=Path.of(args[4]);
        WitnessProbe.withWitness(inputs,args[3],witness->run(inputs,installation,output,args[2],args[3],witness,observer));
        System.out.println(args[2]+":"+args[3]+":passed");
    }
}
