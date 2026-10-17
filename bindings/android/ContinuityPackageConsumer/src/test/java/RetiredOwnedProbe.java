// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Cleanup of an identity originally created by this Android consumer. Only public
 * approvals cross the issuer boundary; wrapping keys and journals remain local. */
public final class RetiredOwnedProbe {
    @FunctionalInterface public interface CutObserver { void beforeHalt(byte[] originalReport) throws Exception; }
    private RetiredOwnedProbe() { }
    private static final int ENCODING = 101, AUTHENTICATION = 102, IMAGE_AUTHENTICATION = 208;
    private static RetiredEnrollmentAuthority authority(Path inputs) throws Exception {
        return new RetiredEnrollmentAuthority(read(inputs, "witness-id"), read(inputs, "witness-public"),
            read(inputs, "retirement-proposal"), read(inputs, "witness-subject"), read(inputs, "retirement-receipt"));
    }
    private static ContinuityRetiredEnrollment open(Path inputs, Path installation) throws Exception {
        ContinuityRetiredEnrollment owner = ContinuityRetiredEnrollment.prepareOpen(installation.toString(), intent(inputs), authority(inputs));
        try { owner.finishOpen(); return owner; }
        catch (Throwable failure) {
            try { owner.close(); } catch (Throwable cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }
    private static byte[] receipt(Path inputs, String name) throws Exception { return read(inputs, "retirement-" + name); }
    private static byte[] expectedId(Path inputs) throws Exception {
        byte[] proposal = receipt(inputs, "report-proposal"); require(proposal.length == 353, "original proposal width");
        return Arrays.copyOfRange(proposal, 321, 353);
    }
    private static void sameProposal(Path inputs, RetiredReportProposal value) throws Exception {
        require(value != null && Arrays.equals(value.encoded(), receipt(inputs, "report-proposal")), "retirement proposal changed");
    }
    private static RetiredReportProposal prepareAck(ContinuityRetiredEnrollment owner, Path inputs, byte[] record) throws Exception {
        RetiredReportProposal result = owner.prepareAcknowledgement(receipt(inputs, "inventory-receipt"), receipt(inputs, "report-receipt"), record);
        sameProposal(inputs, result); sameProposal(inputs, owner.acknowledgementProposal()); return result;
    }
    private static void durableReport(Path installation, byte[] record) throws Exception {
        publish(installation.resolve("retirement-host-report"), record);
        try (FileChannel directory = FileChannel.open(installation, StandardOpenOption.READ)) { directory.force(true); }
    }
    private static void crashAfter(Path output, byte[] report, CutObserver observer) throws Exception {
        publish(output, report);
        observer.beforeHalt(report.clone());
        Runtime.getRuntime().halt(77);
        throw new AssertionError("retirement process cut returned");
    }
    public static void main(String[] args) throws Exception {
        run(args, originalReport -> { });
    }
    public static void run(String[] args, CutObserver observer) throws Exception {
        require(args.length == 5, "owned retirement arguments");
        Path inputs = Path.of(args[0]), installation = Path.of(args[1]), output = Path.of(args[4]);
        String profile = args[2], mode = args[3];
        if (mode.equals("retired-owned-operational-denied")) {
            WitnessProbe.withWitness(inputs, mode, witness -> {
                try (ContinuityConfiguration configuration = configuration(inputs, installation, profile.equals("recoverable"), false)) {
                    configuration.finishOpen(); EnrollmentIntent original = intent(inputs);
                    failed(215, () -> configuration.resumeEnrollment(original, witness));
                    publish(output, ByteBuffer.allocate(4).putInt(215).array());
                }
            });
        } else try (ContinuityRetiredEnrollment owner = open(inputs, installation)) {
            switch (mode) {
                case "retired-owned-inventory": {
                    byte[] inventory = owner.inventory().encoded();
                    try { owner.prepareReport(new byte[3689]); throw new AssertionError("short retirement receipt admitted"); }
                    catch (IllegalArgumentException expected) { require(Arrays.equals(owner.inventory().encoded(), inventory), "preflight changed inventory"); }
                    failed(ENCODING, () -> owner.prepareReport(new byte[3690])); failed(2, owner::inventory);
                    publish(output, inventory); break;
                }
                case "retired-owned-cancelled":
                    owner.cancel(); failed(302, owner::inventory); publish(output, ByteBuffer.allocate(4).putInt(302).array()); break;
                case "retired-owned-prepare-report":
                    RetiredReportProposal proposal = owner.prepareReport(receipt(inputs, "inventory-receipt"));
                    require(Arrays.equals(proposal.encoded(), owner.reportProposal().encoded()), "prepared report changed");
                    publish(output, proposal.encoded()); break;
                case "retired-owned-report-unknown": {
                    RetiredDeviceReport report = owner.loadReport(receipt(inputs, "inventory-receipt"), receipt(inputs, "report-receipt"));
                    require(Arrays.equals(report.report().encoded(), expectedId(inputs)), "original report identity changed");
                    durableReport(installation, report.canonicalBytes()); crashAfter(output, report.report().encoded(), observer); break;
                }
                case "retired-owned-report-reopen": {
                    RetiredDeviceReport report = owner.loadReport(receipt(inputs, "inventory-receipt"), receipt(inputs, "report-receipt"));
                    require(Arrays.equals(report.canonicalBytes(), read(installation, "retirement-host-report")), "complete report changed after process cut");
                    require(Arrays.equals(report.report().encoded(), expectedId(inputs)), "reopened report identity changed");
                    publish(output, ByteBuffer.allocate(36 + report.canonicalBytes().length).put(report.report().encoded())
                        .putInt(report.viewCount()).put(report.canonicalBytes()).array()); break;
                }
                case "retired-owned-ack-tampered": {
                    byte[] record = read(installation, "retirement-host-report"); record[record.length - 1] ^= 1;
                    byte[] inventory = receipt(inputs, "inventory-receipt"), report = receipt(inputs, "report-receipt");
                    failed(IMAGE_AUTHENTICATION, () -> owner.prepareAcknowledgement(inventory, report, record));
                    failed(2, owner::inventory); publish(output, ByteBuffer.allocate(4).putInt(IMAGE_AUTHENTICATION).array()); break;
                }
                case "retired-owned-prepare-ack":
                    require(owner.acknowledgementProposal() == null, "unexpected prior local host acknowledgement");
                    publish(output, prepareAck(owner, inputs, read(installation, "retirement-host-report")).encoded()); break;
                case "retired-owned-erase-wrong-purpose": {
                    byte[] receipt = receipt(inputs, "report-receipt");
                    failed(AUTHENTICATION, () -> owner.eraseJournal(receipt)); failed(2, owner::journalState);
                    publish(output, ByteBuffer.allocate(4).putInt(AUTHENTICATION).array()); break;
                }
                case "retired-owned-journal-unknown":
                    require(owner.journalState() == RetiredErasureState.RETAINED, "journal erased without host acknowledgement");
                    owner.eraseJournal(receipt(inputs, "ack")); crashAfter(output, expectedId(inputs), observer); break;
                case "retired-owned-signer-unknown":
                    require(owner.journalState() == RetiredErasureState.ERASED, "journal terminal missing");
                    owner.prepareSignerErasure(receipt(inputs, "ack"));
                    require(owner.signerState() == RetiredErasureState.RETAINED, "original signer not retained");
                    owner.eraseSigner(); crashAfter(output, expectedId(inputs), observer); break;
                case "retired-owned-verify":
                    prepareAck(owner, inputs, read(installation, "retirement-host-report"));
                    require(owner.journalState() == RetiredErasureState.ERASED && owner.signerState() == RetiredErasureState.ERASED, "retirement terminal missing");
                    owner.eraseSigner(); failed(2, owner::signerState);
                    publish(output, read(installation, "retirement-host-report")); break;
                default: throw new IllegalArgumentException("unknown owned retirement stage");
            }
        }
        System.out.println(profile + ":" + mode + ":passed");
    }
}
