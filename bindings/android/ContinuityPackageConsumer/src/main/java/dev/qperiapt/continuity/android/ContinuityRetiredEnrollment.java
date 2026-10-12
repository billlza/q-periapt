// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Cleanup-only original enrollment. No device, traffic or signing capability is returned.
 * Admitted native failures can consume the resource. Close and reopen the exact
 * original inputs after unknown outcomes; never recreate or reset missing state.
 * Calls perform no witness network request or external host transaction.
 */
public final class ContinuityRetiredEnrollment implements AutoCloseable {
    private final Owner owner;
    private ContinuityRetiredEnrollment(long handle) { owner = new Owner(handle); }
    private static ContinuityRetiredEnrollment own(long handle) {
        try { return new ContinuityRetiredEnrollment(handle); }
        catch (Throwable failure) {
            if (handle != 0) try { Native.action(handle, 3); } catch (Throwable cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }
    /** Copies inputs; finishOpen subsequently opens existing original state. */
    public static ContinuityRetiredEnrollment prepareOpen(String path, EnrollmentIntent original,
            RetiredEnrollmentAuthority authority) {
        byte[][] intent = Objects.requireNonNull(original, "original enrollment intent").snapshot();
        byte[][] proof = Objects.requireNonNull(authority, "independent retirement authority").snapshot();
        byte[][] input = PolicyCodec.join(new byte[][] {Native.path(path)}, intent, proof);
        long[] counters = {original.generation.bits, original.validFrom.bits, original.validUntil.bits};
        return own(Native.prepareRetired(input, counters));
    }
    public void finishOpen() { owner.action(1); }
    public void cancel() { owner.action(2); }
    @Override public void close() { owner.close(); }
    private byte[] call(int operation, byte[][] input) {
        return owner.call(false, handle -> Native.retiredCommand(handle, operation, input));
    }
    private byte[] query(int operation) { return call(operation, new byte[0][]); }
    private static byte[] receipt(byte[] value, int length, String name) {
        return ConfigurationInputs.copy(value, length, length, name);
    }
    private static byte[][] receipts(byte[] inventory, byte[] report) {
        return new byte[][] {receipt(inventory, 3690, "inventory receipt"), receipt(report, 3730, "report receipt")};
    }
    public RetiredInventory inventory() { return new RetiredInventory(query(Native.RETIRED_INVENTORY)); }
    public RetiredReportProposal prepareReport(byte[] inventoryReceipt) {
        return RetiredReportProposal.decode(call(Native.RETIRED_PREPARE_REPORT,
            new byte[][] {receipt(inventoryReceipt, 3690, "inventory receipt")}), true);
    }
    /** Null denotes local absence, never witness non-commit. */
    public RetiredReportProposal reportProposal() { return RetiredReportProposal.decode(query(Native.RETIRED_REPORT_PROPOSAL), false); }
    /** Null denotes local absence, never a host acknowledgement. */
    public RetiredReportProposal acknowledgementProposal() { return RetiredReportProposal.decode(query(Native.RETIRED_ACK_PROPOSAL), false); }
    public RetiredDeviceReport loadReport(byte[] inventoryReceipt, byte[] reportReceipt) {
        return new RetiredDeviceReport(call(Native.RETIRED_LOAD_REPORT, receipts(inventoryReceipt, reportReceipt)));
    }
    /** Call only after durably retaining and accounting for the complete original report.
     * Native verification compares recordedReport with the authenticated original bytes.
     */
    public RetiredReportProposal prepareAcknowledgement(byte[] inventoryReceipt, byte[] reportReceipt, byte[] recordedReport) {
        byte[][] input = PolicyCodec.join(receipts(inventoryReceipt, reportReceipt),
            new byte[][] {ConfigurationInputs.copy(recordedReport, 1, 8388608, "recorded complete report")});
        return RetiredReportProposal.decode(call(Native.RETIRED_PREPARE_ACK, input), true);
    }
    public RetiredErasureState journalState() { return RetiredErasureState.decode(query(Native.RETIRED_JOURNAL_STATE)); }
    public RetiredErasureState signerState() { return RetiredErasureState.decode(query(Native.RETIRED_SIGNER_STATE)); }
    private void change(int operation, byte[][] input) {
        if (call(operation, input).length != 0) throw new IllegalStateException("native retirement result width");
    }
    public void eraseJournal(byte[] hostAcknowledgement) {
        change(Native.RETIRED_ERASE_JOURNAL, new byte[][] {receipt(hostAcknowledgement, 3730, "host acknowledgement")});
    }
    public void prepareSignerErasure(byte[] hostAcknowledgement) {
        change(Native.RETIRED_PREPARE_SIGNER, new byte[][] {receipt(hostAcknowledgement, 3730, "host acknowledgement")});
    }
    /** Consumes this cleanup resource even on success; close its registry handle afterwards. */
    public void eraseSigner() { change(Native.RETIRED_ERASE_SIGNER, new byte[0][]); }
}
