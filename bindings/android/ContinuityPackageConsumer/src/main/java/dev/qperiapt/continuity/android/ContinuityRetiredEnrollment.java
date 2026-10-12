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
    private final RetiredOperations retired;
    private ContinuityRetiredEnrollment(long handle) { owner = new Owner(handle); retired = new RetiredOperations(owner); }
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
    public RetiredInventory inventory() { return retired.inventory(); }
    public RetiredReportProposal prepareReport(byte[] receipt) { return retired.prepareReport(receipt); }
    public RetiredReportProposal reportProposal() { return retired.reportProposal(); }
    public RetiredReportProposal acknowledgementProposal() { return retired.acknowledgementProposal(); }
    public RetiredDeviceReport loadReport(byte[] inventory, byte[] report) { return retired.loadReport(inventory, report); }
    /** Durably retain/account for the complete original report before requesting independent ACK. */
    public RetiredReportProposal prepareAcknowledgement(byte[] inventory, byte[] report, byte[] recordedReport) {
        return retired.prepareAcknowledgement(inventory, report, recordedReport);
    }
    public RetiredErasureState journalState() { return retired.journalState(); }
    public RetiredErasureState signerState() { return retired.signerState(); }
    public void eraseJournal(byte[] acknowledgement) { retired.eraseJournal(acknowledgement); }
    public void prepareSignerErasure(byte[] acknowledgement) { retired.prepareSignerErasure(acknowledgement); }
    /** Consumes this cleanup resource even on success; close its registry handle afterwards. */
    public void eraseSigner() { retired.eraseSigner(); }
}
