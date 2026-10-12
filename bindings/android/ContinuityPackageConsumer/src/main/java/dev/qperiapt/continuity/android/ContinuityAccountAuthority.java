// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Independent persistent account registry. Keep its path, key and original trust
 * outside device-journal backups. Explicit close revokes managed child admission;
 * cancellation only stops this handle's calls. Reopen does not revive old children.
 */
public final class ContinuityAccountAuthority implements AutoCloseable {
    private final Owner owner;
    private final RetiredOperations retired;
    private ContinuityAccountAuthority(long handle) { owner = new Owner(handle); retired = new RetiredOperations(owner); }
    private static ContinuityAccountAuthority own(long handle) {
        try { return new ContinuityAccountAuthority(handle); }
        catch (Throwable failure) {
            if (handle != 0) try { Native.action(handle, 3); } catch (Throwable cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }
    /** Explicit first-use only, within an existing private directory. Never repairs a missing key. */
    public static void provisionWrappingKey(String directory) { Native.provisionAuthority(new byte[][] {Native.path(directory)}); }
    private static ContinuityAccountAuthority prepare(String directory, AccountAuthorityTrust trust, boolean create) {
        return own(Native.prepareAuthority(Objects.requireNonNull(trust, "registry trust").snapshot(Native.path(directory)), create));
    }
    public static ContinuityAccountAuthority prepareCreate(String directory, AccountAuthorityTrust trust) { return prepare(directory, trust, true); }
    public static ContinuityAccountAuthority prepareOpen(String directory, AccountAuthorityTrust trust) { return prepare(directory, trust, false); }
    public void finishOpen() { owner.action(1); }
    public void cancel() { owner.action(2); }
    @Override public void close() { owner.close(); }
    public AccountAuthorityCheckpoint checkpoint(Ids.ApplicationAccount application) {
        byte[][] input = {Objects.requireNonNull(application, "application account").encoded()};
        return owner.call(false, handle -> AccountAuthorityCheckpoint.fromWire(Native.authorityCommand(handle, 1, input, 0)));
    }
    /** Associate independently approved, signature-verified enrollment inputs.
     * An error may follow commit: retain original inputs and inspect the checkpoint.
     */
    public AccountAuthorityCheckpoint associate(Ids.ApplicationAccount application, AccountPin independentPin,
            byte[] certificate, byte[] roster) {
        Objects.requireNonNull(independentPin, "independent account pin");
        byte[][] pin = independentPin.snapshot();
        byte[][] input = {Objects.requireNonNull(application, "application account").encoded(), pin[0], pin[1], pin[2], pin[3],
            ConfigurationInputs.copy(certificate, 1, 8192, "certificate"), ConfigurationInputs.copy(roster, 1, 8192, "roster")};
        return owner.call(false, handle -> AccountAuthorityCheckpoint.fromWire(
            Native.authorityCommand(handle, 2, input, independentPin.version.bits)));
    }
    void select(Owner enrollment, AccountAuthorityCheckpoint checkpoint) {
        byte[][] input = {checkpoint.wire()};
        owner.call(false, registry -> enrollment.call(false, handle -> {
            Native.selectAuthority(handle, registry, input); return null;
        }));
    }
    /** Converts this registry into the controller; old device aliases lose operational authority.
     * Close the consumed device's table slot. Keep this controller alive while the successor operates. */
    public void beginRootReplacement(ContinuityDevice device, RootReplacementScope scope, RootReplacementPlan plan) {
        RootOperations.begin(owner, device, scope, plan);
    }
    /** Reopen the same original inputs; missing state is never recreated. */
    public void resumeRootReplacement(String path, EnrollmentIntent intent, RootReplacementScope scope, RootReplacementPlan plan) {
        RootOperations.resume(owner, Native.ROOT_RESUME, path, intent, scope,
            new byte[][] {Objects.requireNonNull(plan, "original plan").encoded()});
    }
    public RootReplacementState rootReplacementState() {
        return RootReplacementState.decode(RootOperations.call(owner, Native.ROOT_STATE, new byte[0][]));
    }
    public RootReplacementProposal bindRootFreeze(byte[] receipt) {
        return RootReplacementProposal.fromNative(RootOperations.call(owner, Native.ROOT_BIND_FREEZE,
            new byte[][] {RootOperations.receipt(receipt, 1, 131072)}));
    }
    public AccountAuthorityCheckpoint retainRootRetirement(byte[] receipt) {
        return AccountAuthorityCheckpoint.fromWire(RootOperations.call(owner, Native.ROOT_RETAIN_RETIREMENT,
            new byte[][] {RootOperations.receipt(receipt, 3449, 3449)}));
    }
    /** Signed noncommit preserves suspension; it does not authorize another target. */
    public RootReplacementState retainRootNoncommit(byte[] receipt) {
        return RootReplacementState.decode(RootOperations.call(owner, Native.ROOT_RETAIN_NONCOMMIT,
            new byte[][] {RootOperations.receipt(receipt, 3449, 3449)}));
    }
    public ContinuityDevice activateRootSuccessor(ContinuityEnrollment enrollment) {
        Objects.requireNonNull(enrollment, "successor enrollment");
        return owner.call(false, enrollment::activateRootSuccessor);
    }
    public RootReplacementProposal transitionRoot(RootReplacementTransition approval) {
        return RootReplacementProposal.fromNative(RootOperations.call(owner, Native.ROOT_TRANSITION,
            Objects.requireNonNull(approval, "independent transition approval").snapshot()));
    }
    public AccountAuthorityCheckpoint adoptRoot(RootReplacementAdoption approval) {
        return AccountAuthorityCheckpoint.fromWire(RootOperations.call(owner, Native.ROOT_ADOPT,
            Objects.requireNonNull(approval, "independent adoption approval").snapshot()));
    }
    public void resumeRootTransition(String path, EnrollmentIntent intent, RootReplacementScope scope, RootReplacementTransition approval) {
        RootOperations.resume(owner, Native.ROOT_RESUME_TRANSITION, path, intent, scope,
            Objects.requireNonNull(approval, "original transition approval").snapshot());
    }
    public void resumeRootAdoption(String path, EnrollmentIntent intent, RootReplacementScope scope, RootReplacementAdoption approval) {
        RootOperations.resume(owner, Native.ROOT_RESUME_ADOPTION, path, intent, scope,
            Objects.requireNonNull(approval, "original adoption approval").snapshot());
    }
    public RetiredInventory retiredInventory() { return retired.inventory(); }
    public RetiredReportProposal prepareRetiredReport(byte[] inventory) { return retired.prepareReport(inventory); }
    public RetiredReportProposal retiredReportProposal() { return retired.reportProposal(); }
    public RetiredReportProposal retiredAcknowledgementProposal() { return retired.acknowledgementProposal(); }
    public RetiredDeviceReport loadRetiredReport(byte[] inventory, byte[] report) { return retired.loadReport(inventory, report); }
    public RetiredReportProposal prepareRetiredAcknowledgement(byte[] inventory, byte[] report, byte[] recordedReport) {
        return retired.prepareAcknowledgement(inventory, report, recordedReport);
    }
    public RetiredErasureState retiredJournalState() { return retired.journalState(); }
    public RetiredErasureState retiredSignerState() { return retired.signerState(); }
    public void eraseRetiredJournal(byte[] acknowledgement) { retired.eraseJournal(acknowledgement); }
    public void prepareRetiredSignerErasure(byte[] acknowledgement) { retired.prepareSignerErasure(acknowledgement); }
    /** Preserves this controller and its successor after erasing the historical signer. */
    public void eraseRetiredSigner() { retired.eraseSigner(); }
}
