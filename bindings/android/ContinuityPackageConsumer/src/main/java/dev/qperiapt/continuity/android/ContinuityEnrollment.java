// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/** Original native enrollment; failed operations never authorize a replacement identity. */
public final class ContinuityEnrollment implements AutoCloseable {
    private final Owner owner;
    ContinuityEnrollment(long handle) { owner = new Owner(handle); }
    ContinuityDevice activateRootSuccessor(long registry) {
        return owner.transfer(handle -> {
            ContinuityDevice successor = new ContinuityDevice(handle);
            RootOperations.empty(Native.rootCommand(registry, handle, Native.ROOT_ACTIVATE, new byte[0][], new long[0]));
            return successor;
        });
    }
    public void cancel() { owner.action(2); }
    @Override public void close() { owner.close(); }
    public EnrollmentStatus status() { return owner.call(false, handle -> new EnrollmentStatus(Native.enrollmentQuery(handle, 1))); }
    public byte[] request() {
        return owner.call(false, handle -> {
            byte[] wire = Native.enrollmentQuery(handle, 2);
            if (wire.length != 8196) throw new IllegalStateException("native request width");
            int length = ByteBuffer.wrap(wire).getInt();
            if (length < 1 || length > 8192) throw new IllegalStateException("native request length");
            for (int i = 4 + length; i < wire.length; ++i) if (wire[i] != 0) throw new IllegalStateException("native request tail");
            return Arrays.copyOfRange(wire, 4, 4 + length);
        });
    }
    public byte[] accept(byte[] certificate, byte[] roster, AccountPin independentPin) {
        Objects.requireNonNull(independentPin, "independent account pin");
        byte[][] pin = independentPin.snapshot();
        byte[][] inputs = {ConfigurationInputs.copy(certificate, 1, 8192, "certificate"),
            ConfigurationInputs.copy(roster, 1, 8192, "roster"), pin[0], pin[1], pin[2], pin[3]};
        return owner.call(false, handle -> {
            byte[] id = Native.enrollmentAccept(handle, inputs, independentPin.version.bits);
            if (id.length != 32 || !EnrollmentIntent.nonzero(id)) throw new IllegalStateException("native journal identity");
            return id;
        });
    }
    public StoragePreparation prepareStorage() {
        return owner.call(false, handle -> new StoragePreparation(Native.enrollmentQuery(handle, 3)));
    }
    /** Select the original live registry after independent approval of this request.
     * Managed journals require witness protection. Re-select this original registry
     * after resume before journal-backed renewal requests or activation, and keep it
     * open throughout those calls and use of managed children.
     */
    public void selectAccountAuthority(ContinuityAccountAuthority registry, AccountAuthorityCheckpoint checkpoint) {
        Objects.requireNonNull(registry, "account registry").select(owner, Objects.requireNonNull(checkpoint, "checkpoint"));
    }
    /** Passive original-operation history; no current traffic permission is implied. */
    public CredentialRenewalStatus credentialRenewalStatus() {
        return owner.call(false, handle -> new CredentialRenewalStatus(Native.credentialCommand(handle, 1, new byte[0][], 0)));
    }
    /** Stage an independently approved same-key grant under the original policy.
     * Close active devices first. Required-witness protection needs its explicit
     * prepare/terminal workflow before the ordinary consuming activate call.
     */
    public CredentialRenewalStatus stageCredentialRenewal(byte[] grant, AccountPin independentPin, Ids.CredentialRenewal original) {
        Objects.requireNonNull(independentPin, "independent account pin");
        byte[][] pin = independentPin.snapshot();
        byte[][] input = {ConfigurationInputs.copy(grant, 1, 65536, "credential grant"), pin[0], pin[1], pin[2], pin[3],
            Objects.requireNonNull(original, "original renewal").encoded()};
        return owner.call(false, handle -> new CredentialRenewalStatus(Native.credentialCommand(handle, 2, input, independentPin.version.bits)));
    }
    private CredentialRenewalStatus credentialPair(int command, Ids.CredentialRenewal original, Ids.CredentialStatement statement) {
        byte[][] input = {Objects.requireNonNull(original, "original renewal").encoded(), Objects.requireNonNull(statement, "original statement").encoded()};
        return owner.call(false, handle -> new CredentialRenewalStatus(Native.credentialCommand(handle, command, input, 0)));
    }
    public CredentialRenewalStatus reconcileExpiredCredentialRenewal(Ids.CredentialRenewal original, Ids.CredentialStatement statement) {
        return credentialPair(3, original, statement);
    }
    public CredentialRenewalProposal prepareWitnessedCredentialRenewal() {
        return owner.call(false, handle -> new CredentialRenewalProposal(Native.credentialCommand(handle, 4, new byte[0][], 0)));
    }
    public CredentialRenewalCancellation prepareWitnessedCredentialCancellation() {
        return owner.call(false, handle -> new CredentialRenewalCancellation(Native.credentialCommand(handle, 5, new byte[0][], 0)));
    }
    /** A new commit requires current authorization; terminal history releases no device. */
    public CredentialRenewalStatus commitWitnessedCredentialRenewal(Ids.CredentialRenewal original, Ids.CredentialStatement statement) {
        return credentialPair(6, original, statement);
    }
    /** Close can lose to Applied; that outcome remains Committed. */
    public CredentialRenewalStatus closeWitnessedCredentialRenewal(Ids.CredentialRenewal original, Ids.CredentialStatement statement) {
        return credentialPair(7, original, statement);
    }
    /** Sends neither Commit nor Close. Unavailable or failure never proves NoCommit. */
    public CredentialRenewalStatus reconcileWitnessedCredentialRenewal(Ids.CredentialRenewal original, Ids.CredentialStatement statement) {
        return credentialPair(8, original, statement);
    }
    void selectPolicyFrom(Owner configuration) {
        configuration.call(false, source -> owner.call(false, handle -> {
            Native.selectPolicy(source, handle); return null;
        }));
    }
    private PolicyRenewalRequest policyRequest(Ids.PolicyRenewal operation, int command) {
        byte[][] input = {Objects.requireNonNull(operation, "original policy operation").encoded()};
        return owner.call(false, handle -> PolicyRenewalRequest.fromNative(Native.policyCommand(handle, command, input)));
    }
    /** Actual signed historical P0 and original identity; reserves nothing.
     * Retain the entire request and operation after an unknown submission result.
     */
    public PolicyRenewalRequest policyRenewalRequest(Ids.PolicyRenewal operation) {
        return policyRequest(operation, Native.POLICY_REQUEST);
    }
    /** Required-witness counterpart. Missing witness is an error, never a local fallback. */
    public PolicyRenewalRequest witnessedPolicyRenewalRequest(Ids.PolicyRenewal operation) {
        return policyRequest(operation, Native.POLICY_WITNESSED_REQUEST);
    }
    public PolicyRenewalStatus policyRenewalStatus() {
        return owner.call(false, handle -> new PolicyRenewalStatus(Native.policyCommand(handle, Native.POLICY_STATUS, new byte[0][])));
    }
    /** Select an independently trusted current target first. Both root approvals,
     * original request and predecessor pins are reverified by the native coordinator.
     * Admitted failures can consume the owner or follow commit; close and reopen the
     * original enrollment, retaining these exact inputs instead of choosing new IDs.
     */
    public PolicyRenewalStatus stagePolicyRenewal(PolicyRenewalRequest request, AccountPin originalPin,
            AccountPin currentPin, byte[] approvals, ConfigurationInputs.ProtocolPolicy previous) {
        byte[][] input = PolicyCodec.join(new byte[][] {Objects.requireNonNull(request, "original policy request").nativeWire()},
            PolicyCodec.pin(originalPin), PolicyCodec.pin(currentPin),
            new byte[][] {ConfigurationInputs.copy(approvals, 7618, 7618, "policy approvals")}, PolicyCodec.document(previous));
        return owner.call(false, handle -> new PolicyRenewalStatus(Native.policyCommand(handle, Native.POLICY_STAGE, input)));
    }
    public byte[] pendingPolicyRenewalApproval(Ids.PolicyRenewal operation) {
        byte[][] input = {Objects.requireNonNull(operation, "original policy operation").encoded()};
        return owner.call(false, handle -> {
            byte[] wire = Native.policyCommand(handle, Native.POLICY_APPROVAL, input);
            if (wire.length != 8196) throw new IllegalStateException("native policy approval width");
            try {
                byte[] approval = PolicyCodec.publicRecord(ByteBuffer.wrap(wire));
                if (approval.length != 7618) throw new IllegalArgumentException("policy approval length");
                return approval;
            } catch (IllegalArgumentException failure) { throw new IllegalStateException("malformed native policy approval", failure); }
        });
    }
    /** Resume original local policy advancement under the selected current target. */
    public PolicyRenewalStatus reconcilePolicyRenewal() {
        return owner.call(false, handle -> new PolicyRenewalStatus(Native.policyCommand(handle, Native.POLICY_RECONCILE, new byte[0][])));
    }
    /** Local-only exact historical result; selects no runtime and transfers no Device.
     * Required-witness policies refuse this operation. Use their complete original
     * proposal with reconcileWitnessedPolicyRenewal and witnessedPolicyRenewalProgress.
     */
    public PolicyRenewalStatus resolvePolicyRenewal(Ids.PolicyRenewal operation, Ids.PolicyStatement statement,
            ConfigurationInputs.ProtocolPolicy target) {
        byte[][] input = PolicyCodec.join(new byte[][] {Objects.requireNonNull(operation, "policy operation").encoded(),
            Objects.requireNonNull(statement, "policy statement").encoded()}, PolicyCodec.document(target));
        return owner.call(false, handle -> new PolicyRenewalStatus(Native.policyCommand(handle, Native.POLICY_RESOLVE, input)));
    }
    /** Requires selected current target. Retain the complete proposal for independent approval. */
    public IndependentPolicyProposal prepareWitnessedPolicyRenewal(ConfigurationInputs.ProtocolPolicy previous) {
        byte[][] input = PolicyCodec.document(previous);
        return owner.call(false, handle -> IndependentPolicyProposal.fromNative(Native.policyCommand(handle, Native.POLICY_PREPARE, input)));
    }
    /** Null means local absence only; it does not prove witness non-commit. */
    public IndependentPolicyProposal recoverWitnessedPolicyRenewalPreparation() {
        return owner.call(false, handle -> IndependentPolicyProposal.preparation(
            Native.policyCommand(handle, Native.POLICY_PREPARATION, new byte[0][])));
    }
    public IndependentPolicyProgress witnessedPolicyRenewalProgress() {
        return owner.call(false, handle -> new IndependentPolicyProgress(
            Native.policyCommand(handle, Native.POLICY_PROGRESS, new byte[0][])));
    }
    private IndependentPolicyState policyWitness(int command, IndependentPolicyProposal original) {
        byte[][] input = {Objects.requireNonNull(original, "original policy proposal").encoded()};
        return owner.call(false, handle -> IndependentPolicyState.fromNative(Native.policyCommand(handle, command, input)));
    }
    public IndependentPolicyState commitWitnessedPolicyRenewal(IndependentPolicyProposal original) {
        return policyWitness(Native.POLICY_COMMIT, original);
    }
    /** Historical original transaction; sends no new Commit or Close. */
    public IndependentPolicyState reconcileWitnessedPolicyRenewal(IndependentPolicyProposal original) {
        return policyWitness(Native.POLICY_WITNESS_RECONCILE, original);
    }
    /** Explicit closure can lose to Applied; neither result grants current traffic authority. */
    public IndependentPolicyState closeWitnessedPolicyRenewal(IndependentPolicyProposal original) {
        return policyWitness(Native.POLICY_CLOSE, original);
    }
    /** Transfers the original native owner only after fresh target authorization,
     * TLS configuration and any required witness retirement have completed.
     */
    public ContinuityDevice activatePolicyRenewal() {
        return owner.transfer(handle -> {
            ContinuityDevice successor = new ContinuityDevice(handle);
            Native.policyCommand(handle, Native.POLICY_ACTIVATE, new byte[0][]);
            return successor;
        });
    }
    private static byte[] rosterCheckpoint(RosterCheckpoint checkpoint) {
        ByteBuffer bytes = ByteBuffer.allocate(40); PolicyCodec.checkpoint(bytes, Objects.requireNonNull(checkpoint, "roster checkpoint"));
        return bytes.array();
    }
    private static byte[] rosterPolicy(RosterPolicySource selected) {
        return ByteBuffer.allocate(4).putInt(Objects.requireNonNull(selected, "roster policy choice").code).array();
    }
    /** Stage local same-credential roster advancement. Activation performs current admission
     * and completes advancement; REFRESHING is not a committed receipt. Retain the exact pair.
     * Required-witness protection must use its explicit atomic R coordination instead.
     */
    public EnrollmentStatus refreshRoster(RosterCheckpoint previous, byte[] roster, AccountPin independentPin) {
        byte[][] input = PolicyCodec.join(new byte[][] {rosterCheckpoint(previous), ConfigurationInputs.copy(roster, 1, 8192, "roster")},
            PolicyCodec.pin(independentPin));
        return owner.call(false, handle -> new EnrollmentStatus(Native.rosterCommand(handle, Native.ROSTER_REFRESH, input)));
    }
    /** Explicit local current policy. SELECTED requires prior selection and independent
     * policy adoption; it never falls back. Complete through activatePolicyRenewal(). */
    public EnrollmentStatus refreshRoster(RosterCheckpoint previous, byte[] roster, AccountPin independentPin,
            RosterPolicySource policy) {
        byte[][] input = PolicyCodec.join(new byte[][] {rosterCheckpoint(previous), rosterPolicy(policy),
            ConfigurationInputs.copy(roster, 1, 8192, "roster")}, PolicyCodec.pin(independentPin));
        return owner.call(false, handle -> new EnrollmentStatus(Native.rosterCommand(handle, Native.ROSTER_REFRESH_WITH_POLICY, input)));
    }
    /** Original local metadata only. A later head remains superseded-unknown, not no-commit.
     * On admitted failure, close and resume the original enrollment and retry this same pair.
     */
    public RosterRefreshResolution resolveRosterRefresh(RosterCheckpoint previous, RosterCheckpoint target) {
        byte[][] input = {rosterCheckpoint(previous), rosterCheckpoint(target)};
        return owner.call(false, handle -> new RosterRefreshResolution(Native.rosterCommand(handle, Native.ROSTER_RESOLVE, input)));
    }
    /** Export the complete original proposal for independent witness approval. Current
     * policy selection is explicit; SELECTED requires selectContinuedPolicy beforehand.
     */
    public RosterRefreshProposal prepareWitnessedRosterRefresh(Ids.RosterRefresh operation, RosterPolicySource policy,
            byte[] certificate, byte[] roster, AccountPin independentPin) {
        byte[][] input = PolicyCodec.join(new byte[][] {Objects.requireNonNull(operation, "roster operation").encoded(),
            rosterPolicy(policy), ConfigurationInputs.copy(certificate, 1, 8192, "roster credential"),
            ConfigurationInputs.copy(roster, 1, 8192, "roster")}, PolicyCodec.pin(independentPin));
        return owner.call(false, handle -> RosterRefreshProposal.fromNative(Native.rosterCommand(handle, Native.ROSTER_PREPARE, input)));
    }
    /** Null is local preparation absence, never witness non-commit evidence. */
    public RosterRefreshProposal recoverWitnessedRosterRefreshPreparation() {
        return owner.call(false, handle -> RosterRefreshProposal.preparation(Native.rosterCommand(handle, Native.ROSTER_PREPARATION, new byte[0][])));
    }
    public RosterRefreshProgress witnessedRosterRefreshProgress() {
        return owner.call(false, handle -> new RosterRefreshProgress(Native.rosterCommand(handle, Native.ROSTER_PROGRESS, new byte[0][])));
    }
    /** Local abandonment before proposal release, subject to original lease and pending-state checks. */
    public RosterRefreshProgress abandonUnpreparedRosterRefresh(Ids.RosterRefresh operation) {
        byte[][] input = {Objects.requireNonNull(operation, "roster operation").encoded()};
        return owner.call(false, handle -> new RosterRefreshProgress(Native.rosterCommand(handle, Native.ROSTER_ABANDON, input)));
    }
    public RosterRefreshState commitWitnessedRosterRefresh(RosterRefreshProposal original, RosterPolicySource policy) {
        byte[][] input = {Objects.requireNonNull(original, "original roster proposal").encoded(), rosterPolicy(policy)};
        return owner.call(false, handle -> RosterRefreshState.fromNative(Native.rosterCommand(handle, Native.ROSTER_COMMIT, input)));
    }
    /** Exact original history; sends no new Commit or Close. */
    public RosterRefreshState reconcileWitnessedRosterRefresh(RosterRefreshProposal original) {
        return rosterHistory(Native.ROSTER_RECONCILE, original);
    }
    /** Explicit closure may lose to Applied. Neither result releases current traffic authority. */
    public RosterRefreshState closeWitnessedRosterRefresh(RosterRefreshProposal original) {
        return rosterHistory(Native.ROSTER_CLOSE, original);
    }
    private RosterRefreshState rosterHistory(int command, RosterRefreshProposal original) {
        byte[][] input = {Objects.requireNonNull(original, "original roster proposal").encoded()};
        return owner.call(false, handle -> RosterRefreshState.fromNative(Native.rosterCommand(handle, command, input)));
    }
    /** Missing required witness enrollment is an error, never a local-mode fallback. */
    public ContinuityDevice activate() {
        return owner.transfer(handle -> {
            ContinuityDevice successor = new ContinuityDevice(handle);
            Native.action(handle, 4);
            return successor;
        });
    }
}
